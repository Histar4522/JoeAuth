import { Hono } from 'hono';
import type { AppEnv, AppRow, UserRow } from '../types';
import {
  getPublicJwks,
  hashSecretValue,
  nowSec,
  randomBase64Url,
  sha256Base64Url,
  sha256Hex,
  signEd25519Jwt,
  timingSafeEqualHex,
  verifyEd25519JwtWithEnv,
} from '../lib/crypto';
import { destroyCurrentSession, getIpHash, getPepper, switchActiveSession } from '../lib/session';
import { getAppLogoUrl, getUserAvatarUrl } from '../lib/images';
import { writeAuditLog } from '../lib/audit';
import { recordOAuthAppError } from '../lib/webhooks';
import { requireCsrf, requireUser } from '../middleware/auth';
import { rateLimitMiddleware } from '../middleware/rateLimit';
import { AccountChooserPage, LogoutConfirmPage } from '../views/AuthPages';
import { ConsentPage } from '../views/ConsentPage';

const oauthRoutes = new Hono<AppEnv>();

function getIssuer(c: { env: AppEnv['Bindings']; req: { url: string } }): string {
  return (c.env.ISSUER_URL || new URL(c.req.url).origin).replace(/\/$/, '');
}

function appendQuery(baseUri: string, params: Record<string, string>): string {
  const u = new URL(baseUri);
  for (const [k, v] of Object.entries(params)) {
    if (v !== '') u.searchParams.set(k, v);
  }
  return u.toString();
}

function escapeHtml(value: string): string {
  return value
    .replaceAll('&', '&amp;')
    .replaceAll('<', '&lt;')
    .replaceAll('>', '&gt;')
    .replaceAll('"', '&quot;')
    .replaceAll("'", '&#39;');
}

function filterAllowedScopes(rawScope: string, allowedScopesJson: string): string[] {
  const appScopes = new Set(JSON.parse(allowedScopesJson) as string[]);
  const requested = rawScope
    .split(/\s+/)
    .map((s) => s.trim())
    .filter((s) => s && appScopes.has(s));
  if (requested.length === 0) requested.push('openid');
  return Array.from(new Set(requested));
}

function renderOAuthError(title: string, detail: string) {
  const safeTitle = escapeHtml(title);
  const safeDetail = escapeHtml(detail);
  return `<!doctype html><html lang="en" data-bs-theme="dark"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1.0"><title>${safeTitle}</title><script src="/theme.js"></script><link rel="stylesheet" href="/vendor/bootstrap.min.css"><link rel="stylesheet" href="/vendor/bootstrap-icons.min.css"><link rel="stylesheet" href="/styles.css"></head><body class="centered-body"><main class="minimal-main"><div class="card shadow-sm auth-card"><div class="card-body p-4"><h1 class="h4 fw-semibold mb-3"><i class="bi bi-exclamation-triangle-fill text-danger me-2"></i>${safeTitle}</h1><div class="alert alert-danger">${safeDetail}</div><a class="btn btn-outline-secondary" href="/"><i class="bi bi-arrow-left me-1"></i>Back to JoeAuth</a></div></div></main></body></html>`;
}

function generateDeviceUserCode(): string {
  const alphabet = 'ABCDEFGHJKLMNPQRSTUVWXYZ23456789';
  const bytes = new Uint8Array(8);
  crypto.getRandomValues(bytes);
  let out = '';
  for (let i = 0; i < 8; i++) {
    if (i === 4) out += '-';
    out += alphabet[bytes[i] % alphabet.length];
  }
  return out;
}

function normalizeDeviceUserCode(input: string): string {
  const clean = input.toUpperCase().replace(/[^A-Z0-9]/g, '');
  if (clean.length === 8) return `${clean.slice(0, 4)}-${clean.slice(4)}`;
  return clean;
}

// --- OIDC Discovery & JWKS ---

oauthRoutes.get('/.well-known/openid-configuration', (c) => {
  const issuer = getIssuer(c);
  return c.json({
    issuer,
    authorization_endpoint: `${issuer}/oauth/authorize`,
    token_endpoint: `${issuer}/api/oauth/token`,
    device_authorization_endpoint: `${issuer}/api/oauth/device_code`,
    userinfo_endpoint: `${issuer}/api/oauth/userinfo`,
    introspection_endpoint: `${issuer}/api/oauth/introspect`,
    revocation_endpoint: `${issuer}/api/oauth/revoke`,
    end_session_endpoint: `${issuer}/oauth/logout`,
    jwks_uri: `${issuer}/.well-known/jwks.json`,
    response_types_supported: ['code'],
    grant_types_supported: [
      'authorization_code',
      'refresh_token',
      'client_credentials',
      'urn:ietf:params:oauth:grant-type:device_code',
    ],
    subject_types_supported: ['public'],
    id_token_signing_alg_values_supported: ['EdDSA'],
    token_endpoint_auth_methods_supported: ['client_secret_post', 'client_secret_basic', 'none'],
    scopes_supported: ['openid', 'profile', 'email', 'offline_access'],
    code_challenge_methods_supported: ['S256'],
    prompt_values_supported: ['none', 'login', 'consent', 'select_account'],
    claims_supported: [
      'sub',
      'iss',
      'aud',
      'exp',
      'iat',
      'auth_time',
      'name',
      'picture',
      'email',
      'email_verified',
      'role',
      'developer_status',
    ],
  });
});

oauthRoutes.get('/.well-known/jwks.json', async (c) => {
  const jwks = await getPublicJwks(c.env);
  c.header('Cache-Control', 'public, max-age=300');
  return c.json(jwks);
});

// --- Authorization & Consent Flow ---

async function issueAuthCodeAndRedirect(
  c: { env: AppEnv['Bindings']; redirect: (url: string) => Response },
  opts: {
    app: AppRow;
    user: UserRow;
    redirectUri: string;
    scope: string;
    state: string;
    codeChallenge: string;
    codeChallengeMethod: string;
    nonce: string;
    authTime: number;
  }
): Promise<Response> {
  const rawCode = `jac_${randomBase64Url(24)}`;
  const codeHash = await sha256Hex(rawCode);
  const now = nowSec();

  await c.env.DB.prepare(
    `INSERT INTO oauth_codes (code_hash, app_id, user_id, redirect_uri, scope, code_challenge, code_challenge_method, nonce, auth_time, expires_at, used)
     VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 0)`
  )
    .bind(
      codeHash,
      opts.app.id,
      opts.user.id,
      opts.redirectUri,
      opts.scope,
      opts.codeChallenge || null,
      opts.codeChallengeMethod || null,
      opts.nonce || null,
      opts.authTime || now,
      now + 60
    )
    .run();

  return c.redirect(
    appendQuery(opts.redirectUri, {
      code: rawCode,
      state: opts.state,
    })
  );
}

oauthRoutes.get('/oauth/authorize', async (c) => {
  const clientId = c.req.query('client_id') || '';
  const redirectUri = c.req.query('redirect_uri') || '';
  const responseType = c.req.query('response_type') || 'code';
  const rawScope = c.req.query('scope') || 'openid profile email';
  const state = c.req.query('state') || '';
  const codeChallenge = c.req.query('code_challenge') || '';
  const codeChallengeMethod = c.req.query('code_challenge_method') || '';
  const nonce = c.req.query('nonce') || '';
  const prompt = (c.req.query('prompt') || '').trim();
  const loginHint = (c.req.query('login_hint') || '').trim();
  const maxAgeRaw = (c.req.query('max_age') || '').trim();
  const maxAge = maxAgeRaw && /^\d+$/.test(maxAgeRaw) ? Number(maxAgeRaw) : null;

  const app = await c.env.DB.prepare('SELECT * FROM apps WHERE client_id = ?').bind(clientId).first<AppRow>();
  if (!app || app.status !== 'approved') {
    return c.html(renderOAuthError('Invalid Application', 'Unknown or suspended client_id.'), 400);
  }

  const allowedUris = JSON.parse(app.redirect_uris) as string[];
  if (!allowedUris.includes(redirectUri)) {
    await recordOAuthAppError(c.env.DB, app.id, '/oauth/authorize', 'invalid_redirect_uri', 'redirect_uri does not match registered URIs');
    return c.html(renderOAuthError('Invalid Redirect URI', 'redirect_uri does not match registered URIs.'), 400);
  }

  if (responseType !== 'code') {
    await recordOAuthAppError(c.env.DB, app.id, '/oauth/authorize', 'unsupported_response_type', `Unsupported response_type: ${responseType}`);
    return c.redirect(appendQuery(redirectUri, { error: 'unsupported_response_type', state }));
  }
  if (app.client_type === 'public' && (!codeChallenge || codeChallengeMethod !== 'S256')) {
    await recordOAuthAppError(c.env.DB, app.id, '/oauth/authorize', 'invalid_request', 'Public clients must use PKCE S256');
    return c.redirect(
      appendQuery(redirectUri, { error: 'invalid_request', error_description: 'Public clients require PKCE S256', state })
    );
  }
  if (codeChallenge && codeChallengeMethod !== 'S256') {
    await recordOAuthAppError(c.env.DB, app.id, '/oauth/authorize', 'invalid_request', 'Only S256 PKCE is supported');
    return c.redirect(appendQuery(redirectUri, { error: 'invalid_request', error_description: 'Only S256 PKCE is supported', state }));
  }

  const promptTokens = new Set(prompt.split(/\s+/).filter(Boolean));
  if (promptTokens.has('none') && promptTokens.size > 1) {
    await recordOAuthAppError(c.env.DB, app.id, '/oauth/authorize', 'invalid_request', 'prompt=none cannot be combined with other prompt values');
    return c.redirect(appendQuery(redirectUri, { error: 'invalid_request', error_description: 'Invalid prompt parameter', state }));
  }

  const auth = c.get('auth');
  const userAccounts = (auth?.accounts || []).filter((a) => !a.isSuperuser && a.user);
  const selected = c.req.query('selected') === '1';
  const reauthed = c.req.query('reauthed') === '1';
  const requestedScopes = filterAllowedScopes(rawScope, app.allowed_scopes);
  const scopeStr = requestedScopes.join(' ');
  const now = nowSec();

  // Handle silent authentication (prompt=none) without ever rendering UI
  if (promptTokens.has('none')) {
    let candidate =
      auth?.user && !auth.isSuperuser
        ? userAccounts.find((a) => a.sessionId === auth.sessionId) || null
        : null;
    if (loginHint && userAccounts.length > 0) {
      candidate =
        userAccounts.find((a) => a.user && (a.user.email.toLowerCase() === loginHint.toLowerCase() || a.user.id === loginHint)) ||
        null;
    } else if (!candidate && userAccounts.length === 1) {
      candidate = userAccounts[0];
    }

    if (!candidate || !candidate.user) {
      return c.redirect(appendQuery(redirectUri, { error: 'login_required', state }));
    }
    if (maxAge !== null && now - candidate.authTime > maxAge) {
      return c.redirect(appendQuery(redirectUri, { error: 'login_required', state }));
    }

    const existingConsent = await c.env.DB.prepare('SELECT scopes FROM user_consents WHERE user_id = ? AND app_id = ?')
      .bind(candidate.user.id, app.id)
      .first<{ scopes: string }>();
    const alreadyGranted = existingConsent
      ? requestedScopes.every((s) => (JSON.parse(existingConsent.scopes) as string[]).includes(s))
      : false;

    if (app.is_first_party !== 1 && !alreadyGranted) {
      return c.redirect(appendQuery(redirectUri, { error: 'consent_required', state }));
    }

    return issueAuthCodeAndRedirect(c, {
      app,
      user: candidate.user,
      redirectUri,
      scope: scopeStr,
      state,
      codeChallenge,
      codeChallengeMethod,
      nonce,
      authTime: candidate.authTime,
    });
  }

  const buildAuthorizeReturnTo = (extra: Record<string, string>) =>
    `/oauth/authorize?${new URLSearchParams({
      client_id: clientId,
      redirect_uri: redirectUri,
      response_type: responseType,
      scope: rawScope,
      state,
      code_challenge: codeChallenge,
      code_challenge_method: codeChallengeMethod,
      nonce,
      prompt,
      login_hint: loginHint,
      max_age: maxAgeRaw,
      ...extra,
    }).toString()}`;

  if (userAccounts.length === 0) {
    const loginParams = new URLSearchParams({ return_to: buildAuthorizeReturnTo({ selected: '1', reauthed: '1' }) });
    if (loginHint) loginParams.set('login_hint', loginHint);
    return c.redirect(`/login?${loginParams.toString()}`);
  }

  if (promptTokens.has('login') && !reauthed) {
    const loginParams = new URLSearchParams({
      mode: 'add',
      return_to: buildAuthorizeReturnTo({ selected: '1', reauthed: '1' }),
    });
    if (loginHint) loginParams.set('login_hint', loginHint);
    return c.redirect(`/login?${loginParams.toString()}`);
  }

  // Show Account Chooser unless already selected in this authorize transition
  if (!selected || !auth?.user || auth.isSuperuser) {
    return c.html(
      <AccountChooserPage
        csrfToken={c.get('csrfToken')}
        accounts={userAccounts}
        oauthParams={{
          appName: app.name,
          appLogoUrl: app.logo_key ? getAppLogoUrl('', app.id, app.logo_version) : null,
          client_id: clientId,
          redirect_uri: redirectUri,
          response_type: responseType,
          scope: rawScope,
          state,
          code_challenge: codeChallenge,
          code_challenge_method: codeChallengeMethod,
          nonce,
          prompt,
          login_hint: loginHint,
          max_age: maxAgeRaw,
        }}
      />
    );
  }

  const activeAccount = userAccounts.find((a) => a.sessionId === auth.sessionId);
  const activeAuthTime = activeAccount?.authTime ?? auth.user.created_at;

  if (maxAge !== null && now - activeAuthTime > maxAge && !reauthed) {
    const loginParams = new URLSearchParams({
      mode: 'add',
      return_to: buildAuthorizeReturnTo({ selected: '1', reauthed: '1' }),
    });
    if (loginHint || auth.user.email) loginParams.set('login_hint', loginHint || auth.user.email);
    return c.redirect(`/login?${loginParams.toString()}`);
  }

  // Skip consent for first-party apps or previously consented scopes unless prompt=consent
  const existingConsent = await c.env.DB.prepare('SELECT scopes FROM user_consents WHERE user_id = ? AND app_id = ?')
    .bind(auth.user.id, app.id)
    .first<{ scopes: string }>();

  const alreadyGranted = existingConsent
    ? requestedScopes.every((s) => (JSON.parse(existingConsent.scopes) as string[]).includes(s))
    : false;

  if (!promptTokens.has('consent') && (app.is_first_party === 1 || alreadyGranted)) {
    return issueAuthCodeAndRedirect(c, {
      app,
      user: auth.user,
      redirectUri,
      scope: scopeStr,
      state,
      codeChallenge,
      codeChallengeMethod,
      nonce,
      authTime: activeAuthTime,
    });
  }

  return c.html(
    <ConsentPage
      appName={c.env.APP_NAME || 'JoeAuth'}
      auth={auth}
      csrfToken={c.get('csrfToken')}
      clientApp={app}
      scopes={Array.from(new Set(requestedScopes))}
      params={{
        client_id: clientId,
        redirect_uri: redirectUri,
        response_type: responseType,
        scope: scopeStr,
        state,
        code_challenge: codeChallenge,
        code_challenge_method: codeChallengeMethod,
        nonce,
      }}
    />
  );
});

oauthRoutes.post('/oauth/select-account', requireCsrf, async (c) => {
  const body = await c.req.parseBody();
  const sessionId = String(body.sessionId || '');
  const ok = await switchActiveSession(c, sessionId);
  if (!ok) {
    return c.redirect('/login');
  }

  const nextParams = new URLSearchParams({
    client_id: String(body.client_id || ''),
    redirect_uri: String(body.redirect_uri || ''),
    response_type: String(body.response_type || 'code'),
    scope: String(body.scope || 'openid profile email'),
    state: String(body.state || ''),
    code_challenge: String(body.code_challenge || ''),
    code_challenge_method: String(body.code_challenge_method || ''),
    nonce: String(body.nonce || ''),
    prompt: String(body.prompt || ''),
    login_hint: String(body.login_hint || ''),
    max_age: String(body.max_age || ''),
    selected: '1',
  });
  return c.redirect(`/oauth/authorize?${nextParams.toString()}`);
});

oauthRoutes.post('/oauth/authorize', requireCsrf, async (c) => {
  const auth = c.get('auth');
  if (!auth || !auth.user) {
    return c.redirect('/login');
  }

  const body = await c.req.parseBody();
  const clientId = String(body.client_id || '');
  const redirectUri = String(body.redirect_uri || '');
  const scopeStr = String(body.scope || 'openid');
  const state = String(body.state || '');
  const codeChallenge = String(body.code_challenge || '');
  const codeChallengeMethod = String(body.code_challenge_method || '');
  const nonce = String(body.nonce || '');
  const decision = String(body.decision || 'deny');

  const app = await c.env.DB.prepare('SELECT * FROM apps WHERE client_id = ? AND status = ?')
    .bind(clientId, 'approved')
    .first<AppRow>();
  if (!app) {
    return c.html(renderOAuthError('Invalid Application', 'Unknown or suspended client_id.'), 400);
  }
  const allowedUris = JSON.parse(app.redirect_uris) as string[];
  if (!allowedUris.includes(redirectUri)) {
    return c.html(renderOAuthError('Invalid Redirect URI', 'redirect_uri mismatch.'), 400);
  }

  if (decision !== 'allow') {
    return c.redirect(appendQuery(redirectUri, { error: 'access_denied', state }));
  }

  const activeAccount = auth.accounts.find((a) => a.sessionId === auth.sessionId);
  const authTime = activeAccount?.authTime ?? auth.user.created_at;

  const scopesArr = filterAllowedScopes(scopeStr, app.allowed_scopes);
  const effectiveScopeStr = scopesArr.join(' ');
  await c.env.DB.prepare(
    `INSERT INTO user_consents (user_id, app_id, scopes, granted_at) VALUES (?, ?, ?, ?)
     ON CONFLICT(user_id, app_id) DO UPDATE SET scopes = excluded.scopes, granted_at = excluded.granted_at`
  )
    .bind(auth.user.id, app.id, JSON.stringify(scopesArr), nowSec())
    .run();

  return issueAuthCodeAndRedirect(c, {
    app,
    user: auth.user,
    redirectUri,
    scope: effectiveScopeStr,
    state,
    codeChallenge,
    codeChallengeMethod,
    nonce,
    authTime,
  });
});

// --- RP-Initiated Logout ---

oauthRoutes.get('/oauth/logout', async (c) => {
  const idTokenHint = (c.req.query('id_token_hint') || '').trim();
  const postLogoutRedirectUri = (c.req.query('post_logout_redirect_uri') || '').trim();
  const clientIdParam = (c.req.query('client_id') || '').trim();
  const state = (c.req.query('state') || '').trim();

  let targetApp: AppRow | null = null;
  let verifiedHint = false;
  let hintSub: string | null = null;

  if (idTokenHint) {
    const payload = await verifyEd25519JwtWithEnv(idTokenHint, c.env, { ignoreExpiration: true });
    if (payload && typeof payload.sub === 'string') {
      verifiedHint = true;
      hintSub = payload.sub;
      const hintClientId = typeof payload.aud === 'string' ? payload.aud : typeof payload.client_id === 'string' ? payload.client_id : '';
      const lookupCid = clientIdParam || hintClientId;
      if (lookupCid) {
        targetApp = await c.env.DB.prepare('SELECT * FROM apps WHERE client_id = ? AND status = ?')
          .bind(lookupCid, 'approved')
          .first<AppRow>();
      }
    }
  } else if (clientIdParam) {
    targetApp = await c.env.DB.prepare('SELECT * FROM apps WHERE client_id = ? AND status = ?')
      .bind(clientIdParam, 'approved')
      .first<AppRow>();
  }

  if (postLogoutRedirectUri) {
    const allowedLogoutUris = targetApp ? (JSON.parse(targetApp.post_logout_redirect_uris || '[]') as string[]) : [];
    if (!targetApp || !allowedLogoutUris.includes(postLogoutRedirectUri)) {
      if (targetApp) {
        await recordOAuthAppError(c.env.DB, targetApp.id, '/oauth/logout', 'invalid_request', 'Unregistered post_logout_redirect_uri');
      }
      return c.html(
        renderOAuthError('Invalid Logout Redirect', 'post_logout_redirect_uri is not registered for this application.'),
        400
      );
    }
  }

  const finalRedirect = postLogoutRedirectUri
    ? appendQuery(postLogoutRedirectUri, state ? { state } : {})
    : '/';

  const auth = c.get('auth');
  if (verifiedHint) {
    if (auth?.user && !auth.isSuperuser && (!hintSub || auth.user.id === hintSub)) {
      const uid = auth.user.id;
      await destroyCurrentSession(c);
      await writeAuditLog(c.env.DB, {
        actorId: uid,
        action: 'oauth.rp_logout',
        targetType: 'app',
        targetId: targetApp?.id || undefined,
        ipHash: await getIpHash(c),
      });
    }
    return c.redirect(finalRedirect);
  }

  if (!auth?.user || auth.isSuperuser) {
    return c.redirect(postLogoutRedirectUri ? finalRedirect : '/login');
  }

  return c.html(
    <LogoutConfirmPage
      appName={c.env.APP_NAME || 'JoeAuth'}
      csrfToken={c.get('csrfToken')}
      userEmail={auth.user.email}
      clientName={targetApp?.name || null}
      postLogoutRedirectUri={postLogoutRedirectUri}
      clientId={targetApp?.client_id || clientIdParam}
      state={state}
    />
  );
});

oauthRoutes.post('/oauth/logout', requireCsrf, async (c) => {
  const body = await c.req.parseBody();
  const decision = String(body.decision || 'confirm');
  const postLogoutRedirectUri = String(body.post_logout_redirect_uri || '').trim();
  const clientIdParam = String(body.client_id || '').trim();
  const state = String(body.state || '').trim();

  let validatedRedirect = '/';
  if (postLogoutRedirectUri && clientIdParam) {
    const app = await c.env.DB.prepare('SELECT id, post_logout_redirect_uris FROM apps WHERE client_id = ? AND status = ?')
      .bind(clientIdParam, 'approved')
      .first<Pick<AppRow, 'id' | 'post_logout_redirect_uris'>>();
    const allowed = app ? (JSON.parse(app.post_logout_redirect_uris || '[]') as string[]) : [];
    if (!app || !allowed.includes(postLogoutRedirectUri)) {
      return c.html(
        renderOAuthError('Invalid Logout Redirect', 'post_logout_redirect_uri is not registered for this application.'),
        400
      );
    }
    validatedRedirect = appendQuery(postLogoutRedirectUri, state ? { state } : {});
  }

  const auth = c.get('auth');
  if (decision === 'confirm' && auth?.user && !auth.isSuperuser) {
    const uid = auth.user.id;
    await destroyCurrentSession(c);
    await writeAuditLog(c.env.DB, {
      actorId: uid,
      action: 'oauth.rp_logout',
      targetType: 'user',
      targetId: uid,
      ipHash: await getIpHash(c),
    });
    return c.redirect(postLogoutRedirectUri ? validatedRedirect : '/login');
  }

  return c.redirect(validatedRedirect);
});

// --- Device Authorization Grant (RFC 8628) ---

oauthRoutes.post('/api/oauth/device_code', rateLimitMiddleware('token'), async (c) => {
  const params = await parseTokenRequest(c.req.raw);
  const basic = extractBasicClientCredentials(c.req.header('authorization'));
  const clientId = params.client_id || basic.clientId || '';
  const scopeRaw = params.scope || 'openid profile email';

  const app = await c.env.DB.prepare('SELECT * FROM apps WHERE client_id = ? AND status = ?')
    .bind(clientId, 'approved')
    .first<AppRow>();
  if (!app) {
    return c.json({ error: 'invalid_client', error_description: 'Client authentication failed' }, 401);
  }

  const scopes = filterAllowedScopes(scopeRaw, app.allowed_scopes);
  const scopeStr = scopes.join(' ');
  const deviceCode = `jdc_${randomBase64Url(24)}`;
  const deviceCodeHash = await sha256Hex(deviceCode);
  const userCode = generateDeviceUserCode();
  const now = nowSec();
  const expiresIn = 600;
  const interval = 5;

  await c.env.DB.prepare(
    `INSERT INTO device_codes (device_code_hash, user_code, app_id, scope, status, expires_at, interval_sec, last_poll_at, created_at)
     VALUES (?, ?, ?, ?, 'pending', ?, ?, 0, ?)`
  )
    .bind(deviceCodeHash, userCode, app.id, scopeStr, now + expiresIn, interval, now)
    .run();

  const issuer = getIssuer(c);
  return c.json({
    device_code: deviceCode,
    user_code: userCode,
    verification_uri: `${issuer}/device`,
    verification_uri_complete: `${issuer}/device?user_code=${encodeURIComponent(userCode)}`,
    expires_in: expiresIn,
    interval,
  });
});

oauthRoutes.post('/api/oauth/device/approve', requireUser, requireCsrf, async (c) => {
  const auth = c.get('auth')!;
  const user = auth.user!;
  if (auth.isSuperuser) {
    return c.json({ ok: false, error: { code: 'FORBIDDEN', message: 'Sign in with a standard user account to approve devices.' } }, 403);
  }

  const body = await c.req.json<{ userCode?: string; decision?: string }>().catch(() => ({} as Record<string, string | undefined>));
  const normalized = normalizeDeviceUserCode(body.userCode || '');
  const decision = body.decision === 'deny' ? 'denied' : 'approved';
  if (!normalized || normalized.length < 4) {
    return c.json({ ok: false, error: { code: 'INVALID_CODE', message: 'Enter the verification code shown on your device.' } }, 400);
  }

  const row = await c.env.DB.prepare(
    `SELECT d.device_code_hash, d.app_id, d.scope, a.name AS app_name
     FROM device_codes d
     JOIN apps a ON a.id = d.app_id
     WHERE d.user_code = ? AND d.status = 'pending' AND d.expires_at > ?`
  )
    .bind(normalized, nowSec())
    .first<{ device_code_hash: string; app_id: string; scope: string; app_name: string }>();

  if (!row) {
    return c.json({ ok: false, error: { code: 'CODE_NOT_FOUND', message: 'Verification code is invalid or expired.' } }, 404);
  }

  const update = await c.env.DB.prepare(
    "UPDATE device_codes SET status = ?, user_id = ? WHERE device_code_hash = ? AND status = 'pending'"
  )
    .bind(decision, user.id, row.device_code_hash)
    .run();
  if (!update.meta.changes) {
    return c.json({ ok: false, error: { code: 'CODE_USED', message: 'This verification code has already been processed.' } }, 409);
  }

  if (decision === 'approved') {
    const scopesArr = row.scope.split(/\s+/).filter(Boolean);
    await c.env.DB.prepare(
      `INSERT INTO user_consents (user_id, app_id, scopes, granted_at) VALUES (?, ?, ?, ?)
       ON CONFLICT(user_id, app_id) DO UPDATE SET scopes = excluded.scopes, granted_at = excluded.granted_at`
    )
      .bind(user.id, row.app_id, JSON.stringify(scopesArr), nowSec())
      .run();
  }

  await writeAuditLog(c.env.DB, {
    actorId: user.id,
    action: `oauth.device_code.${decision}`,
    targetType: 'app',
    targetId: row.app_id,
    ipHash: await getIpHash(c),
  });

  return c.json({ ok: true, data: { status: decision, appName: row.app_name } });
});

// --- Token Endpoint ---

async function parseTokenRequest(req: Request): Promise<Record<string, string>> {
  const ct = (req.headers.get('content-type') || '').toLowerCase();
  if (ct.includes('application/json')) {
    const json = (await req.json().catch(() => ({}))) as Record<string, unknown>;
    const out: Record<string, string> = {};
    for (const [k, v] of Object.entries(json)) {
      if (typeof v === 'string') out[k] = v;
    }
    return out;
  }
  const text = new TextDecoder().decode(await req.arrayBuffer());
  const params = new URLSearchParams(text);
  const out: Record<string, string> = {};
  params.forEach((v, k) => {
    out[k] = v;
  });
  return out;
}

function extractBasicClientCredentials(authHeader: string | undefined): { clientId?: string; clientSecret?: string } {
  if (!authHeader || !authHeader.startsWith('Basic ')) return {};
  try {
    const decoded = atob(authHeader.slice(6).trim());
    const idx = decoded.indexOf(':');
    if (idx === -1) return {};
    return {
      clientId: decodeURIComponent(decoded.slice(0, idx)),
      clientSecret: decodeURIComponent(decoded.slice(idx + 1)),
    };
  } catch {
    return {};
  }
}

async function verifyClientSecret(app: AppRow, rawSecret: string, pepper: string): Promise<boolean> {
  const hash = await hashSecretValue(rawSecret, pepper);
  return timingSafeEqualHex(hash, app.client_secret_hash);
}

async function buildUserTokenSet(
  c: { env: AppEnv['Bindings']; req: { url: string } },
  opts: { app: AppRow; user: UserRow; scope: string; nonce?: string | null; authTime?: number; familyId?: string }
) {
  if (!c.env.JWT_PRIVATE_JWK) {
    throw new Error('JWT_PRIVATE_JWK secret is not configured');
  }

  const issuer = getIssuer(c);
  const scopes = opts.scope.split(/\s+/).filter(Boolean);
  const accessPayload: Record<string, unknown> = {
    iss: issuer,
    sub: opts.user.id,
    aud: opts.app.client_id,
    client_id: opts.app.client_id,
    scope: opts.scope,
    token_type: 'user',
    role: opts.user.role,
  };

  const accessToken = await signEd25519Jwt(accessPayload, c.env.JWT_PRIVATE_JWK, 900); // 15 min

  let idToken: string | undefined;
  if (scopes.includes('openid')) {
    const idPayload: Record<string, unknown> = {
      iss: issuer,
      sub: opts.user.id,
      aud: opts.app.client_id,
      ...(opts.authTime ? { auth_time: opts.authTime } : {}),
      ...(opts.nonce ? { nonce: opts.nonce } : {}),
      ...(scopes.includes('profile')
        ? {
            name: opts.user.name,
            picture: getUserAvatarUrl(issuer, opts.user.id, opts.user.avatar_version),
            role: opts.user.role,
            developer_status: opts.user.developer_status,
          }
        : {}),
      ...(scopes.includes('email')
        ? { email: opts.user.email, email_verified: opts.user.email_verified === 1 }
        : {}),
    };
    idToken = await signEd25519Jwt(idPayload, c.env.JWT_PRIVATE_JWK, 3600); // 1 hour
  }

  let refreshToken: string | undefined;
  if (scopes.includes('offline_access')) {
    refreshToken = `jar_${randomBase64Url(32)}`;
    const refreshHash = await sha256Hex(refreshToken);
    const now = nowSec();
    await c.env.DB.prepare(
      `INSERT INTO refresh_tokens (id, token_hash, app_id, user_id, scope, family_id, revoked, expires_at, created_at)
       VALUES (?, ?, ?, ?, ?, ?, 0, ?, ?)`
    )
      .bind(
        crypto.randomUUID(),
        refreshHash,
        opts.app.id,
        opts.user.id,
        opts.scope,
        opts.familyId || crypto.randomUUID(),
        now + 60 * 60 * 24 * 30,
        now
      )
      .run();
  }

  return {
    token_type: 'Bearer',
    expires_in: 900,
    scope: opts.scope,
    access_token: accessToken,
    ...(idToken ? { id_token: idToken } : {}),
    ...(refreshToken ? { refresh_token: refreshToken } : {}),
  };
}

oauthRoutes.post('/api/oauth/token', rateLimitMiddleware('token'), async (c) => {
  const params = await parseTokenRequest(c.req.raw);
  const basic = extractBasicClientCredentials(c.req.header('authorization'));
  const clientId = params.client_id || basic.clientId || '';
  const clientSecret = params.client_secret || basic.clientSecret || '';
  const grantType = params.grant_type || '';

  const app = await c.env.DB.prepare('SELECT * FROM apps WHERE client_id = ? AND status = ?')
    .bind(clientId, 'approved')
    .first<AppRow>();
  if (!app) {
    return c.json({ error: 'invalid_client', error_description: 'Client authentication failed' }, 401);
  }

  const pepper = getPepper(c.env);

  if (grantType === 'authorization_code') {
    const code = params.code || '';
    const redirectUri = params.redirect_uri || '';
    const codeVerifier = params.code_verifier || '';

    if (!code || !redirectUri) {
      await recordOAuthAppError(c.env.DB, app.id, '/api/oauth/token', 'invalid_request', 'code and redirect_uri are required');
      return c.json({ error: 'invalid_request', error_description: 'code and redirect_uri are required' }, 400);
    }

    if (app.client_type === 'confidential') {
      if (!clientSecret || !(await verifyClientSecret(app, clientSecret, pepper))) {
        await recordOAuthAppError(c.env.DB, app.id, '/api/oauth/token', 'invalid_client', 'Client authentication failed');
        return c.json({ error: 'invalid_client', error_description: 'Client authentication failed' }, 401);
      }
    }

    const codeHash = await sha256Hex(code);
    const now = nowSec();
    const codeRow = await c.env.DB.prepare(
      'SELECT * FROM oauth_codes WHERE code_hash = ? AND used = 0 AND expires_at > ?'
    )
      .bind(codeHash, now)
      .first<{
        code_hash: string;
        app_id: string;
        user_id: string;
        redirect_uri: string;
        scope: string;
        code_challenge: string | null;
        code_challenge_method: string | null;
        nonce: string | null;
        auth_time: number;
      }>();

    if (!codeRow || codeRow.app_id !== app.id || codeRow.redirect_uri !== redirectUri) {
      await recordOAuthAppError(c.env.DB, app.id, '/api/oauth/token', 'invalid_grant', 'Authorization code is invalid, mismatched, or expired');
      return c.json({ error: 'invalid_grant', error_description: 'Authorization code is invalid or expired' }, 400);
    }

    // Consume single-use code atomically
    const consume = await c.env.DB.prepare('UPDATE oauth_codes SET used = 1 WHERE code_hash = ? AND used = 0')
      .bind(codeHash)
      .run();
    if (!consume.meta.changes) {
      await recordOAuthAppError(c.env.DB, app.id, '/api/oauth/token', 'invalid_grant', 'Authorization code already consumed');
      return c.json({ error: 'invalid_grant', error_description: 'Authorization code is invalid or expired' }, 400);
    }

    // Verify PKCE for public clients or whenever code_challenge was supplied
    if (app.client_type === 'public' || codeRow.code_challenge) {
      const computed = await sha256Base64Url(codeVerifier);
      if (!codeRow.code_challenge || !codeVerifier || computed !== codeRow.code_challenge) {
        await recordOAuthAppError(c.env.DB, app.id, '/api/oauth/token', 'invalid_grant', 'PKCE code_verifier mismatch');
        return c.json({ error: 'invalid_grant', error_description: 'Authorization code is invalid or expired' }, 400);
      }
    }

    const user = await c.env.DB.prepare("SELECT * FROM users WHERE id = ? AND status = 'active'")
      .bind(codeRow.user_id)
      .first<UserRow>();
    if (!user) {
      return c.json({ error: 'invalid_grant', error_description: 'Authorization code is invalid or expired' }, 400);
    }

    const tokens = await buildUserTokenSet(c, {
      app,
      user,
      scope: codeRow.scope,
      nonce: codeRow.nonce,
      authTime: codeRow.auth_time,
    });
    return c.json(tokens);
  }

  if (grantType === 'refresh_token') {
    const rawRefresh = params.refresh_token || '';
    if (!rawRefresh) {
      await recordOAuthAppError(c.env.DB, app.id, '/api/oauth/token', 'invalid_request', 'refresh_token is required');
      return c.json({ error: 'invalid_request', error_description: 'refresh_token is required' }, 400);
    }
    if (app.client_type === 'confidential') {
      if (!clientSecret || !(await verifyClientSecret(app, clientSecret, pepper))) {
        await recordOAuthAppError(c.env.DB, app.id, '/api/oauth/token', 'invalid_client', 'Client authentication failed');
        return c.json({ error: 'invalid_client', error_description: 'Client authentication failed' }, 401);
      }
    }

    const tokenHash = await sha256Hex(rawRefresh);
    const row = await c.env.DB.prepare('SELECT * FROM refresh_tokens WHERE token_hash = ? AND app_id = ?')
      .bind(tokenHash, app.id)
      .first<{
        id: string;
        user_id: string;
        scope: string;
        family_id: string;
        revoked: number;
        expires_at: number;
      }>();

    if (!row || row.expires_at <= nowSec()) {
      await recordOAuthAppError(c.env.DB, app.id, '/api/oauth/token', 'invalid_grant', 'Refresh token invalid or expired');
      return c.json({ error: 'invalid_grant', error_description: 'Refresh token is invalid or expired' }, 400);
    }
    if (row.revoked === 1) {
      await c.env.DB.prepare('UPDATE refresh_tokens SET revoked = 1 WHERE family_id = ?').bind(row.family_id).run();
      await recordOAuthAppError(c.env.DB, app.id, '/api/oauth/token', 'invalid_grant', 'Refresh token reuse detected');
      return c.json({ error: 'invalid_grant', error_description: 'Refresh token is invalid or revoked' }, 400);
    }

    // Consume refresh token atomically to prevent concurrent double-rotation race
    const revokeRes = await c.env.DB.prepare('UPDATE refresh_tokens SET revoked = 1 WHERE id = ? AND revoked = 0')
      .bind(row.id)
      .run();
    if (!revokeRes.meta.changes) {
      await c.env.DB.prepare('UPDATE refresh_tokens SET revoked = 1 WHERE family_id = ?').bind(row.family_id).run();
      return c.json({ error: 'invalid_grant', error_description: 'Refresh token is invalid or revoked' }, 400);
    }

    const user = await c.env.DB.prepare("SELECT * FROM users WHERE id = ? AND status = 'active'")
      .bind(row.user_id)
      .first<UserRow>();
    if (!user) {
      return c.json({ error: 'invalid_grant', error_description: 'Refresh token is invalid or expired' }, 400);
    }

    const tokens = await buildUserTokenSet(c, {
      app,
      user,
      scope: row.scope,
      familyId: row.family_id,
    });
    return c.json(tokens);
  }

  if (grantType === 'urn:ietf:params:oauth:grant-type:device_code') {
    const rawDeviceCode = params.device_code || '';
    if (!rawDeviceCode) {
      return c.json({ error: 'invalid_request', error_description: 'device_code is required' }, 400);
    }
    if (app.client_type === 'confidential' && clientSecret && !(await verifyClientSecret(app, clientSecret, pepper))) {
      await recordOAuthAppError(c.env.DB, app.id, '/api/oauth/token', 'invalid_client', 'Client authentication failed');
      return c.json({ error: 'invalid_client', error_description: 'Client authentication failed' }, 401);
    }

    const deviceHash = await sha256Hex(rawDeviceCode);
    const now = nowSec();
    const row = await c.env.DB.prepare('SELECT * FROM device_codes WHERE device_code_hash = ? AND app_id = ?')
      .bind(deviceHash, app.id)
      .first<{
        device_code_hash: string;
        app_id: string;
        user_id: string | null;
        scope: string;
        status: string;
        expires_at: number;
        interval_sec: number;
        last_poll_at: number;
      }>();

    if (!row) {
      return c.json({ error: 'invalid_grant', error_description: 'Invalid device_code' }, 400);
    }
    if (row.expires_at <= now) {
      return c.json({ error: 'expired_token', error_description: 'Device code has expired' }, 400);
    }
    if (row.status === 'denied') {
      return c.json({ error: 'access_denied', error_description: 'User denied the authorization request' }, 400);
    }
    if (row.status === 'consumed') {
      return c.json({ error: 'invalid_grant', error_description: 'Device code already used' }, 400);
    }

    if (row.status === 'pending') {
      if (row.last_poll_at > 0 && now - row.last_poll_at < row.interval_sec) {
        await c.env.DB.prepare(
          'UPDATE device_codes SET interval_sec = interval_sec + 5, last_poll_at = ? WHERE device_code_hash = ?'
        )
          .bind(now, deviceHash)
          .run();
        return c.json({ error: 'slow_down', error_description: 'Polling too frequently' }, 400);
      }
      await c.env.DB.prepare('UPDATE device_codes SET last_poll_at = ? WHERE device_code_hash = ?').bind(now, deviceHash).run();
      return c.json({ error: 'authorization_pending', error_description: 'Authorization pending user verification' }, 400);
    }

    if (row.status !== 'approved' || !row.user_id) {
      return c.json({ error: 'invalid_grant' }, 400);
    }

    const consume = await c.env.DB.prepare(
      "UPDATE device_codes SET status = 'consumed' WHERE device_code_hash = ? AND status = 'approved'"
    )
      .bind(deviceHash)
      .run();
    if (!consume.meta.changes) {
      return c.json({ error: 'invalid_grant', error_description: 'Device code already used' }, 400);
    }

    const user = await c.env.DB.prepare("SELECT * FROM users WHERE id = ? AND status = 'active'")
      .bind(row.user_id)
      .first<UserRow>();
    if (!user) {
      return c.json({ error: 'invalid_grant', error_description: 'User account is unavailable' }, 400);
    }

    const tokens = await buildUserTokenSet(c, {
      app,
      user,
      scope: row.scope,
      authTime: now,
    });
    return c.json(tokens);
  }

  if (grantType === 'client_credentials') {
    if (app.client_type === 'public') {
      await recordOAuthAppError(c.env.DB, app.id, '/api/oauth/token', 'unauthorized_client', 'Public clients cannot use client_credentials grant');
      return c.json({ error: 'unauthorized_client', error_description: 'Public clients cannot use client_credentials grant' }, 400);
    }
    if (!clientSecret || !(await verifyClientSecret(app, clientSecret, pepper))) {
      await recordOAuthAppError(c.env.DB, app.id, '/api/oauth/token', 'invalid_client', 'Client authentication failed');
      return c.json({ error: 'invalid_client', error_description: 'Client authentication failed' }, 401);
    }
    if (!c.env.JWT_PRIVATE_JWK) {
      return c.json({ error: 'server_error', error_description: 'Service temporarily unavailable' }, 500);
    }

    const requestedScope = (params.scope || '').trim();
    const scope =
      requestedScope && /^[a-zA-Z0-9_:.\-\s]{1,128}$/.test(requestedScope)
        ? requestedScope
        : 'app:service';
    const accessToken = await signEd25519Jwt(
      {
        iss: getIssuer(c),
        sub: app.client_id,
        aud: getIssuer(c),
        client_id: app.client_id,
        app_id: app.id,
        owner_user_id: app.owner_user_id,
        scope,
        token_type: 'app',
      },
      c.env.JWT_PRIVATE_JWK,
      3600
    );

    await writeAuditLog(c.env.DB, {
      actorId: app.owner_user_id,
      action: 'oauth.client_credentials',
      targetType: 'app',
      targetId: app.id,
      ipHash: await getIpHash(c),
    });

    return c.json({
      token_type: 'Bearer',
      expires_in: 3600,
      scope,
      access_token: accessToken,
    });
  }

  return c.json({ error: 'unsupported_grant_type' }, 400);
});

// --- OIDC UserInfo ---

oauthRoutes.get('/api/oauth/userinfo', async (c) => {
  const authHeader = c.req.header('authorization') || '';
  if (!authHeader.startsWith('Bearer ') || !c.env.JWT_PUBLIC_JWK) {
    return c.json({ error: 'invalid_token' }, 401);
  }
  const token = authHeader.slice(7).trim();
  const payload = await verifyEd25519JwtWithEnv(token, c.env);
  if (!payload || payload.token_type !== 'user' || typeof payload.sub !== 'string') {
    return c.json({ error: 'invalid_token' }, 401);
  }

  const user = await c.env.DB.prepare("SELECT * FROM users WHERE id = ? AND status = 'active'")
    .bind(payload.sub)
    .first<UserRow>();
  if (!user) {
    return c.json({ error: 'invalid_token' }, 401);
  }

  const scopes = String(payload.scope || 'openid').split(/\s+/);
  const claims: Record<string, unknown> = { sub: user.id };
  if (scopes.includes('profile')) {
    claims.name = user.name;
    claims.picture = getUserAvatarUrl(getIssuer(c), user.id, user.avatar_version);
    claims.role = user.role;
    claims.developer_status = user.developer_status;
  }
  if (scopes.includes('email')) {
    claims.email = user.email;
    claims.email_verified = user.email_verified === 1;
  }
  return c.json(claims);
});

// --- RFC 7662 Token Introspection ---

oauthRoutes.post('/api/oauth/introspect', rateLimitMiddleware('token'), async (c) => {
  const params = await parseTokenRequest(c.req.raw);
  const basic = extractBasicClientCredentials(c.req.header('authorization'));
  const clientId = params.client_id || basic.clientId || '';
  const clientSecret = params.client_secret || basic.clientSecret || '';

  const app = await c.env.DB.prepare('SELECT * FROM apps WHERE client_id = ? AND status = ?')
    .bind(clientId, 'approved')
    .first<AppRow>();
  if (!app || !clientSecret || !(await verifyClientSecret(app, clientSecret, getPepper(c.env)))) {
    return c.json({ error: 'invalid_client' }, 401);
  }

  const token = params.token || '';
  if (!token || !c.env.JWT_PUBLIC_JWK) {
    return c.json({ active: false });
  }

  const payload = await verifyEd25519JwtWithEnv(token, c.env);
  if (!payload) {
    return c.json({ active: false });
  }

  if (payload.token_type === 'user' && typeof payload.sub === 'string') {
    const user = await c.env.DB.prepare(
      "SELECT id, email, name, role, developer_status, email_verified, avatar_version FROM users WHERE id = ? AND status = 'active'"
    )
      .bind(payload.sub)
      .first<{
        id: string;
        email: string;
        name: string;
        role: string;
        developer_status: string;
        email_verified: number;
        avatar_version: number;
      }>();
    if (!user) return c.json({ active: false });

    return c.json({
      active: true,
      ...payload,
      user: {
        id: user.id,
        email: user.email,
        name: user.name,
        picture: getUserAvatarUrl(getIssuer(c), user.id, user.avatar_version),
        role: user.role,
        developer_status: user.developer_status,
        email_verified: user.email_verified === 1,
      },
    });
  }

  return c.json({ active: true, ...payload });
});

// --- Token Revocation ---

oauthRoutes.post('/api/oauth/revoke', rateLimitMiddleware('token'), async (c) => {
  const params = await parseTokenRequest(c.req.raw);
  const token = params.token || '';
  if (token) {
    const tokenHash = await sha256Hex(token);
    await c.env.DB.prepare('UPDATE refresh_tokens SET revoked = 1 WHERE token_hash = ?').bind(tokenHash).run();
  }
  return c.json({ ok: true });
});

export default oauthRoutes;
