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
  verifyEd25519Jwt,
} from '../lib/crypto';
import { getIpHash, getPepper, switchActiveSession } from '../lib/session';
import { writeAuditLog } from '../lib/audit';
import { requireCsrf } from '../middleware/auth';
import { rateLimitMiddleware } from '../middleware/rateLimit';
import { AccountChooserPage } from '../views/AuthPages';
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

function renderOAuthError(title: string, detail: string) {
  return `<!doctype html><html><head><meta charset="utf-8"><title>${title}</title><link rel="stylesheet" href="/styles.css"></head><body><main class="container main-content"><div class="auth-card"><h1>${title}</h1><p class="alert alert-error">${detail}</p><a class="btn btn-ghost" href="/">Back to JoeAuth</a></div></main></body></html>`;
}

// --- OIDC Discovery & JWKS ---

oauthRoutes.get('/.well-known/openid-configuration', (c) => {
  const issuer = getIssuer(c);
  return c.json({
    issuer,
    authorization_endpoint: `${issuer}/oauth/authorize`,
    token_endpoint: `${issuer}/api/oauth/token`,
    userinfo_endpoint: `${issuer}/api/oauth/userinfo`,
    introspection_endpoint: `${issuer}/api/oauth/introspect`,
    revocation_endpoint: `${issuer}/api/oauth/revoke`,
    jwks_uri: `${issuer}/.well-known/jwks.json`,
    response_types_supported: ['code'],
    grant_types_supported: ['authorization_code', 'refresh_token', 'client_credentials'],
    subject_types_supported: ['public'],
    id_token_signing_alg_values_supported: ['EdDSA'],
    token_endpoint_auth_methods_supported: ['client_secret_post', 'client_secret_basic', 'none'],
    scopes_supported: ['openid', 'profile', 'email', 'offline_access'],
    code_challenge_methods_supported: ['S256'],
    claims_supported: ['sub', 'iss', 'aud', 'exp', 'iat', 'name', 'email', 'email_verified', 'role', 'developer_status'],
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
  }
): Promise<Response> {
  const rawCode = `jac_${randomBase64Url(24)}`;
  const codeHash = await sha256Hex(rawCode);
  const now = nowSec();

  await c.env.DB.prepare(
    `INSERT INTO oauth_codes (code_hash, app_id, user_id, redirect_uri, scope, code_challenge, code_challenge_method, nonce, expires_at, used)
     VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, 0)`
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

  const app = await c.env.DB.prepare('SELECT * FROM apps WHERE client_id = ?').bind(clientId).first<AppRow>();
  if (!app || app.status !== 'approved') {
    return c.html(renderOAuthError('Invalid Application', 'Unknown or suspended client_id.'), 400);
  }

  const allowedUris = JSON.parse(app.redirect_uris) as string[];
  if (!allowedUris.includes(redirectUri)) {
    return c.html(renderOAuthError('Invalid Redirect URI', 'redirect_uri does not match registered URIs.'), 400);
  }

  if (responseType !== 'code') {
    return c.redirect(appendQuery(redirectUri, { error: 'unsupported_response_type', state }));
  }
  if (codeChallenge && codeChallengeMethod !== 'S256') {
    return c.redirect(appendQuery(redirectUri, { error: 'invalid_request', error_description: 'Only S256 PKCE is supported', state }));
  }

  const auth = c.get('auth');
  const userAccounts = (auth?.accounts || []).filter((a) => !a.isSuperuser && a.user);
  const selected = c.req.query('selected') === '1';
  const prompt = c.req.query('prompt') || '';

  const authorizeReturnTo = `/oauth/authorize?${new URLSearchParams({
    client_id: clientId,
    redirect_uri: redirectUri,
    response_type: responseType,
    scope: rawScope,
    state,
    code_challenge: codeChallenge,
    code_challenge_method: codeChallengeMethod,
    nonce,
    selected: '1',
  }).toString()}`;

  if (userAccounts.length === 0) {
    return c.redirect(`/login?return_to=${encodeURIComponent(authorizeReturnTo)}`);
  }
  if (prompt === 'login') {
    return c.redirect(`/login?mode=add&return_to=${encodeURIComponent(authorizeReturnTo)}`);
  }

  // Always show Account Chooser first (even when only 1 account is saved), unless user just chose one
  if (!selected || !auth?.user) {
    return c.html(
      <AccountChooserPage
        csrfToken={c.get('csrfToken')}
        accounts={userAccounts}
        oauthParams={{
          appName: app.name,
          client_id: clientId,
          redirect_uri: redirectUri,
          response_type: responseType,
          scope: rawScope,
          state,
          code_challenge: codeChallenge,
          code_challenge_method: codeChallengeMethod,
          nonce,
        }}
      />
    );
  }

  const appScopes = new Set(JSON.parse(app.allowed_scopes) as string[]);
  const requestedScopes = rawScope
    .split(/\s+/)
    .map((s) => s.trim())
    .filter((s) => s && appScopes.has(s));
  if (requestedScopes.length === 0) requestedScopes.push('openid');
  const scopeStr = Array.from(new Set(requestedScopes)).join(' ');

  // Skip consent for first-party apps or previously consented scopes
  const existingConsent = await c.env.DB.prepare(
    'SELECT scopes FROM user_consents WHERE user_id = ? AND app_id = ?'
  )
    .bind(auth.user.id, app.id)
    .first<{ scopes: string }>();

  const alreadyGranted = existingConsent
    ? requestedScopes.every((s) => (JSON.parse(existingConsent.scopes) as string[]).includes(s))
    : false;

  if (app.is_first_party === 1 || alreadyGranted) {
    return issueAuthCodeAndRedirect(c, {
      app,
      user: auth.user,
      redirectUri,
      scope: scopeStr,
      state,
      codeChallenge,
      codeChallengeMethod,
      nonce,
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

  const scopesArr = scopeStr.split(/\s+/).filter(Boolean);
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
    scope: scopeStr,
    state,
    codeChallenge,
    codeChallengeMethod,
    nonce,
  });
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
  opts: { app: AppRow; user: UserRow; scope: string; nonce?: string | null; familyId?: string }
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
      ...(opts.nonce ? { nonce: opts.nonce } : {}),
      ...(scopes.includes('profile')
        ? { name: opts.user.name, role: opts.user.role, developer_status: opts.user.developer_status }
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
    return c.json({ error: 'invalid_client', error_description: 'Unknown or suspended client_id' }, 401);
  }

  const pepper = getPepper(c.env);

  if (grantType === 'authorization_code') {
    const code = params.code || '';
    const redirectUri = params.redirect_uri || '';
    const codeVerifier = params.code_verifier || '';

    if (!code || !redirectUri) {
      return c.json({ error: 'invalid_request', error_description: 'code and redirect_uri are required' }, 400);
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
      }>();

    if (!codeRow || codeRow.app_id !== app.id || codeRow.redirect_uri !== redirectUri) {
      return c.json({ error: 'invalid_grant', error_description: 'Authorization code is invalid or expired' }, 400);
    }

    // Consume single-use code atomically
    const consume = await c.env.DB.prepare('UPDATE oauth_codes SET used = 1 WHERE code_hash = ? AND used = 0')
      .bind(codeHash)
      .run();
    if (!consume.meta.changes) {
      return c.json({ error: 'invalid_grant', error_description: 'Authorization code already used' }, 400);
    }

    // Verify PKCE and/or client_secret
    if (codeRow.code_challenge) {
      const computed = await sha256Base64Url(codeVerifier);
      if (!codeVerifier || computed !== codeRow.code_challenge) {
        return c.json({ error: 'invalid_grant', error_description: 'PKCE code_verifier mismatch' }, 400);
      }
      if (clientSecret && !(await verifyClientSecret(app, clientSecret, pepper))) {
        return c.json({ error: 'invalid_client', error_description: 'Invalid client_secret' }, 401);
      }
    } else {
      if (!clientSecret || !(await verifyClientSecret(app, clientSecret, pepper))) {
        return c.json({ error: 'invalid_client', error_description: 'client_secret or PKCE is required' }, 401);
      }
    }

    const user = await c.env.DB.prepare("SELECT * FROM users WHERE id = ? AND status = 'active'")
      .bind(codeRow.user_id)
      .first<UserRow>();
    if (!user) {
      return c.json({ error: 'invalid_grant', error_description: 'User account is no longer active' }, 400);
    }

    const tokens = await buildUserTokenSet(c, {
      app,
      user,
      scope: codeRow.scope,
      nonce: codeRow.nonce,
    });
    return c.json(tokens);
  }

  if (grantType === 'refresh_token') {
    const rawRefresh = params.refresh_token || '';
    if (!rawRefresh) {
      return c.json({ error: 'invalid_request', error_description: 'refresh_token is required' }, 400);
    }
    if (clientSecret && !(await verifyClientSecret(app, clientSecret, pepper))) {
      return c.json({ error: 'invalid_client', error_description: 'Invalid client_secret' }, 401);
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
      return c.json({ error: 'invalid_grant', error_description: 'Refresh token invalid or expired' }, 400);
    }
    if (row.revoked === 1) {
      // Reuse detected -> revoke entire token family!
      await c.env.DB.prepare('UPDATE refresh_tokens SET revoked = 1 WHERE family_id = ?').bind(row.family_id).run();
      return c.json({ error: 'invalid_grant', error_description: 'Refresh token reuse detected; family revoked' }, 400);
    }

    await c.env.DB.prepare('UPDATE refresh_tokens SET revoked = 1 WHERE id = ?').bind(row.id).run();

    const user = await c.env.DB.prepare("SELECT * FROM users WHERE id = ? AND status = 'active'")
      .bind(row.user_id)
      .first<UserRow>();
    if (!user) {
      return c.json({ error: 'invalid_grant', error_description: 'User is no longer active' }, 400);
    }

    const tokens = await buildUserTokenSet(c, {
      app,
      user,
      scope: row.scope,
      familyId: row.family_id,
    });
    return c.json(tokens);
  }

  if (grantType === 'client_credentials') {
    if (!clientSecret || !(await verifyClientSecret(app, clientSecret, pepper))) {
      return c.json({ error: 'invalid_client', error_description: 'Valid client_secret required' }, 401);
    }
    if (!c.env.JWT_PRIVATE_JWK) {
      return c.json({ error: 'server_error', error_description: 'Signing key not configured' }, 500);
    }

    const scope = params.scope || 'app:service';
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
  const payload = await verifyEd25519Jwt(token, c.env.JWT_PUBLIC_JWK);
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

  const payload = await verifyEd25519Jwt(token, c.env.JWT_PUBLIC_JWK);
  if (!payload) {
    return c.json({ active: false });
  }

  if (payload.token_type === 'user' && typeof payload.sub === 'string') {
    const user = await c.env.DB.prepare(
      "SELECT id, email, name, role, developer_status, email_verified FROM users WHERE id = ? AND status = 'active'"
    )
      .bind(payload.sub)
      .first<{ id: string; email: string; name: string; role: string; developer_status: string; email_verified: number }>();
    if (!user) return c.json({ active: false });

    return c.json({
      active: true,
      ...payload,
      user: {
        id: user.id,
        email: user.email,
        name: user.name,
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
