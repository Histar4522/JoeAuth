/// <reference types="@cloudflare/vitest-pool-workers/types" />
import type { D1Migration } from '@cloudflare/vitest-pool-workers';
import { applyD1Migrations, env, SELF } from 'cloudflare:test';
import { beforeAll, describe, expect, it, vi } from 'vitest';
import { sha256Base64Url, verifyEd25519Jwt } from '../src/lib/crypto';
import { runDailyCleanup } from '../src/index';
import type { Bindings } from '../src/types';

const testEnv = env as unknown as Bindings & { TEST_MIGRATIONS: D1Migration[] };

class CookieJar {
  cookies = new Map<string, string>();
  capture(resp: Response) {
    const setCookies = resp.headers.getSetCookie?.() || [];
    for (const sc of setCookies) {
      const [pair] = sc.split(';');
      const idx = pair.indexOf('=');
      if (idx > 0) {
        const name = pair.slice(0, idx).trim();
        const val = pair.slice(idx + 1).trim();
        if (val === '' || sc.toLowerCase().includes('max-age=0') || sc.toLowerCase().includes('expires=thu, 01 jan 1970')) {
          this.cookies.delete(name);
        } else {
          this.cookies.set(name, val);
        }
      }
    }
  }
  header(): string {
    return Array.from(this.cookies.entries())
      .map(([k, v]) => `${k}=${v}`)
      .join('; ');
  }
  csrf(): string {
    return this.cookies.get('joe_csrf') || '';
  }
}

async function req(
  path: string,
  jar: CookieJar,
  opts: { method?: string; body?: unknown; form?: URLSearchParams; headers?: Record<string, string> } = {}
) {
  if (!jar.csrf()) {
    const init = await SELF.fetch('http://localhost/api/health');
    jar.capture(init);
  }
  const headers: Record<string, string> = {
    Cookie: jar.header(),
    'X-CSRF-Token': jar.csrf(),
    Origin: 'http://localhost',
    ...(opts.headers || {}),
  };
  let body: string | undefined;
  if (opts.form) {
    headers['Content-Type'] = 'application/x-www-form-urlencoded';
    body = opts.form.toString();
  } else if (opts.body !== undefined) {
    headers['Content-Type'] = 'application/json';
    body = JSON.stringify(opts.body);
  }
  const resp = await SELF.fetch(`http://localhost${path}`, {
    method: opts.method || 'GET',
    headers,
    body,
    redirect: 'manual',
  });
  jar.capture(resp);
  return resp;
}

describe('JoeAuth End-to-End Workers Flow', () => {
  beforeAll(async () => {
    await applyD1Migrations(testEnv.DB, testEnv.TEST_MIGRATIONS);
    const origFetch = globalThis.fetch.bind(globalThis);
    vi.spyOn(globalThis, 'fetch').mockImplementation(async (input, init) => {
      const url = typeof input === 'string' ? input : input instanceof Request ? input.url : String(input);
      if (url.startsWith('https://challenges.cloudflare.com/turnstile/v0/siteverify')) {
        return new Response(JSON.stringify({ success: true }), {
          status: 200,
          headers: { 'Content-Type': 'application/json' },
        });
      }
      if (url.startsWith('https://api.resend.com/emails')) {
        return new Response(JSON.stringify({ id: 'mock-email-id' }), {
          status: 200,
          headers: { 'Content-Type': 'application/json' },
        });
      }
      return origFetch(input as RequestInfo, init);
    });
  });

  it('exposes OIDC discovery & Ed25519 JWKS', async () => {
    const disc = await SELF.fetch('http://localhost/.well-known/openid-configuration');
    expect(disc.status).toBe(200);
    const discJson = (await disc.json()) as { id_token_signing_alg_values_supported: string[] };
    expect(discJson.id_token_signing_alg_values_supported).toContain('EdDSA');

    const jwksResp = await SELF.fetch('http://localhost/.well-known/jwks.json');
    expect(jwksResp.status).toBe(200);
    const jwks = (await jwksResp.json()) as { keys: Array<{ crv: string; alg: string }> };
    expect(jwks.keys[0].crv).toBe('Ed25519');
    expect(jwks.keys[0].alg).toBe('EdDSA');
  });

  it('enforces approve-nothing registration, developer gating, admin roles, and full PKCE OAuth flow', async () => {
    const userJar = new CookieJar();
    const superJar = new CookieJar();

    // 1. Registration blocked by default (no rules yet)
    const blockedReg = await req('/api/auth/register', userJar, {
      method: 'POST',
      body: {
        name: 'Joe Dev',
        email: 'joe@joeuniverse.com',
        password: 'StrongPassword123',
        turnstileToken: 'test-token',
      },
    });
    expect(blockedReg.status).toBe(403);

    // 2. Superuser logs in via SHA-256 secret and adds domain allow rule
    const suLogin = await req('/api/admin/superuser/login', superJar, {
      method: 'POST',
      body: { password: 'test-superuser-pass', turnstileToken: 'test-token' },
    });
    expect(suLogin.status).toBe(200);

    // Disable email verification requirement for smooth test or verify via DB
    await req('/api/admin/settings', superJar, {
      method: 'PATCH',
      body: { requireEmailVerification: false },
    });

    const addRule = await req('/api/admin/rules', superJar, {
      method: 'POST',
      body: {
        ruleType: 'allow',
        pattern: '^[^@]+@joeuniverse\\.com$',
        priority: 100,
        description: 'Joe Universe Domain',
      },
    });
    expect(addRule.status).toBe(201);

    const testRule = await req('/api/admin/rules/test', superJar, {
      method: 'POST',
      body: { email: 'joe@joeuniverse.com' },
    });
    expect(((await testRule.json()) as { data: { allowed: boolean } }).data.allowed).toBe(true);

    // 3. Now Joe can register
    const okReg = await req('/api/auth/register', userJar, {
      method: 'POST',
      body: {
        name: 'Joe Dev',
        email: 'joe@joeuniverse.com',
        password: 'StrongPassword123',
        turnstileToken: 'test-token',
      },
    });
    expect(okReg.status).toBe(201);
    const regData = (await okReg.json()) as { data: { user: { id: string } } };
    const joeUserId = regData.data.user.id;

    // 4. Developer gating: cannot create OAuth app before developer approval
    const deniedAppCreate = await req('/api/dev/apps', userJar, {
      method: 'POST',
      body: {
        name: 'JoeDrive',
        homepageUrl: 'https://drive.joeuniverse.com',
        redirectUris: ['https://drive.joeuniverse.com/callback'],
      },
    });
    expect(deniedAppCreate.status).toBe(403);

    // Apply for developer access
    const devApply = await req('/api/dev/apply', userJar, {
      method: 'POST',
      body: {
        reason: 'Building cloud storage for Joe Universe',
        turnstileToken: 'test-token',
      },
    });
    expect(devApply.status).toBe(201);
    const devAppId = ((await devApply.json()) as { data: { id: string } }).data.id;

    // 5. Superuser promotes a second user to Admin; that Admin approves Joe's developer application
    const adminJar = new CookieJar();
    const adminReg = await req('/api/auth/register', adminJar, {
      method: 'POST',
      body: {
        name: 'Helper Admin',
        email: 'helper@joeuniverse.com',
        password: 'StrongPassword123',
        turnstileToken: 'test-token',
      },
    });
    const helperId = ((await adminReg.json()) as { data: { user: { id: string } } }).data.user.id;

    const promote = await req(`/api/admin/users/${helperId}/role`, superJar, {
      method: 'PATCH',
      body: { role: 'admin' },
    });
    expect(promote.status).toBe(200);

    // Helper Admin CAN approve developer application
    const approveDev = await req(`/api/admin/dev-applications/${devAppId}`, adminJar, {
      method: 'PATCH',
      body: { decision: 'approved' },
    });
    expect(approveDev.status).toBe(200);

    // Helper Admin CANNOT promote roles (Superuser only)
    const forbiddenRoleChange = await req(`/api/admin/users/${joeUserId}/role`, adminJar, {
      method: 'PATCH',
      body: { role: 'admin' },
    });
    expect(forbiddenRoleChange.status).toBe(403);

    // 6. Approved developer creates an OAuth App -> immediately approved!
    const createApp = await req('/api/dev/apps', userJar, {
      method: 'POST',
      body: {
        name: 'JoeDrive',
        homepageUrl: 'https://drive.joeuniverse.com',
        redirectUris: ['https://drive.joeuniverse.com/callback'],
        allowedScopes: ['openid', 'profile', 'email', 'offline_access'],
      },
    });
    expect(createApp.status).toBe(201);
    const appData = (await createApp.json()) as {
      data: { client_id: string; client_secret: string; status: string };
    };
    expect(appData.data.status).toBe('approved');

    // 7. Full OAuth 2.0 + PKCE S256 Account Chooser, Consent & Token Flow
    const codeVerifier = 'test_pkce_verifier_string_with_sufficient_entropy_12345';
    const codeChallenge = await sha256Base64Url(codeVerifier);

    const chooserResp = await req(
      `/oauth/authorize?client_id=${encodeURIComponent(appData.data.client_id)}&redirect_uri=${encodeURIComponent(
        'https://drive.joeuniverse.com/callback'
      )}&response_type=code&scope=${encodeURIComponent('openid profile email offline_access')}&state=xyz&code_challenge=${encodeURIComponent(
        codeChallenge
      )}&code_challenge_method=S256&nonce=n1`,
      userJar
    );
    expect(chooserResp.status).toBe(200);
    const chooserHtml = await chooserResp.text();
    expect(chooserHtml).toContain('Continue to JoeDrive');
    expect(chooserHtml).toContain('joe@joeuniverse.com');
    expect(chooserHtml).toContain('Use another account');
    expect(chooserHtml).toContain('Create account');

    const accListBeforeOAuth = await req('/api/auth/accounts', userJar);
    expect(accListBeforeOAuth.status).toBe(200);
    const accListData = (await accListBeforeOAuth.json()) as {
      data: { accounts: Array<{ sessionId: string; isActive: boolean; user: { email: string } | null }> };
    };
    const joeSessionId = accListData.data.accounts[0].sessionId;

    const selectAccountForm = new URLSearchParams({
      _csrf: userJar.csrf(),
      sessionId: joeSessionId,
      client_id: appData.data.client_id,
      redirect_uri: 'https://drive.joeuniverse.com/callback',
      response_type: 'code',
      scope: 'openid profile email offline_access',
      state: 'xyz',
      code_challenge: codeChallenge,
      code_challenge_method: 'S256',
      nonce: 'n1',
    });
    const selectAccountResp = await req('/oauth/select-account', userJar, { method: 'POST', form: selectAccountForm });
    expect(selectAccountResp.status).toBe(302);
    const selectedPath = selectAccountResp.headers.get('location')!;
    expect(selectedPath).toContain('selected=1');

    // Verify Referrer-Policy prevents Origin: null mangling, and CSRF origin rules allow same-origin null while blocking cross-site
    expect(chooserResp.headers.get('referrer-policy')).toBe('same-origin');
    const crossOriginPost = await req('/oauth/select-account', userJar, {
      method: 'POST',
      form: selectAccountForm,
      headers: { Origin: 'https://evil.example' },
    });
    expect(crossOriginPost.status).toBe(403);
    const sameOriginNullPost = await req('/oauth/select-account', userJar, {
      method: 'POST',
      form: selectAccountForm,
      headers: { Origin: 'null', 'Sec-Fetch-Site': 'same-origin' },
    });
    expect(sameOriginNullPost.status).toBe(302);
    const crossSiteNullPost = await req('/oauth/select-account', userJar, {
      method: 'POST',
      form: selectAccountForm,
      headers: { Origin: 'null', 'Sec-Fetch-Site': 'cross-site' },
    });
    expect(crossSiteNullPost.status).toBe(403);

    const authGet = await req(selectedPath, userJar);
    expect(authGet.status).toBe(200);
    expect(await authGet.text()).toContain('JoeDrive wants access');

    const consentForm = new URLSearchParams({
      _csrf: userJar.csrf(),
      client_id: appData.data.client_id,
      redirect_uri: 'https://drive.joeuniverse.com/callback',
      response_type: 'code',
      scope: 'openid profile email offline_access',
      state: 'xyz',
      code_challenge: codeChallenge,
      code_challenge_method: 'S256',
      nonce: 'n1',
      decision: 'allow',
    });
    const authPost = await req('/oauth/authorize', userJar, { method: 'POST', form: consentForm });
    expect(authPost.status).toBe(302);
    const location = authPost.headers.get('location') || '';
    const redirectUrl = new URL(location);
    expect(redirectUrl.searchParams.get('state')).toBe('xyz');
    const code = redirectUrl.searchParams.get('code')!;
    expect(code).toBeTruthy();

    // Exchange code for Ed25519 tokens
    const tokenResp = await SELF.fetch('http://localhost/api/oauth/token', {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body: new URLSearchParams({
        grant_type: 'authorization_code',
        client_id: appData.data.client_id,
        client_secret: appData.data.client_secret,
        code,
        redirect_uri: 'https://drive.joeuniverse.com/callback',
        code_verifier: codeVerifier,
      }).toString(),
    });
    expect(tokenResp.status).toBe(200);
    const tokens = (await tokenResp.json()) as {
      access_token: string;
      id_token: string;
      refresh_token: string;
    };

    // Verify Ed25519 JWT signature
    const verifiedClaims = await verifyEd25519Jwt(tokens.id_token, testEnv.JWT_PUBLIC_JWK!);
    expect(verifiedClaims?.email).toBe('joe@joeuniverse.com');
    expect(verifiedClaims?.nonce).toBe('n1');

    // UserInfo endpoint
    const uiResp = await SELF.fetch('http://localhost/api/oauth/userinfo', {
      headers: { Authorization: `Bearer ${tokens.access_token}` },
    });
    expect(uiResp.status).toBe(200);
    const ui = (await uiResp.json()) as { email: string; name: string };
    expect(ui.email).toBe('joe@joeuniverse.com');

    // Introspect endpoint
    const introResp = await SELF.fetch('http://localhost/api/oauth/introspect', {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body: new URLSearchParams({
        client_id: appData.data.client_id,
        client_secret: appData.data.client_secret,
        token: tokens.access_token,
      }).toString(),
    });
    const intro = (await introResp.json()) as { active: boolean; user: { email: string } };
    expect(intro.active).toBe(true);
    expect(intro.user.email).toBe('joe@joeuniverse.com');

    // Refresh token rotation & reuse detection
    const refresh1 = await SELF.fetch('http://localhost/api/oauth/token', {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body: new URLSearchParams({
        grant_type: 'refresh_token',
        client_id: appData.data.client_id,
        client_secret: appData.data.client_secret,
        refresh_token: tokens.refresh_token,
      }).toString(),
    });
    expect(refresh1.status).toBe(200);
    const rotated = (await refresh1.json()) as { refresh_token: string };

    // Reusing old refresh token fails & revokes family
    const reuse = await SELF.fetch('http://localhost/api/oauth/token', {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body: new URLSearchParams({
        grant_type: 'refresh_token',
        client_id: appData.data.client_id,
        client_secret: appData.data.client_secret,
        refresh_token: tokens.refresh_token,
      }).toString(),
    });
    expect(reuse.status).toBe(400);

    // Rotated token is now also revoked due to reuse detection
    const afterReuse = await SELF.fetch('http://localhost/api/oauth/token', {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body: new URLSearchParams({
        grant_type: 'refresh_token',
        client_id: appData.data.client_id,
        client_secret: appData.data.client_secret,
        refresh_token: rotated.refresh_token,
      }).toString(),
    });
    expect(afterReuse.status).toBe(400);

    // Client credentials M2M app token
    const m2m = await SELF.fetch('http://localhost/api/oauth/token', {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body: new URLSearchParams({
        grant_type: 'client_credentials',
        client_id: appData.data.client_id,
        client_secret: appData.data.client_secret,
      }).toString(),
    });
    expect(m2m.status).toBe(200);
    const m2mJson = (await m2m.json()) as { access_token: string };
    const m2mClaims = await verifyEd25519Jwt(m2mJson.access_token, testEnv.JWT_PUBLIC_JWK!);
    expect(m2mClaims?.token_type).toBe('app');
    expect(m2mClaims?.sub).toBe(appData.data.client_id);

    // 8. User Panel: update profile & change password
    const profUpdate = await req('/api/user/profile', userJar, {
      method: 'PATCH',
      body: { name: 'Joe Updated' },
    });
    expect(profUpdate.status).toBe(200);

    const meResp = await req('/api/user/me', userJar);
    const meJson = (await meResp.json()) as { data: { name: string; developer_status: string } };
    expect(meJson.data.name).toBe('Joe Updated');
    expect(meJson.data.developer_status).toBe('approved');

    // 2FA setup returns SVG QR code data URL
    const totpSetup = await req('/api/user/2fa/setup', userJar, { method: 'POST', body: {} });
    expect(totpSetup.status).toBe(200);
    const totpData = (await totpSetup.json()) as { data: { secret: string; qrDataUrl: string } };
    expect(totpData.data.qrDataUrl.startsWith('data:image/svg+xml;utf8,')).toBe(true);
    expect(decodeURIComponent(totpData.data.qrDataUrl)).toContain('<svg');

    // 8b. Multi-token / multi-account chooser & session switching on same browser
    // /login with 1 signed-in account still renders Account Chooser with login/register options
    const loginChooser = await req('/login', userJar);
    expect(loginChooser.status).toBe(200);
    const loginChooserHtml = await loginChooser.text();
    expect(loginChooserHtml).toContain('Choose an account');
    expect(loginChooserHtml).toContain('joe@joeuniverse.com');
    expect(loginChooserHtml).toContain('Use another account');
    expect(loginChooserHtml).toContain('Create account');

    // /login?mode=add and /register remain accessible while signed in
    expect((await req('/login?mode=add', userJar)).status).toBe(200);
    expect((await req('/register', userJar)).status).toBe(200);

    // Sign up a 2nd account into the same browser jar -> both accounts co-exist
    const aliceReg = await req('/api/auth/register', userJar, {
      method: 'POST',
      body: {
        name: 'Alice Dev',
        email: 'alice@joeuniverse.com',
        password: 'StrongPassword123',
        turnstileToken: 'test-token',
      },
    });
    expect(aliceReg.status).toBe(201);

    const accountsResp = await req('/api/auth/accounts', userJar);
    expect(accountsResp.status).toBe(200);
    const accountsJson = (await accountsResp.json()) as {
      data: { accounts: Array<{ sessionId: string; isActive: boolean; user: { email: string } | null }> };
    };
    expect(accountsJson.data.accounts.length).toBe(2);
    const joeEntry = accountsJson.data.accounts.find((a) => a.user?.email === 'joe@joeuniverse.com')!;
    const aliceEntry = accountsJson.data.accounts.find((a) => a.user?.email === 'alice@joeuniverse.com')!;
    expect(joeEntry).toBeTruthy();
    expect(aliceEntry).toBeTruthy();
    expect(aliceEntry.isActive).toBe(true);

    // Reject switching to an unknown/foreign sessionId
    const badSwitch = await req('/api/auth/switch', userJar, {
      method: 'POST',
      body: { sessionId: 'nonexistent_session_id' },
    });
    expect(badSwitch.status).toBe(403);

    // Switch back to Joe
    const goodSwitch = await req('/api/auth/switch', userJar, {
      method: 'POST',
      body: { sessionId: joeEntry.sessionId },
    });
    expect(goodSwitch.status).toBe(200);

    const switchedMe = await req('/api/user/me', userJar);
    expect(((await switchedMe.json()) as { data: { email: string } }).data.email).toBe('joe@joeuniverse.com');

    // Sign out only Alice -> Joe stays active
    const logoutAlice = await req('/api/auth/logout', userJar, {
      method: 'POST',
      body: { sessionId: aliceEntry.sessionId },
    });
    expect(logoutAlice.status).toBe(200);

    const remainingAccounts = (
      (await (await req('/api/auth/accounts', userJar)).json()) as {
        data: { accounts: Array<{ user: { email: string } | null }> };
      }
    ).data.accounts;
    expect(remainingAccounts.length).toBe(1);
    expect(remainingAccounts[0].user?.email).toBe('joe@joeuniverse.com');

    // Sign out all clears remaining sessions
    const logoutAll = await req('/api/auth/logout', userJar, {
      method: 'POST',
      body: { all: true },
    });
    expect(logoutAll.status).toBe(200);
    const emptyAccounts = (
      (await (await req('/api/auth/accounts', userJar)).json()) as { data: { accounts: unknown[] } }
    ).data.accounts;
    expect(emptyAccounts.length).toBe(0);

    // 9. Root redirects to /login when unauthenticated; auth & doc pages render cleanly
    const rootResp = await SELF.fetch('http://localhost/', { redirect: 'manual' });
    expect(rootResp.status).toBe(302);
    expect(rootResp.headers.get('location')).toBe('/login');

    for (const p of ['/login', '/register', '/docs', '/admin/login']) {
      const pageResp = await SELF.fetch(`http://localhost${p}`);
      expect(pageResp.status).toBe(200);
    }

    // 10. Cron daily cleanup runs cleanly
    await expect(runDailyCleanup(env as unknown as Parameters<typeof runDailyCleanup>[0])).resolves.toBeUndefined();
  });
});
