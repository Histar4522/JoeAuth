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
  opts: { method?: string; body?: unknown; form?: URLSearchParams; rawBody?: BodyInit; headers?: Record<string, string> } = {}
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
  let body: BodyInit | undefined;
  if (opts.rawBody !== undefined) {
    body = opts.rawBody;
  } else if (opts.form) {
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

function makeTestPng(width: number, height: number, size = 64): Uint8Array {
  const buf = new Uint8Array(Math.max(size, 33));
  buf.set([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a], 0);
  const view = new DataView(buf.buffer);
  view.setUint32(8, 13, false);
  buf.set([0x49, 0x48, 0x44, 0x52], 12);
  view.setUint32(16, width, false);
  view.setUint32(20, height, false);
  return buf;
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

    // 1. Registration blocked by default (no rules yet) — ensure no internal policy details leak
    const blockedReg = await req('/api/auth/register', userJar, {
      method: 'POST',
      body: {
        name: 'Joe Doe',
        email: 'joe@example.com',
        password: 'StrongPassword123',
        turnstileToken: 'test-token',
      },
    });
    expect(blockedReg.status).toBe(403);
    const blockedRegText = await blockedReg.text();
    expect(blockedRegText).not.toContain('default deny');
    expect(blockedRegText).not.toContain('allow rule');

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
        pattern: '^[^@]+@example\\.com$',
        priority: 100,
        description: 'Example Domain',
      },
    });
    expect(addRule.status).toBe(201);

    const testRule = await req('/api/admin/rules/test', superJar, {
      method: 'POST',
      body: { email: 'joe@example.com' },
    });
    expect(((await testRule.json()) as { data: { allowed: boolean } }).data.allowed).toBe(true);

    // 3. Now Joe can register
    const okReg = await req('/api/auth/register', userJar, {
      method: 'POST',
      body: {
        name: 'Joe Doe',
        email: 'joe@example.com',
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
        name: 'Example Drive',
        homepageUrl: 'https://drive.example.com',
        redirectUris: ['https://drive.example.com/callback'],
      },
    });
    expect(deniedAppCreate.status).toBe(403);

    // Apply for developer access
    const devApply = await req('/api/dev/apply', userJar, {
      method: 'POST',
      body: {
        reason: 'Building cloud storage for Example App',
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
        email: 'helper@example.com',
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
        name: 'Example Drive',
        description: 'Encrypted cloud storage for Example App',
        privilegeDescription: 'Displays your profile picture and email in Example Drive.',
        homepageUrl: 'https://drive.example.com',
        redirectUris: ['https://drive.example.com/callback'],
        allowedScopes: ['openid', 'profile', 'email', 'offline_access'],
      },
    });
    expect(createApp.status).toBe(201);
    const appData = (await createApp.json()) as {
      data: { id: string; client_id: string; client_secret: string; status: string };
    };
    expect(appData.data.status).toBe('approved');

    // 6b. Profile picture & App logo validation, R2 upload, media serving & deletion
    const meBeforeAvatar = (await (await req('/api/user/me', userJar)).json()) as {
      data: { id: string; avatar_color: string; avatar_url: string; has_custom_avatar: boolean };
    };
    expect(meBeforeAvatar.data.avatar_color).toMatch(/^#[0-9a-f]{6}$/);
    expect(meBeforeAvatar.data.has_custom_avatar).toBe(false);

    const defaultAvatarResp = await SELF.fetch(`http://localhost${meBeforeAvatar.data.avatar_url}`);
    expect(defaultAvatarResp.status).toBe(200);
    expect(defaultAvatarResp.headers.get('content-type')).toContain('image/svg+xml');
    expect(defaultAvatarResp.headers.get('cross-origin-resource-policy')).toBe('cross-origin');
    expect(await defaultAvatarResp.text()).toContain(meBeforeAvatar.data.avatar_color);

    const badDimAvatar = await req('/api/user/avatar', userJar, {
      method: 'POST',
      rawBody: makeTestPng(128, 128, 64),
      headers: { 'Content-Type': 'image/png' },
    });
    expect(badDimAvatar.status).toBe(400);

    const oversizedAvatar = await req('/api/user/avatar', userJar, {
      method: 'POST',
      rawBody: makeTestPng(256, 256, 131073),
      headers: { 'Content-Type': 'image/png' },
    });
    expect(oversizedAvatar.status).toBe(400);

    const validAvatarPng = makeTestPng(256, 256, 128);
    const uploadAvatar = await req('/api/user/avatar', userJar, {
      method: 'POST',
      rawBody: validAvatarPng,
      headers: { 'Content-Type': 'image/png' },
    });
    expect(uploadAvatar.status).toBe(200);
    const avatarJson = (await uploadAvatar.json()) as {
      data: { avatar_url: string; has_custom_avatar: boolean };
    };
    expect(avatarJson.data.has_custom_avatar).toBe(true);

    const customAvatarResp = await SELF.fetch(`http://localhost${avatarJson.data.avatar_url}`);
    expect(customAvatarResp.status).toBe(200);
    expect(customAvatarResp.headers.get('content-type')).toBe('image/png');
    expect((await customAvatarResp.arrayBuffer()).byteLength).toBe(128);

    const defaultAppLogoResp = await SELF.fetch(`http://localhost/media/app-logos/${appData.data.id}`);
    expect(defaultAppLogoResp.status).toBe(404);

    const uploadLogo = await req(`/api/dev/apps/${appData.data.id}/logo`, userJar, {
      method: 'POST',
      rawBody: makeTestPng(256, 256, 96),
      headers: { 'Content-Type': 'image/png' },
    });
    expect(uploadLogo.status).toBe(200);
    const logoJson = (await uploadLogo.json()) as { data: { logo_url: string; has_custom_logo: boolean } };
    expect(logoJson.data.has_custom_logo).toBe(true);

    const customLogoResp = await SELF.fetch(`http://localhost${logoJson.data.logo_url}`);
    expect(customLogoResp.status).toBe(200);
    expect(customLogoResp.headers.get('content-type')).toBe('image/png');

    // 7. Full OAuth 2.0 + PKCE S256 Account Chooser, Consent & Token Flow
    const codeVerifier = 'test_pkce_verifier_string_with_sufficient_entropy_12345';
    const codeChallenge = await sha256Base64Url(codeVerifier);

    const chooserResp = await req(
      `/oauth/authorize?client_id=${encodeURIComponent(appData.data.client_id)}&redirect_uri=${encodeURIComponent(
        'https://drive.example.com/callback'
      )}&response_type=code&scope=${encodeURIComponent('openid profile email offline_access')}&state=xyz&code_challenge=${encodeURIComponent(
        codeChallenge
      )}&code_challenge_method=S256&nonce=n1`,
      userJar
    );
    expect(chooserResp.status).toBe(200);
    const chooserHtml = await chooserResp.text();
    expect(chooserHtml).toContain('Continue to Example Drive');
    expect(chooserHtml).toContain('joe@example.com');
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
      redirect_uri: 'https://drive.example.com/callback',
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

    // Verify Referrer-Policy prevents Origin: null mangling, and CSRF origin rules allow same-origin null while blocking cross-site / missing header
    expect(chooserResp.headers.get('referrer-policy')).toBe('same-origin');
    const crossOriginPost = await req('/oauth/select-account', userJar, {
      method: 'POST',
      form: selectAccountForm,
      headers: { Origin: 'https://evil.example' },
    });
    expect(crossOriginPost.status).toBe(403);
    const missingSecFetchNullPost = await req('/oauth/select-account', userJar, {
      method: 'POST',
      form: selectAccountForm,
      headers: { Origin: 'null' },
    });
    expect(missingSecFetchNullPost.status).toBe(403);
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
    const consentHtml = await authGet.text();
    expect(consentHtml).toContain('Example Drive wants access');
    expect(consentHtml).toContain('Encrypted cloud storage for Example App');
    expect(consentHtml).toContain('Displays your profile picture and email in Example Drive.');
    expect(consentHtml).toContain(`/media/app-logos/${appData.data.id}`);
    expect(consentHtml).toContain(`/media/avatars/${meBeforeAvatar.data.id}`);

    const consentForm = new URLSearchParams({
      _csrf: userJar.csrf(),
      client_id: appData.data.client_id,
      redirect_uri: 'https://drive.example.com/callback',
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
        redirect_uri: 'https://drive.example.com/callback',
        code_verifier: codeVerifier,
      }).toString(),
    });
    expect(tokenResp.status).toBe(200);
    const tokens = (await tokenResp.json()) as {
      access_token: string;
      id_token: string;
      refresh_token: string;
    };

    // Verify Ed25519 JWT signature & OIDC picture claim
    const verifiedClaims = await verifyEd25519Jwt(tokens.id_token, testEnv.JWT_PUBLIC_JWK!);
    expect(verifiedClaims?.email).toBe('joe@example.com');
    expect(verifiedClaims?.nonce).toBe('n1');
    expect(String(verifiedClaims?.picture || '')).toContain(`/media/avatars/${meBeforeAvatar.data.id}`);

    // UserInfo endpoint
    const uiResp = await SELF.fetch('http://localhost/api/oauth/userinfo', {
      headers: { Authorization: `Bearer ${tokens.access_token}` },
    });
    expect(uiResp.status).toBe(200);
    const ui = (await uiResp.json()) as { email: string; name: string; picture?: string };
    expect(ui.email).toBe('joe@example.com');
    expect(ui.picture).toContain(`/media/avatars/${meBeforeAvatar.data.id}`);

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
    const intro = (await introResp.json()) as { active: boolean; user: { email: string; picture?: string } };
    expect(intro.active).toBe(true);
    expect(intro.user.email).toBe('joe@example.com');
    expect(intro.user.picture).toContain(`/media/avatars/${meBeforeAvatar.data.id}`);

    // Deleting avatar & app logo restores default fallbacks
    const delAvatar = await req('/api/user/avatar', userJar, { method: 'DELETE', body: {} });
    expect(delAvatar.status).toBe(200);
    const revertedAvatarResp = await SELF.fetch(`http://localhost/media/avatars/${meBeforeAvatar.data.id}`);
    expect(revertedAvatarResp.status).toBe(200);
    expect(revertedAvatarResp.headers.get('content-type')).toContain('image/svg+xml');

    const delLogo = await req(`/api/dev/apps/${appData.data.id}/logo`, userJar, { method: 'DELETE', body: {} });
    expect(delLogo.status).toBe(200);
    expect((await SELF.fetch(`http://localhost/media/app-logos/${appData.data.id}`)).status).toBe(404);

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

    // 8a-bis. Security regressions: scope escalation on POST /oauth/authorize & open redirect sanitization
    const restrictedAppResp = await req('/api/dev/apps', userJar, {
      method: 'POST',
      body: {
        name: 'Restricted App',
        homepageUrl: 'https://app.example.com',
        redirectUris: ['https://app.example.com/callback'],
        allowedScopes: ['openid'],
      },
    });
    expect(restrictedAppResp.status).toBe(201);
    const restrictedApp = (await restrictedAppResp.json()) as {
      data: { id: string; client_id: string; client_secret: string };
    };

    const tamperedConsentResp = await req('/oauth/authorize', userJar, {
      method: 'POST',
      form: new URLSearchParams({
        _csrf: userJar.csrf(),
        decision: 'allow',
        client_id: restrictedApp.data.client_id,
        redirect_uri: 'https://app.example.com/callback',
        scope: 'openid profile email offline_access',
        state: 'esc_state',
        code_challenge: codeChallenge,
        code_challenge_method: 'S256',
      }),
    });
    expect(tamperedConsentResp.status).toBe(302);
    const tamperedRedirect = new URL(tamperedConsentResp.headers.get('location')!);
    const restrictedCode = tamperedRedirect.searchParams.get('code')!;
    expect(restrictedCode).toBeTruthy();

    const restrictedTokenResp = await SELF.fetch('http://localhost/api/oauth/token', {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body: new URLSearchParams({
        grant_type: 'authorization_code',
        code: restrictedCode,
        client_id: restrictedApp.data.client_id,
        client_secret: restrictedApp.data.client_secret,
        redirect_uri: 'https://app.example.com/callback',
        code_verifier: codeVerifier,
      }).toString(),
    });
    expect(restrictedTokenResp.status).toBe(200);
    const restrictedTokens = (await restrictedTokenResp.json()) as {
      scope: string;
      refresh_token?: string;
    };
    expect(restrictedTokens.scope).toBe('openid');
    expect(restrictedTokens.refresh_token).toBeUndefined();

    // Ensure unsafe return_to URLs are neutralized in SSR
    const openRedirectLogin = await req('/login?mode=add&return_to=https://evil.example/phish', userJar);
    expect(openRedirectLogin.status).toBe(200);
    const openRedirectHtml = await openRedirectLogin.text();
    expect(openRedirectHtml).toContain('data-return-to="/account"');
    expect(openRedirectHtml).not.toContain('https://evil.example/phish');

    const protoRelRedirect = await req('/register?return_to=//evil.example/phish', userJar);
    expect(protoRelRedirect.status).toBe(200);
    const protoRelHtml = await protoRelRedirect.text();
    expect(protoRelHtml).toContain('data-return-to="/account"');
    expect(protoRelHtml).not.toContain('//evil.example/phish');

    // 8b. Multi-token / multi-account chooser & session switching on same browser
    // /login with 1 signed-in account still renders Account Chooser with login/register options
    const loginChooser = await req('/login', userJar);
    expect(loginChooser.status).toBe(200);
    const loginChooserHtml = await loginChooser.text();
    expect(loginChooserHtml).toContain('Choose an account');
    expect(loginChooserHtml).toContain('joe@example.com');
    expect(loginChooserHtml).toContain('Use another account');
    expect(loginChooserHtml).toContain('Create account');

    // /login?mode=add and /register remain accessible while signed in
    expect((await req('/login?mode=add', userJar)).status).toBe(200);
    expect((await req('/register', userJar)).status).toBe(200);

    // Single account stays on clean /account URL without forcing /u/0
    const singleAccountPage = await req('/account', userJar);
    expect(singleAccountPage.status).toBe(200);
    expect(await singleAccountPage.text()).toContain('<meta name="account-base" content=""');

    // Sign up a 2nd account into the same browser jar -> both accounts co-exist
    const alexReg = await req('/api/auth/register', userJar, {
      method: 'POST',
      body: {
        name: 'Alex Doe',
        email: 'alex@example.com',
        password: 'StrongPassword123',
        turnstileToken: 'test-token',
      },
    });
    expect(alexReg.status).toBe(201);
    const alexJson = (await alexReg.json()) as {
      data: { slot: string; userCount: number; user: { id: string } };
    };
    const alexUserId = alexJson.data.user.id;
    expect(alexJson.data.slot).toBe('1');
    expect(alexJson.data.userCount).toBe(2);

    // Multi-account bare /account redirects to /u/<slot>/account (Google-style)
    const bareAccountMulti = await req('/account', userJar);
    expect(bareAccountMulti.status).toBe(302);
    expect(bareAccountMulti.headers.get('location')).toBe('/u/1/account');

    // Simultaneous /u/0 and /u/1 work independently on the same CookieJar without switching global cookie
    const u0Page = await req('/u/0/account', userJar);
    expect(u0Page.status).toBe(200);
    const u0Html = await u0Page.text();
    expect(u0Html).toContain('<meta name="account-base" content="/u/0"');
    expect(u0Html).toContain('href="/u/0/developer"');

    const u0Me = await req('/u/0/api/user/me', userJar);
    expect(((await u0Me.json()) as { data: { email: string } }).data.email).toBe('joe@example.com');

    const u1Me = await req('/u/1/api/user/me', userJar);
    expect(((await u1Me.json()) as { data: { email: string } }).data.email).toBe('alex@example.com');

    // Superuser co-exists under special /u/superuser slot without disturbing u/0 or u/1
    const multiSuLogin = await req('/api/admin/superuser/login', userJar, {
      method: 'POST',
      body: { password: 'test-superuser-pass', turnstileToken: 'test-token' },
    });
    expect(multiSuLogin.status).toBe(200);
    expect(((await multiSuLogin.json()) as { data: { slot: string } }).data.slot).toBe('superuser');

    // Re-read /u/0 and /u/1 and /u/superuser simultaneously
    expect(((await (await req('/u/0/api/user/me', userJar)).json()) as { data: { email: string } }).data.email).toBe(
      'joe@example.com'
    );
    expect(((await (await req('/u/1/api/user/me', userJar)).json()) as { data: { email: string } }).data.email).toBe(
      'alex@example.com'
    );
    const suAdminPage = await req('/u/superuser/admin', userJar);
    expect(suAdminPage.status).toBe(200);
    expect(await suAdminPage.text()).toContain('<meta name="account-base" content="/u/superuser"');
    expect((await req('/u/superuser/api/admin/overview', userJar)).status).toBe(200);
    // Slot isolation: regular user slot u/0 cannot access /admin even though superuser is signed in
    expect((await req('/u/0/admin', userJar)).status).toBe(302);

    const accountsResp = await req('/api/auth/accounts', userJar);
    expect(accountsResp.status).toBe(200);
    const accountsJson = (await accountsResp.json()) as {
      data: {
        accounts: Array<{ sessionId: string; slot: string; isActive: boolean; isSuperuser: boolean; user: { email: string } | null }>;
      };
    };
    expect(accountsJson.data.accounts.length).toBe(3);
    const joeEntry = accountsJson.data.accounts.find((a) => a.user?.email === 'joe@example.com')!;
    const alexEntry = accountsJson.data.accounts.find((a) => a.user?.email === 'alex@example.com')!;
    expect(joeEntry.slot).toBe('0');
    expect(alexEntry.slot).toBe('1');

    // Switch back to Joe on bare cookie & verify client header spoofing x-joe-slot is rejected
    const goodSwitch = await req('/api/auth/switch', userJar, {
      method: 'POST',
      body: { sessionId: joeEntry.sessionId },
    });
    expect(goodSwitch.status).toBe(200);
    const spoofedSlotResp = await req('/api/admin/overview', userJar, {
      headers: { 'x-joe-slot': 'superuser' },
    });
    expect(spoofedSlotResp.status).toBe(403);

    // Log out ONLY the superuser slot via /u/superuser/api/auth/logout; Joe & Alex remain signed in
    const suSlotLogout = await req('/u/superuser/api/auth/logout', userJar, { method: 'POST', body: {} });
    expect(suSlotLogout.status).toBe(200);
    expect((await req('/u/superuser/api/admin/overview', userJar)).status).toBe(401);

    // Reject switching to an unknown/foreign sessionId
    const badSwitch = await req('/api/auth/switch', userJar, {
      method: 'POST',
      body: { sessionId: 'nonexistent_session_id' },
    });
    expect(badSwitch.status).toBe(403);

    const switchedMe = await req('/api/user/me', userJar);
    expect(((await switchedMe.json()) as { data: { email: string } }).data.email).toBe('joe@example.com');

    // Sign out only Alex -> Joe stays active & bare /account returns 200 again for single account
    const logoutAlex = await req('/api/auth/logout', userJar, {
      method: 'POST',
      body: { sessionId: alexEntry.sessionId },
    });
    expect(logoutAlex.status).toBe(200);
    expect((await req('/account', userJar)).status).toBe(200);

    const remainingAccounts = (
      (await (await req('/api/auth/accounts', userJar)).json()) as {
        data: { accounts: Array<{ user: { email: string } | null }> };
      }
    ).data.accounts;
    expect(remainingAccounts.length).toBe(1);
    expect(remainingAccounts[0].user?.email).toBe('joe@example.com');

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

    // 8c. Admin Panel versatile user management, self-protection guards, app deletion & log/maintenance purges
    // Admin page renders with current user id for self-protection UI
    const adminPageResp = await req('/admin', adminJar);
    expect(adminPageResp.status).toBe(200);
    const adminPageHtml = await adminPageResp.text();
    expect(adminPageHtml).toContain(`data-current-user-id="${helperId}"`);

    // Helper Admin CANNOT suspend or delete their own active account
    const selfSuspend = await req(`/api/admin/users/${helperId}/status`, adminJar, {
      method: 'PATCH',
      body: { status: 'suspended' },
    });
    expect(selfSuspend.status).toBe(400);

    const selfDelete = await req(`/api/admin/users/${helperId}`, adminJar, {
      method: 'DELETE',
      body: {},
    });
    expect(selfDelete.status).toBe(400);

    // Grant & revoke developer privilege via admin API
    const grantDev = await req(`/api/admin/users/${alexUserId}/developer-status`, adminJar, {
      method: 'PATCH',
      body: { developerStatus: 'approved' },
    });
    expect(grantDev.status).toBe(200);
    const revokeDev = await req(`/api/admin/users/${alexUserId}/developer-status`, adminJar, {
      method: 'PATCH',
      body: { developerStatus: 'revoked' },
    });
    expect(revokeDev.status).toBe(200);

    // Admin sets Alex's password -> old password fails (creates login_failed audit log), new password works
    const setPwd = await req(`/api/admin/users/${alexUserId}/password`, adminJar, {
      method: 'POST',
      body: { newPassword: 'BrandNewPassword456' },
    });
    expect(setPwd.status).toBe(200);

    const alexLoginJar = new CookieJar();
    const badLogin = await req('/api/auth/login', alexLoginJar, {
      method: 'POST',
      body: { email: 'alex@example.com', password: 'StrongPassword123', turnstileToken: 'test-token' },
    });
    expect(badLogin.status).toBe(401);

    const okNewPwdLogin = await req('/api/auth/login', alexLoginJar, {
      method: 'POST',
      body: { email: 'alex@example.com', password: 'BrandNewPassword456', turnstileToken: 'test-token' },
    });
    expect(okNewPwdLogin.status).toBe(200);

    // Admin revokes Alex's sessions -> Alex session invalidated
    const revokeAlexSessions = await req(`/api/admin/users/${alexUserId}/revoke-sessions`, adminJar, {
      method: 'POST',
      body: {},
    });
    expect(revokeAlexSessions.status).toBe(200);
    expect((await req('/api/user/me', alexLoginJar)).status).toBe(401);

    // Admin resets 2FA & deletes Alex's account
    const reset2fa = await req(`/api/admin/users/${alexUserId}/2fa`, adminJar, {
      method: 'DELETE',
      body: {},
    });
    expect(reset2fa.status).toBe(200);

    const deleteAlex = await req(`/api/admin/users/${alexUserId}`, adminJar, {
      method: 'DELETE',
      body: {},
    });
    expect(deleteAlex.status).toBe(200);

    const deletedLookup = await req('/api/admin/users?q=alex@example.com', adminJar);
    expect(((await deletedLookup.json()) as { data: unknown[] }).data.length).toBe(0);

    // Admin can delete OAuth apps directly
    const adminDelApp = await req(`/api/admin/apps/${restrictedApp.data.id}`, adminJar, {
      method: 'DELETE',
      body: {},
    });
    expect(adminDelApp.status).toBe(200);

    // Audit log category filter & categorized log purge + maintenance purge
    const failureLogsBefore = (
      (await (await req('/api/admin/audit-logs?category=auth_failures', adminJar)).json()) as {
        data: unknown[];
      }
    ).data;
    expect(failureLogsBefore.length).toBeGreaterThan(0);

    const purgeFailures = await req('/api/admin/audit-logs/purge', adminJar, {
      method: 'POST',
      body: { category: 'auth_failures' },
    });
    expect(purgeFailures.status).toBe(200);
    expect(((await purgeFailures.json()) as { data: { deleted: number } }).data.deleted).toBeGreaterThan(0);

    const failureLogsAfter = (
      (await (await req('/api/admin/audit-logs?category=auth_failures', adminJar)).json()) as {
        data: unknown[];
      }
    ).data;
    expect(failureLogsAfter.length).toBe(0);

    const maintPurge = await req('/api/admin/maintenance/purge', adminJar, {
      method: 'POST',
      body: { target: 'all_stale' },
    });
    expect(maintPurge.status).toBe(200);

    const overviewAfter = (
      (await (await req('/api/admin/overview', adminJar)).json()) as {
        data: { maintenance: { auditLogsTotal: number; authFailureLogs: number } };
      }
    ).data;
    expect(overviewAfter.maintenance.authFailureLogs).toBe(0);
    expect(overviewAfter.maintenance.auditLogsTotal).toBeGreaterThan(0);

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
