import { Hono } from 'hono';
import { renderSVG } from 'uqr';
import type { AppEnv, SessionRow } from '../types';
import {
  buildTotpUri,
  generateRecoveryCodes,
  generateTotpSecret,
  hashPassword,
  normalizeRecoveryCode,
  nowSec,
  randomBase64Url,
  sha256Hex,
  verifyPassword,
  verifyTotpCode,
} from '../lib/crypto';
import {
  deleteUserAccountData,
  destroyCurrentSession,
  getIpHash,
  getPepper,
  isEmailVerificationRequired,
  parseUserAgentSummary,
} from '../lib/session';
import { evaluateRegistrationEmail, getActiveRules } from '../lib/rules';
import { extractUploadedPng, getAppLogoUrl, getUserAvatarUrl } from '../lib/images';
import { sendEmail, verificationEmailContent } from '../lib/email';
import { writeAuditLog } from '../lib/audit';
import { toBase64Url, verifyRegistrationResponse } from '../lib/webauthn';
import { dispatchAppWebhooks } from '../lib/webhooks';
import { requireCsrf, requireUser } from '../middleware/auth';

const userRoutes = new Hono<AppEnv>();

userRoutes.use('*', requireUser);

userRoutes.get('/me', (c) => {
  const user = c.get('auth')!.user!;
  return c.json({
    ok: true,
    data: {
      id: user.id,
      email: user.email,
      name: user.name,
      role: user.role,
      developer_status: user.developer_status,
      email_verified: user.email_verified === 1,
      totp_enabled: user.totp_enabled === 1,
      avatar_color: user.avatar_color,
      avatar_url: getUserAvatarUrl('', user.id, user.avatar_version),
      has_custom_avatar: Boolean(user.avatar_key),
      created_at: user.created_at,
    },
  });
});

userRoutes.post('/avatar', requireCsrf, async (c) => {
  const user = c.get('auth')!.user!;
  const parsed = await extractUploadedPng(c.req.raw, ['file', 'avatar']);
  if (!parsed.ok) {
    return c.json({ ok: false, error: { code: 'INVALID_IMAGE', message: parsed.message } }, 400);
  }

  const nextVersion = (user.avatar_version || 0) + 1;
  const key = `avatars/${user.id}/v${nextVersion}.png`;
  await c.env.MEDIA_BUCKET.put(key, parsed.bytes, {
    httpMetadata: { contentType: 'image/png' },
  });

  if (user.avatar_key && user.avatar_key !== key) {
    await c.env.MEDIA_BUCKET.delete(user.avatar_key).catch(() => {});
  }

  await c.env.DB.prepare('UPDATE users SET avatar_key = ?, avatar_version = ?, updated_at = ? WHERE id = ?')
    .bind(key, nextVersion, nowSec(), user.id)
    .run();

  await writeAuditLog(c.env.DB, {
    actorId: user.id,
    action: 'user.avatar_updated',
    targetType: 'user',
    targetId: user.id,
    ipHash: await getIpHash(c),
  });

  return c.json({
    ok: true,
    data: {
      avatar_url: getUserAvatarUrl('', user.id, nextVersion),
      avatar_version: nextVersion,
      has_custom_avatar: true,
    },
  });
});

userRoutes.delete('/avatar', requireCsrf, async (c) => {
  const user = c.get('auth')!.user!;
  if (user.avatar_key) {
    await c.env.MEDIA_BUCKET.delete(user.avatar_key).catch(() => {});
  }
  const nextVersion = (user.avatar_version || 0) + 1;
  await c.env.DB.prepare('UPDATE users SET avatar_key = NULL, avatar_version = ?, updated_at = ? WHERE id = ?')
    .bind(nextVersion, nowSec(), user.id)
    .run();

  await writeAuditLog(c.env.DB, {
    actorId: user.id,
    action: 'user.avatar_deleted',
    targetType: 'user',
    targetId: user.id,
    ipHash: await getIpHash(c),
  });

  return c.json({
    ok: true,
    data: {
      avatar_url: getUserAvatarUrl('', user.id, nextVersion),
      avatar_version: nextVersion,
      has_custom_avatar: false,
    },
  });
});

userRoutes.patch('/profile', requireCsrf, async (c) => {
  const user = c.get('auth')!.user!;
  const body = await c.req.json<{ name?: string }>().catch(() => ({} as Record<string, undefined>));
  const name = (body.name || '').trim();
  if (name.length < 1 || name.length > 80) {
    return c.json({ ok: false, error: { code: 'INVALID_NAME', message: 'Name must be 1 to 80 characters.' } }, 400);
  }

  await c.env.DB.prepare('UPDATE users SET name = ?, updated_at = ? WHERE id = ?')
    .bind(name, nowSec(), user.id)
    .run();

  return c.json({ ok: true, data: { name } });
});

userRoutes.post('/change-email', requireCsrf, async (c) => {
  const user = c.get('auth')!.user!;
  const body = await c.req.json<{ newEmail?: string; currentPassword?: string }>().catch(() => ({} as Record<string, undefined>));
  const newEmail = (body.newEmail || '').trim().toLowerCase();
  const currentPassword = body.currentPassword || '';

  if (!(await verifyPassword(currentPassword, user.password_hash, getPepper(c.env)))) {
    return c.json({ ok: false, error: { code: 'INVALID_PASSWORD', message: 'Current password is incorrect.' } }, 401);
  }
  if (newEmail === user.email.toLowerCase()) {
    return c.json({ ok: false, error: { code: 'SAME_EMAIL', message: 'New email matches your current email.' } }, 400);
  }

  const rules = await getActiveRules(c.env);
  const ruleEval = evaluateRegistrationEmail(newEmail, rules);
  if (!ruleEval.allowed) {
    return c.json({ ok: false, error: { code: 'EMAIL_RULE_BLOCKED', message: 'This email address is not permitted.' } }, 403);
  }

  const taken = await c.env.DB.prepare('SELECT id FROM users WHERE email = ?').bind(newEmail).first();
  if (taken) {
    return c.json({ ok: false, error: { code: 'EMAIL_EXISTS', message: 'Email is already in use.' } }, 409);
  }

  const now = nowSec();
  if (await isEmailVerificationRequired(c.env)) {
    const rawToken = randomBase64Url(32);
    const tokenHash = await sha256Hex(rawToken);
    await c.env.DB.prepare(
      'INSERT INTO verification_tokens (token_hash, user_id, purpose, target_value, expires_at, created_at) VALUES (?, ?, ?, ?, ?, ?)'
    )
      .bind(tokenHash, user.id, 'email_change', newEmail, now + 1800, now)
      .run();

    const origin = c.env.ISSUER_URL || new URL(c.req.url).origin;
    const verifyUrl = `${origin}/api/auth/verify-email?token=${encodeURIComponent(rawToken)}`;
    const content = verificationEmailContent(c.env.APP_NAME || 'JoeAuth', verifyUrl, 'email_change');
    await sendEmail(c.env, { to: newEmail, ...content });

    return c.json({
      ok: true,
      data: { verificationRequired: true, message: `Confirmation link sent to ${newEmail}.` },
    });
  }

  await c.env.DB.prepare('UPDATE users SET email = ?, updated_at = ? WHERE id = ?')
    .bind(newEmail, now, user.id)
    .run();

  await writeAuditLog(c.env.DB, {
    actorId: user.id,
    action: 'user.email_changed',
    targetType: 'user',
    targetId: user.id,
    ipHash: await getIpHash(c),
  });

  return c.json({ ok: true, data: { verificationRequired: false, email: newEmail } });
});

userRoutes.post('/change-password', requireCsrf, async (c) => {
  const auth = c.get('auth')!;
  const user = auth.user!;
  const body = await c.req.json<{ currentPassword?: string; newPassword?: string }>().catch(() => ({} as Record<string, undefined>));

  if (!(await verifyPassword(body.currentPassword || '', user.password_hash, getPepper(c.env)))) {
    return c.json({ ok: false, error: { code: 'INVALID_PASSWORD', message: 'Current password is incorrect.' } }, 401);
  }
  const newPassword = body.newPassword || '';
  if (newPassword.length < 8 || newPassword.length > 128) {
    return c.json(
      { ok: false, error: { code: 'WEAK_PASSWORD', message: 'New password must be 8 to 128 characters.' } },
      400
    );
  }

  const newHash = await hashPassword(newPassword, getPepper(c.env));
  await c.env.DB.batch([
    c.env.DB.prepare('UPDATE users SET password_hash = ?, updated_at = ? WHERE id = ?').bind(newHash, nowSec(), user.id),
    c.env.DB.prepare('DELETE FROM sessions WHERE user_id = ? AND id != ?').bind(user.id, auth.sessionId),
    c.env.DB.prepare("DELETE FROM verification_tokens WHERE user_id = ? AND purpose = 'password_reset'").bind(user.id),
  ]);

  await writeAuditLog(c.env.DB, {
    actorId: user.id,
    action: 'user.password_changed',
    targetType: 'user',
    targetId: user.id,
    ipHash: await getIpHash(c),
  });

  return c.json({ ok: true, data: { message: 'Password updated and other sessions signed out.' } });
});

userRoutes.get('/sessions', async (c) => {
  const auth = c.get('auth')!;
  const { results } = await c.env.DB.prepare(
    'SELECT id, ip_hash, user_agent, auth_time, created_at, last_seen_at, expires_at FROM sessions WHERE user_id = ? AND expires_at > ? ORDER BY last_seen_at DESC'
  )
    .bind(auth.user!.id, nowSec())
    .all<Pick<SessionRow, 'id' | 'ip_hash' | 'user_agent' | 'auth_time' | 'created_at' | 'last_seen_at' | 'expires_at'>>();

  return c.json({
    ok: true,
    data: (results || []).map((s) => ({
      id: s.id,
      user_agent: s.user_agent,
      device_label: parseUserAgentSummary(s.user_agent),
      ip_hash: s.ip_hash,
      auth_time: s.auth_time || s.created_at,
      created_at: s.created_at,
      last_seen_at: s.last_seen_at,
      expires_at: s.expires_at,
      is_current: s.id === auth.sessionId,
    })),
  });
});

userRoutes.delete('/sessions/:id', requireCsrf, async (c) => {
  const auth = c.get('auth')!;
  const targetId = c.req.param('id');
  await c.env.DB.prepare('DELETE FROM sessions WHERE id = ? AND user_id = ?')
    .bind(targetId, auth.user!.id)
    .run();
  return c.json({ ok: true, data: { revoked: true } });
});

userRoutes.delete('/sessions', requireCsrf, async (c) => {
  const auth = c.get('auth')!;
  await c.env.DB.prepare('DELETE FROM sessions WHERE user_id = ? AND id != ?')
    .bind(auth.user!.id, auth.sessionId)
    .run();
  return c.json({ ok: true, data: { revokedAllOthers: true } });
});

userRoutes.get('/apps', async (c) => {
  const user = c.get('auth')!.user!;
  const { results } = await c.env.DB.prepare(
    `SELECT uc.app_id, uc.scopes, uc.granted_at, a.name, a.description, a.privilege_description, a.homepage_url, a.client_id, a.logo_key, a.logo_version
     FROM user_consents uc
     JOIN apps a ON a.id = uc.app_id
     WHERE uc.user_id = ?
     ORDER BY uc.granted_at DESC`
  )
    .bind(user.id)
    .all<{
      app_id: string;
      scopes: string;
      granted_at: number;
      name: string;
      description: string;
      privilege_description: string;
      homepage_url: string;
      client_id: string;
      logo_key: string | null;
      logo_version: number;
    }>();

  return c.json({
    ok: true,
    data: (results || []).map(({ logo_key, logo_version, ...row }) => ({
      ...row,
      has_custom_logo: Boolean(logo_key),
      logo_url: logo_key ? getAppLogoUrl('', row.app_id, logo_version) : null,
    })),
  });
});

userRoutes.delete('/apps/:appId', requireCsrf, async (c) => {
  const user = c.get('auth')!.user!;
  const appId = c.req.param('appId');
  await c.env.DB.batch([
    c.env.DB.prepare('DELETE FROM user_consents WHERE user_id = ? AND app_id = ?').bind(user.id, appId),
    c.env.DB.prepare('UPDATE refresh_tokens SET revoked = 1 WHERE user_id = ? AND app_id = ?').bind(user.id, appId),
  ]);
  await dispatchAppWebhooks(c.env, c.executionCtx, {
    event: 'consent.revoked',
    userId: user.id,
    appId,
    data: { user_id: user.id },
  });
  return c.json({ ok: true, data: { revoked: true } });
});

userRoutes.post('/2fa/setup', requireCsrf, async (c) => {
  const user = c.get('auth')!.user!;
  const secret = generateTotpSecret();
  await c.env.DB.prepare('UPDATE users SET totp_secret = ?, totp_enabled = 0, updated_at = ? WHERE id = ?')
    .bind(secret, nowSec(), user.id)
    .run();

  const otpauthUri = buildTotpUri(secret, user.email, c.env.APP_NAME || 'JoeAuth');
  const svg = renderSVG(otpauthUri, { border: 2, pixelSize: 6 });
  const qrDataUrl = `data:image/svg+xml;utf8,${encodeURIComponent(svg)}`;

  return c.json({
    ok: true,
    data: {
      secret,
      otpauthUri,
      qrDataUrl,
    },
  });
});

async function replaceUserRecoveryCodes(db: D1Database, userId: string): Promise<string[]> {
  const codes = generateRecoveryCodes(8);
  const now = nowSec();
  const inserts = await Promise.all(
    codes.map(async (code) => {
      const hash = await sha256Hex(`${userId}:${normalizeRecoveryCode(code)}`);
      return db
        .prepare('INSERT INTO user_recovery_codes (id, user_id, code_hash, created_at) VALUES (?, ?, ?, ?)')
        .bind(crypto.randomUUID(), userId, hash, now);
    })
  );
  await db.batch([db.prepare('DELETE FROM user_recovery_codes WHERE user_id = ?').bind(userId), ...inserts]);
  return codes;
}

userRoutes.post('/2fa/verify', requireCsrf, async (c) => {
  const user = c.get('auth')!.user!;
  const body = await c.req.json<{ code?: string }>().catch(() => ({} as Record<string, undefined>));
  if (!user.totp_secret) {
    return c.json({ ok: false, error: { code: 'NO_TOTP_SETUP', message: 'Start 2FA setup first.' } }, 400);
  }
  const ok = await verifyTotpCode(user.totp_secret, body.code || '');
  if (!ok) {
    return c.json({ ok: false, error: { code: 'TOTP_INVALID', message: 'Invalid 6-digit code.' } }, 400);
  }
  await c.env.DB.prepare('UPDATE users SET totp_enabled = 1, updated_at = ? WHERE id = ?')
    .bind(nowSec(), user.id)
    .run();

  const recoveryCodes = await replaceUserRecoveryCodes(c.env.DB, user.id);
  await writeAuditLog(c.env.DB, { actorId: user.id, action: 'user.2fa_enabled', targetType: 'user', targetId: user.id });
  return c.json({ ok: true, data: { totpEnabled: true, recoveryCodes } });
});

userRoutes.post('/2fa/recovery-codes/regenerate', requireCsrf, async (c) => {
  const user = c.get('auth')!.user!;
  const body = await c.req.json<{ currentPassword?: string }>().catch(() => ({} as Record<string, undefined>));
  if (user.totp_enabled !== 1) {
    return c.json({ ok: false, error: { code: 'TOTP_NOT_ENABLED', message: 'Enable 2FA first.' } }, 400);
  }
  if (!(await verifyPassword(body.currentPassword || '', user.password_hash, getPepper(c.env)))) {
    return c.json({ ok: false, error: { code: 'INVALID_PASSWORD', message: 'Password is incorrect.' } }, 401);
  }

  const recoveryCodes = await replaceUserRecoveryCodes(c.env.DB, user.id);
  await writeAuditLog(c.env.DB, {
    actorId: user.id,
    action: 'user.2fa_recovery_regenerated',
    targetType: 'user',
    targetId: user.id,
    ipHash: await getIpHash(c),
  });
  return c.json({ ok: true, data: { recoveryCodes } });
});

userRoutes.delete('/2fa', requireCsrf, async (c) => {
  const user = c.get('auth')!.user!;
  const body = await c.req.json<{ currentPassword?: string }>().catch(() => ({} as Record<string, undefined>));
  if (!(await verifyPassword(body.currentPassword || '', user.password_hash, getPepper(c.env)))) {
    return c.json({ ok: false, error: { code: 'INVALID_PASSWORD', message: 'Password is incorrect.' } }, 401);
  }
  await c.env.DB.batch([
    c.env.DB.prepare('UPDATE users SET totp_enabled = 0, totp_secret = NULL, updated_at = ? WHERE id = ?').bind(nowSec(), user.id),
    c.env.DB.prepare('DELETE FROM user_recovery_codes WHERE user_id = ?').bind(user.id),
  ]);
  await writeAuditLog(c.env.DB, { actorId: user.id, action: 'user.2fa_disabled', targetType: 'user', targetId: user.id });
  return c.json({ ok: true, data: { totpEnabled: false } });
});

// --- WebAuthn Passkeys ---

userRoutes.get('/passkeys', async (c) => {
  const user = c.get('auth')!.user!;
  const { results } = await c.env.DB.prepare(
    'SELECT id, label AS name, transports, created_at, last_used_at FROM webauthn_credentials WHERE user_id = ? ORDER BY created_at DESC'
  )
    .bind(user.id)
    .all<{ id: string; name: string; transports: string; created_at: number; last_used_at: number | null }>();

  return c.json({
    ok: true,
    data: (results || []).map((r) => ({
      ...r,
      transports: (() => {
        try {
          return JSON.parse(r.transports) as string[];
        } catch {
          return [];
        }
      })(),
    })),
  });
});

userRoutes.post('/passkeys/register/options', requireCsrf, async (c) => {
  const user = c.get('auth')!.user!;
  const { results } = await c.env.DB.prepare('SELECT id AS credential_id FROM webauthn_credentials WHERE user_id = ?')
    .bind(user.id)
    .all<{ credential_id: string }>();

  if ((results || []).length >= 10) {
    return c.json({ ok: false, error: { code: 'LIMIT_REACHED', message: 'Maximum of 10 passkeys per account.' } }, 400);
  }

  const challenge = randomBase64Url(32);
  const challengeId = randomBase64Url(16);
  const rpId = new URL(c.req.url).hostname;

  await c.env.AUTH_CACHE.put(
    `passkey:reg:${challengeId}`,
    JSON.stringify({ userId: user.id, challenge }),
    { expirationTtl: 300 }
  );

  return c.json({
    ok: true,
    data: {
      challengeId,
      options: {
        challenge,
        rp: { name: c.env.APP_NAME || 'JoeAuth', id: rpId },
        user: {
          id: toBase64Url(new TextEncoder().encode(user.id)),
          name: user.email,
          displayName: user.name,
        },
        pubKeyCredParams: [
          { type: 'public-key', alg: -7 },
          { type: 'public-key', alg: -257 },
        ],
        timeout: 60000,
        authenticatorSelection: {
          residentKey: 'preferred',
          userVerification: 'preferred',
        },
        excludeCredentials: (results || []).map((r) => ({ id: r.credential_id, type: 'public-key' })),
      },
    },
  });
});

userRoutes.post('/passkeys/register/verify', requireCsrf, async (c) => {
  const user = c.get('auth')!.user!;
  const body = await c.req.json<{
    challengeId?: string;
    name?: string;
    clientDataJSON?: string;
    attestationObject?: string;
    transports?: string[];
  }>().catch(() => ({} as Record<string, unknown>));

  const challengeId = typeof body.challengeId === 'string' ? body.challengeId.trim() : '';
  const name = typeof body.name === 'string' && body.name.trim() ? body.name.trim().slice(0, 48) : 'Passkey';
  if (!challengeId || typeof body.clientDataJSON !== 'string' || typeof body.attestationObject !== 'string') {
    return c.json({ ok: false, error: { code: 'INVALID_INPUT', message: 'Incomplete passkey registration data.' } }, 400);
  }

  const key = `passkey:reg:${challengeId}`;
  const raw = await c.env.AUTH_CACHE.get(key);
  await c.env.AUTH_CACHE.delete(key).catch(() => {});
  if (!raw) {
    return c.json({ ok: false, error: { code: 'CHALLENGE_EXPIRED', message: 'Registration session expired.' } }, 400);
  }

  const parsedChallenge = JSON.parse(raw) as { userId: string; challenge: string };
  if (parsedChallenge.userId !== user.id) {
    return c.json({ ok: false, error: { code: 'FORBIDDEN', message: 'Challenge does not belong to current user.' } }, 403);
  }

  const reqUrl = new URL(c.req.url);
  let verified;
  try {
    verified = await verifyRegistrationResponse({
      clientDataJSON: body.clientDataJSON,
      attestationObject: body.attestationObject,
      expectedChallenge: parsedChallenge.challenge,
      expectedOrigin: reqUrl.origin,
      expectedRpId: reqUrl.hostname,
    });
  } catch (err) {
    return c.json(
      { ok: false, error: { code: 'INVALID_ATTESTATION', message: err instanceof Error ? err.message : 'Invalid passkey data.' } },
      400
    );
  }

  const existing = await c.env.DB.prepare('SELECT id FROM webauthn_credentials WHERE id = ?')
    .bind(verified.credentialId)
    .first();
  if (existing) {
    return c.json({ ok: false, error: { code: 'DUPLICATE_PASSKEY', message: 'This passkey is already registered.' } }, 409);
  }

  const transports = Array.isArray(body.transports)
    ? body.transports.filter((t): t is string => typeof t === 'string').slice(0, 6)
    : [];

  await c.env.DB.prepare(
    `INSERT INTO webauthn_credentials (id, user_id, label, public_key_jwk, alg, sign_count, transports, created_at)
     VALUES (?, ?, ?, ?, ?, ?, ?, ?)`
  )
    .bind(
      verified.credentialId,
      user.id,
      name,
      verified.publicKeyJwkJson,
      verified.alg,
      verified.signCount,
      JSON.stringify(transports),
      nowSec()
    )
    .run();

  await writeAuditLog(c.env.DB, {
    actorId: user.id,
    action: 'user.passkey_added',
    targetType: 'webauthn_credential',
    targetId: verified.credentialId,
    ipHash: await getIpHash(c),
  });

  return c.json({ ok: true, data: { id: verified.credentialId, name, transports } }, 201);
});

userRoutes.delete('/passkeys/:id', requireCsrf, async (c) => {
  const user = c.get('auth')!.user!;
  const id = c.req.param('id');
  const res = await c.env.DB.prepare('DELETE FROM webauthn_credentials WHERE id = ? AND user_id = ?')
    .bind(id, user.id)
    .run();
  if (!res.meta.changes) {
    return c.json({ ok: false, error: { code: 'NOT_FOUND', message: 'Passkey not found.' } }, 404);
  }
  await writeAuditLog(c.env.DB, {
    actorId: user.id,
    action: 'user.passkey_removed',
    targetType: 'webauthn_credential',
    targetId: id,
    ipHash: await getIpHash(c),
  });
  return c.json({ ok: true, data: { deleted: true } });
});

userRoutes.delete('/account', requireCsrf, async (c) => {
  const user = c.get('auth')!.user!;
  const body = await c.req.json<{ currentPassword?: string }>().catch(() => ({} as Record<string, undefined>));
  if (!(await verifyPassword(body.currentPassword || '', user.password_hash, getPepper(c.env)))) {
    return c.json({ ok: false, error: { code: 'INVALID_PASSWORD', message: 'Password is incorrect.' } }, 401);
  }

  await dispatchAppWebhooks(c.env, c.executionCtx, {
    event: 'user.deleted',
    userId: user.id,
    data: { user_id: user.id },
  });

  await writeAuditLog(c.env.DB, {
    actorId: user.id,
    action: 'user.account_deleted',
    targetType: 'user',
    targetId: user.id,
    ipHash: await getIpHash(c),
  });

  await deleteUserAccountData(c.env.DB, c.env.MEDIA_BUCKET, user.id, user.avatar_key);

  await destroyCurrentSession(c);
  return c.json({ ok: true, data: { deleted: true } });
});

export default userRoutes;
