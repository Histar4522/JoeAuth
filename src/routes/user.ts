import { Hono } from 'hono';
import { renderSVG } from 'uqr';
import type { AppEnv, SessionRow } from '../types';
import {
  buildTotpUri,
  generateTotpSecret,
  hashPassword,
  nowSec,
  randomBase64Url,
  sha256Hex,
  verifyPassword,
  verifyTotpCode,
} from '../lib/crypto';
import { destroyCurrentSession, getIpHash, getPepper, isEmailVerificationRequired } from '../lib/session';
import { evaluateRegistrationEmail, getActiveRules } from '../lib/rules';
import { sendEmail, verificationEmailContent } from '../lib/email';
import { writeAuditLog } from '../lib/audit';
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
      created_at: user.created_at,
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
    return c.json({ ok: false, error: { code: 'EMAIL_RULE_BLOCKED', message: ruleEval.reason } }, 403);
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
    'SELECT id, ip_hash, user_agent, created_at, last_seen_at, expires_at FROM sessions WHERE user_id = ? AND expires_at > ? ORDER BY last_seen_at DESC'
  )
    .bind(auth.user!.id, nowSec())
    .all<Pick<SessionRow, 'id' | 'ip_hash' | 'user_agent' | 'created_at' | 'last_seen_at' | 'expires_at'>>();

  return c.json({
    ok: true,
    data: (results || []).map((s) => ({
      id: s.id,
      user_agent: s.user_agent,
      ip_hash: s.ip_hash,
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
    `SELECT uc.app_id, uc.scopes, uc.granted_at, a.name, a.homepage_url, a.client_id
     FROM user_consents uc
     JOIN apps a ON a.id = uc.app_id
     WHERE uc.user_id = ?
     ORDER BY uc.granted_at DESC`
  )
    .bind(user.id)
    .all<{ app_id: string; scopes: string; granted_at: number; name: string; homepage_url: string; client_id: string }>();

  return c.json({ ok: true, data: results || [] });
});

userRoutes.delete('/apps/:appId', requireCsrf, async (c) => {
  const user = c.get('auth')!.user!;
  const appId = c.req.param('appId');
  await c.env.DB.batch([
    c.env.DB.prepare('DELETE FROM user_consents WHERE user_id = ? AND app_id = ?').bind(user.id, appId),
    c.env.DB.prepare('UPDATE refresh_tokens SET revoked = 1 WHERE user_id = ? AND app_id = ?').bind(user.id, appId),
  ]);
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

  await writeAuditLog(c.env.DB, { actorId: user.id, action: 'user.2fa_enabled', targetType: 'user', targetId: user.id });
  return c.json({ ok: true, data: { totpEnabled: true } });
});

userRoutes.delete('/2fa', requireCsrf, async (c) => {
  const user = c.get('auth')!.user!;
  const body = await c.req.json<{ currentPassword?: string }>().catch(() => ({} as Record<string, undefined>));
  if (!(await verifyPassword(body.currentPassword || '', user.password_hash, getPepper(c.env)))) {
    return c.json({ ok: false, error: { code: 'INVALID_PASSWORD', message: 'Password is incorrect.' } }, 401);
  }
  await c.env.DB.prepare('UPDATE users SET totp_enabled = 0, totp_secret = NULL, updated_at = ? WHERE id = ?')
    .bind(nowSec(), user.id)
    .run();
  await writeAuditLog(c.env.DB, { actorId: user.id, action: 'user.2fa_disabled', targetType: 'user', targetId: user.id });
  return c.json({ ok: true, data: { totpEnabled: false } });
});

userRoutes.delete('/account', requireCsrf, async (c) => {
  const user = c.get('auth')!.user!;
  const body = await c.req.json<{ currentPassword?: string }>().catch(() => ({} as Record<string, undefined>));
  if (!(await verifyPassword(body.currentPassword || '', user.password_hash, getPepper(c.env)))) {
    return c.json({ ok: false, error: { code: 'INVALID_PASSWORD', message: 'Password is incorrect.' } }, 401);
  }

  await writeAuditLog(c.env.DB, {
    actorId: user.id,
    action: 'user.account_deleted',
    targetType: 'user',
    targetId: user.id,
    ipHash: await getIpHash(c),
  });

  await c.env.DB.batch([
    c.env.DB.prepare('DELETE FROM sessions WHERE user_id = ?').bind(user.id),
    c.env.DB.prepare('DELETE FROM refresh_tokens WHERE user_id = ?').bind(user.id),
    c.env.DB.prepare('DELETE FROM oauth_codes WHERE user_id = ?').bind(user.id),
    c.env.DB.prepare('DELETE FROM verification_tokens WHERE user_id = ?').bind(user.id),
    c.env.DB.prepare('DELETE FROM users WHERE id = ?').bind(user.id),
  ]);

  await destroyCurrentSession(c);
  return c.json({ ok: true, data: { deleted: true } });
});

export default userRoutes;
