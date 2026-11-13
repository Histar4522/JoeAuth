import { Hono } from 'hono';
import type { AppEnv, UserRow } from '../types';
import {
  hashPassword,
  nowSec,
  randomBase64Url,
  sha256Hex,
  verifyPassword,
  verifyTotpCode,
} from '../lib/crypto';
import {
  createSession,
  destroySession,
  getIpHash,
  getPepper,
  isEmailVerificationRequired,
  switchActiveSession,
} from '../lib/session';
import { evaluateRegistrationEmail, getActiveRules } from '../lib/rules';
import { verifyTurnstile } from '../lib/turnstile';
import { passwordResetEmailContent, sendEmail, verificationEmailContent } from '../lib/email';
import { writeAuditLog } from '../lib/audit';
import { requireCsrf } from '../middleware/auth';
import { rateLimitMiddleware } from '../middleware/rateLimit';

const authRoutes = new Hono<AppEnv>();

authRoutes.post('/register', rateLimitMiddleware('auth'), requireCsrf, async (c) => {
  const body = await c.req.json<{
    name?: string;
    email?: string;
    password?: string;
    turnstileToken?: string;
  }>().catch(() => ({} as Record<string, undefined>));

  const name = (body.name || '').trim();
  const email = (body.email || '').trim().toLowerCase();
  const password = body.password || '';

  const ts = await verifyTurnstile(body.turnstileToken, c.env.TURNSTILE_SECRET_KEY, c.req.header('cf-connecting-ip'));
  if (!ts.ok) {
    return c.json({ ok: false, error: { code: 'TURNSTILE_FAILED', message: ts.error } }, 400);
  }

  if (name.length < 1 || name.length > 80) {
    return c.json({ ok: false, error: { code: 'INVALID_NAME', message: 'Name must be 1 to 80 characters.' } }, 400);
  }
  if (password.length < 8 || password.length > 128) {
    return c.json(
      { ok: false, error: { code: 'WEAK_PASSWORD', message: 'Password must be 8 to 128 characters.' } },
      400
    );
  }

  const rules = await getActiveRules(c.env);
  const ruleEval = evaluateRegistrationEmail(email, rules);
  if (!ruleEval.allowed) {
    return c.json(
      { ok: false, error: { code: 'REGISTRATION_BLOCKED', message: ruleEval.reason } },
      403
    );
  }

  const existing = await c.env.DB.prepare('SELECT id FROM users WHERE email = ?').bind(email).first();
  if (existing) {
    return c.json(
      { ok: false, error: { code: 'EMAIL_EXISTS', message: 'An account with this email already exists.' } },
      409
    );
  }

  const requireVerify = await isEmailVerificationRequired(c.env);
  const userId = crypto.randomUUID();
  const now = nowSec();
  const passwordHash = await hashPassword(password, getPepper(c.env));

  await c.env.DB.prepare(
    `INSERT INTO users (id, email, name, password_hash, role, developer_status, status, email_verified, created_at, updated_at)
     VALUES (?, ?, ?, ?, 'user', 'none', 'active', ?, ?, ?)`
  )
    .bind(userId, email, name, passwordHash, requireVerify ? 0 : 1, now, now)
    .run();

  const ipHash = await getIpHash(c);
  await writeAuditLog(c.env.DB, {
    actorId: userId,
    action: 'user.register',
    targetType: 'user',
    targetId: userId,
    ipHash,
    metadata: { emailVerified: !requireVerify },
  });

  if (requireVerify) {
    const rawToken = randomBase64Url(32);
    const tokenHash = await sha256Hex(rawToken);
    await c.env.DB.prepare(
      'INSERT INTO verification_tokens (token_hash, user_id, purpose, expires_at, created_at) VALUES (?, ?, ?, ?, ?)'
    )
      .bind(tokenHash, userId, 'email_verify', now + 1800, now)
      .run();

    const origin = c.env.ISSUER_URL || new URL(c.req.url).origin;
    const verifyUrl = `${origin}/api/auth/verify-email?token=${encodeURIComponent(rawToken)}`;
    const content = verificationEmailContent(c.env.APP_NAME || 'JoeAuth', verifyUrl, 'verify');
    await sendEmail(c.env, { to: email, ...content });

    return c.json(
      {
        ok: true,
        data: {
          requiresEmailVerification: true,
          message: 'Account created! Please check your email to verify your address before signing in.',
        },
      },
      201
    );
  }

  await createSession(c, { userId });
  return c.json(
    {
      ok: true,
      data: {
        requiresEmailVerification: false,
        user: { id: userId, email, name, role: 'user', developer_status: 'none' },
      },
    },
    201
  );
});

authRoutes.post('/login', rateLimitMiddleware('auth'), requireCsrf, async (c) => {
  const body = await c.req.json<{
    email?: string;
    password?: string;
    totpCode?: string;
    turnstileToken?: string;
  }>().catch(() => ({} as Record<string, undefined>));

  const email = (body.email || '').trim().toLowerCase();
  const password = body.password || '';

  const ts = await verifyTurnstile(body.turnstileToken, c.env.TURNSTILE_SECRET_KEY, c.req.header('cf-connecting-ip'));
  if (!ts.ok) {
    return c.json({ ok: false, error: { code: 'TURNSTILE_FAILED', message: ts.error } }, 400);
  }

  const user = await c.env.DB.prepare('SELECT * FROM users WHERE email = ?').bind(email).first<UserRow>();
  const ipHash = await getIpHash(c);

  if (!user || !(await verifyPassword(password, user.password_hash, getPepper(c.env)))) {
    await writeAuditLog(c.env.DB, {
      actorId: user?.id ?? null,
      action: 'user.login_failed',
      ipHash,
      metadata: { email },
    });
    return c.json({ ok: false, error: { code: 'INVALID_CREDENTIALS', message: 'Invalid email or password.' } }, 401);
  }

  if (user.status !== 'active') {
    return c.json(
      { ok: false, error: { code: 'ACCOUNT_SUSPENDED', message: 'This account is suspended or deleted.' } },
      403
    );
  }

  const requireVerify = await isEmailVerificationRequired(c.env);
  if (requireVerify && user.email_verified !== 1) {
    return c.json(
      {
        ok: false,
        error: {
          code: 'EMAIL_NOT_VERIFIED',
          message: 'Please verify your email address before signing in.',
        },
      },
      403
    );
  }

  if (user.totp_enabled === 1 && user.totp_secret) {
    if (!body.totpCode) {
      return c.json(
        { ok: false, error: { code: 'TOTP_REQUIRED', message: 'Two-factor authentication code required.' } },
        401
      );
    }
    const validTotp = await verifyTotpCode(user.totp_secret, body.totpCode);
    if (!validTotp) {
      return c.json(
        { ok: false, error: { code: 'TOTP_INVALID', message: 'Invalid 2FA authenticator code.' } },
        401
      );
    }
  }

  await createSession(c, { userId: user.id });
  await writeAuditLog(c.env.DB, {
    actorId: user.id,
    action: 'user.login',
    targetType: 'user',
    targetId: user.id,
    ipHash,
  });

  return c.json({
    ok: true,
    data: {
      user: {
        id: user.id,
        email: user.email,
        name: user.name,
        role: user.role,
        developer_status: user.developer_status,
      },
    },
  });
});

authRoutes.get('/accounts', (c) => {
  const auth = c.get('auth');
  const accounts = (auth?.accounts || []).map((a) => ({
    sessionId: a.sessionId,
    isActive: a.sessionId === auth?.sessionId,
    isSuperuser: a.isSuperuser,
    user: a.user
      ? {
          id: a.user.id,
          email: a.user.email,
          name: a.user.name,
          role: a.user.role,
          developer_status: a.user.developer_status,
        }
      : null,
  }));
  return c.json({ ok: true, data: { accounts } });
});

authRoutes.post('/switch', requireCsrf, async (c) => {
  const body = await c.req.json<{ sessionId?: string }>().catch(() => ({} as Record<string, undefined>));
  const sessionId = (body.sessionId || '').trim();
  if (!sessionId) {
    return c.json({ ok: false, error: { code: 'MISSING_SESSION_ID', message: 'sessionId is required.' } }, 400);
  }

  const ok = await switchActiveSession(c, sessionId);
  if (!ok) {
    return c.json(
      { ok: false, error: { code: 'SESSION_NOT_FOUND', message: 'Account session is not available in this browser.' } },
      403
    );
  }

  const updated = c.get('auth')!;
  return c.json({
    ok: true,
    data: {
      activeSessionId: updated.sessionId,
      isSuperuser: updated.isSuperuser,
      user: updated.user
        ? {
            id: updated.user.id,
            email: updated.user.email,
            name: updated.user.name,
            role: updated.user.role,
          }
        : null,
    },
  });
});

authRoutes.post('/logout', requireCsrf, async (c) => {
  const body = await c.req.json<{ sessionId?: string; all?: boolean }>().catch(() => ({} as { sessionId?: string; all?: boolean }));
  await destroySession(c, { sessionId: body.sessionId, all: body.all === true });
  return c.json({ ok: true, data: { loggedOut: true } });
});

authRoutes.get('/verify-email', async (c) => {
  const token = c.req.query('token') || '';
  const wantsJson = (c.req.header('accept') || '').includes('application/json');
  if (!token) {
    return wantsJson
      ? c.json({ ok: false, error: { code: 'MISSING_TOKEN', message: 'Verification token missing.' } }, 400)
      : c.html('<h1>Invalid Verification Link</h1><p>Missing token.</p><a href="/login">Back to login</a>', 400);
  }

  const tokenHash = await sha256Hex(token);
  const now = nowSec();
  const row = await c.env.DB.prepare(
    "SELECT * FROM verification_tokens WHERE token_hash = ? AND purpose IN ('email_verify', 'email_change') AND expires_at > ?"
  )
    .bind(tokenHash, now)
    .first<{ token_hash: string; user_id: string; purpose: string; target_value: string | null }>();

  if (!row) {
    return wantsJson
      ? c.json({ ok: false, error: { code: 'INVALID_TOKEN', message: 'Verification link expired or invalid.' } }, 400)
      : c.html('<h1>Verification Failed</h1><p>This link is invalid or has expired.</p><a href="/login">Sign in</a>', 400);
  }

  if (row.purpose === 'email_change' && row.target_value) {
    const taken = await c.env.DB.prepare('SELECT id FROM users WHERE email = ? AND id != ?')
      .bind(row.target_value, row.user_id)
      .first();
    if (taken) {
      return c.html('<h1>Email Already In Use</h1><a href="/account">Back to account</a>', 409);
    }
    await c.env.DB.prepare('UPDATE users SET email = ?, email_verified = 1, updated_at = ? WHERE id = ?')
      .bind(row.target_value, now, row.user_id)
      .run();
  } else {
    await c.env.DB.prepare('UPDATE users SET email_verified = 1, updated_at = ? WHERE id = ?')
      .bind(now, row.user_id)
      .run();
  }

  await c.env.DB.prepare('DELETE FROM verification_tokens WHERE token_hash = ?').bind(tokenHash).run();
  await writeAuditLog(c.env.DB, {
    actorId: row.user_id,
    action: row.purpose === 'email_change' ? 'user.email_changed' : 'user.email_verified',
    targetType: 'user',
    targetId: row.user_id,
  });

  if (wantsJson) {
    return c.json({ ok: true, data: { verified: true } });
  }
  return c.redirect('/login?verified=1');
});

authRoutes.post('/resend-verification', rateLimitMiddleware('auth'), requireCsrf, async (c) => {
  const body = await c.req.json<{ email?: string }>().catch(() => ({} as Record<string, undefined>));
  const email = (body.email || c.get('auth')?.user?.email || '').trim().toLowerCase();

  if (email) {
    const user = await c.env.DB.prepare('SELECT id, email, email_verified, status FROM users WHERE email = ?')
      .bind(email)
      .first<Pick<UserRow, 'id' | 'email' | 'email_verified' | 'status'>>();
    if (user && user.status === 'active' && user.email_verified === 0) {
      const now = nowSec();
      const rawToken = randomBase64Url(32);
      const tokenHash = await sha256Hex(rawToken);
      await c.env.DB.prepare(
        'INSERT INTO verification_tokens (token_hash, user_id, purpose, expires_at, created_at) VALUES (?, ?, ?, ?, ?)'
      )
        .bind(tokenHash, user.id, 'email_verify', now + 1800, now)
        .run();

      const origin = c.env.ISSUER_URL || new URL(c.req.url).origin;
      const verifyUrl = `${origin}/api/auth/verify-email?token=${encodeURIComponent(rawToken)}`;
      const content = verificationEmailContent(c.env.APP_NAME || 'JoeAuth', verifyUrl, 'verify');
      await sendEmail(c.env, { to: user.email, ...content });
    }
  }

  return c.json({
    ok: true,
    data: { message: 'If an unverified account exists for that email, a verification link has been sent.' },
  });
});

authRoutes.post('/forgot-password', rateLimitMiddleware('auth'), requireCsrf, async (c) => {
  const body = await c.req.json<{ email?: string; turnstileToken?: string }>().catch(() => ({} as Record<string, undefined>));
  const ts = await verifyTurnstile(body.turnstileToken, c.env.TURNSTILE_SECRET_KEY, c.req.header('cf-connecting-ip'));
  if (!ts.ok) {
    return c.json({ ok: false, error: { code: 'TURNSTILE_FAILED', message: ts.error } }, 400);
  }

  const email = (body.email || '').trim().toLowerCase();
  if (email) {
    const user = await c.env.DB.prepare("SELECT id, email FROM users WHERE email = ? AND status = 'active'")
      .bind(email)
      .first<{ id: string; email: string }>();
    if (user) {
      const now = nowSec();
      const rawToken = randomBase64Url(32);
      const tokenHash = await sha256Hex(rawToken);
      await c.env.DB.prepare(
        'INSERT INTO verification_tokens (token_hash, user_id, purpose, expires_at, created_at) VALUES (?, ?, ?, ?, ?)'
      )
        .bind(tokenHash, user.id, 'password_reset', now + 1200, now)
        .run();

      const origin = c.env.ISSUER_URL || new URL(c.req.url).origin;
      const resetUrl = `${origin}/reset-password?token=${encodeURIComponent(rawToken)}`;
      const content = passwordResetEmailContent(c.env.APP_NAME || 'JoeAuth', resetUrl);
      await sendEmail(c.env, { to: user.email, ...content });
    }
  }

  return c.json({
    ok: true,
    data: { message: 'If an account matches that email, a password reset link has been sent.' },
  });
});

authRoutes.post('/reset-password', rateLimitMiddleware('auth'), requireCsrf, async (c) => {
  const body = await c.req.json<{ token?: string; newPassword?: string }>().catch(() => ({} as Record<string, undefined>));
  const token = (body.token || '').trim();
  const newPassword = body.newPassword || '';

  if (!token || newPassword.length < 8 || newPassword.length > 128) {
    return c.json(
      { ok: false, error: { code: 'INVALID_INPUT', message: 'Valid token and password (8-128 chars) are required.' } },
      400
    );
  }

  const tokenHash = await sha256Hex(token);
  const now = nowSec();
  const row = await c.env.DB.prepare(
    "SELECT token_hash, user_id FROM verification_tokens WHERE token_hash = ? AND purpose = 'password_reset' AND expires_at > ?"
  )
    .bind(tokenHash, now)
    .first<{ token_hash: string; user_id: string }>();

  if (!row) {
    return c.json({ ok: false, error: { code: 'INVALID_TOKEN', message: 'Reset token invalid or expired.' } }, 400);
  }

  const newHash = await hashPassword(newPassword, getPepper(c.env));
  await c.env.DB.batch([
    c.env.DB.prepare('UPDATE users SET password_hash = ?, updated_at = ? WHERE id = ?').bind(newHash, now, row.user_id),
    c.env.DB.prepare('DELETE FROM verification_tokens WHERE token_hash = ?').bind(tokenHash),
    c.env.DB.prepare('DELETE FROM sessions WHERE user_id = ?').bind(row.user_id),
    c.env.DB.prepare('UPDATE refresh_tokens SET revoked = 1 WHERE user_id = ?').bind(row.user_id),
  ]);

  await writeAuditLog(c.env.DB, {
    actorId: row.user_id,
    action: 'user.password_reset',
    targetType: 'user',
    targetId: row.user_id,
    ipHash: await getIpHash(c),
  });

  return c.json({ ok: true, data: { message: 'Password updated. Please sign in with your new password.' } });
});

export default authRoutes;
