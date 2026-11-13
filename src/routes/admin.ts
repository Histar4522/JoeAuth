import { Hono } from 'hono';
import type { AppEnv, DeveloperApplicationRow, RegistrationRuleRow, UserRow } from '../types';
import { hashPassword, nowSec, verifySuperuserPassword } from '../lib/crypto';
import { createSession, deleteUserAccountData, getIpHash, getPepper, getSystemSetting } from '../lib/session';
import {
  REGISTRATION_RULE_TEMPLATES,
  evaluateRegistrationEmail,
  invalidateRulesCache,
  validateRulePattern,
} from '../lib/rules';
import { verifyTurnstile } from '../lib/turnstile';
import { getAppLogoUrl, getUserAvatarUrl } from '../lib/images';
import { writeAuditLog } from '../lib/audit';
import { requireAdmin, requireCsrf, requireSuperuser } from '../middleware/auth';
import { rateLimitMiddleware } from '../middleware/rateLimit';

const adminRoutes = new Hono<AppEnv>();

// Superuser login via SHA-256 secret in env.SUPERUSER_PASSWORD_HASH
adminRoutes.post('/superuser/login', rateLimitMiddleware('auth'), requireCsrf, async (c) => {
  const body = await c.req.json<{ password?: string; turnstileToken?: string }>().catch(() => ({} as Record<string, undefined>));

  const ts = await verifyTurnstile(body.turnstileToken, c.env.TURNSTILE_SECRET_KEY, c.req.header('cf-connecting-ip'));
  if (!ts.ok) {
    return c.json({ ok: false, error: { code: 'TURNSTILE_FAILED', message: ts.error } }, 400);
  }

  const valid = await verifySuperuserPassword(body.password || '', c.env.SUPERUSER_PASSWORD_HASH);
  const ipHash = await getIpHash(c);

  if (!valid) {
    await writeAuditLog(c.env.DB, { actorId: null, action: 'admin.superuser.login_failed', ipHash });
    return c.json({ ok: false, error: { code: 'INVALID_CREDENTIALS', message: 'Invalid superuser password.' } }, 401);
  }

  const session = await createSession(c, { userId: 'superuser', isSuperuser: true });
  await writeAuditLog(c.env.DB, { actorId: 'superuser', action: 'admin.superuser.login', ipHash });

  return c.json({ ok: true, data: { isSuperuser: true, slot: session.slot, userCount: session.userCount } });
});

// All endpoints below require either Superuser OR an Admin user (role = 'admin')
adminRoutes.use('*', requireAdmin);

function actorIdOf(c: { get: (k: 'auth') => AppEnv['Variables']['auth'] }): string {
  const auth = c.get('auth')!;
  return auth.isSuperuser ? 'superuser' : auth.user!.id;
}

adminRoutes.get('/overview', async (c) => {
  const now = nowSec();
  const [
    usersCount,
    pendingDevs,
    appsCount,
    rulesCount,
    requireVerify,
    recentLogs,
    auditCounts,
    expiredSessions,
    expiredTokens,
    staleCodes,
    staleRefresh,
  ] = await Promise.all([
    c.env.DB.prepare("SELECT COUNT(*) as count FROM users WHERE status != 'deleted'").first<{ count: number }>(),
    c.env.DB.prepare("SELECT COUNT(*) as count FROM developer_applications WHERE status = 'pending'").first<{ count: number }>(),
    c.env.DB.prepare('SELECT COUNT(*) as count FROM apps').first<{ count: number }>(),
    c.env.DB.prepare('SELECT COUNT(*) as count FROM registration_rules WHERE is_active = 1').first<{ count: number }>(),
    getSystemSetting(c.env.DB, 'require_email_verification', c.env.REQUIRE_EMAIL_VERIFICATION || 'true'),
    c.env.DB.prepare('SELECT * FROM audit_logs ORDER BY created_at DESC LIMIT 25').all(),
    c.env.DB.prepare(
      `SELECT
         COUNT(*) as total,
         SUM(CASE WHEN action LIKE '%login_failed%' THEN 1 ELSE 0 END) as auth_failures,
         SUM(CASE WHEN action LIKE 'user.%' THEN 1 ELSE 0 END) as user_logs,
         SUM(CASE WHEN action LIKE 'dev.%' THEN 1 ELSE 0 END) as dev_logs,
         SUM(CASE WHEN action LIKE 'oauth.%' THEN 1 ELSE 0 END) as oauth_logs,
         SUM(CASE WHEN action LIKE 'admin.%' OR action LIKE 'superuser.%' THEN 1 ELSE 0 END) as admin_logs
       FROM audit_logs`
    ).first<{
      total: number;
      auth_failures: number | null;
      user_logs: number | null;
      dev_logs: number | null;
      oauth_logs: number | null;
      admin_logs: number | null;
    }>(),
    c.env.DB.prepare('SELECT COUNT(*) as count FROM sessions WHERE expires_at < ?').bind(now).first<{ count: number }>(),
    c.env.DB.prepare('SELECT COUNT(*) as count FROM verification_tokens WHERE expires_at < ?')
      .bind(now)
      .first<{ count: number }>(),
    c.env.DB.prepare('SELECT COUNT(*) as count FROM oauth_codes WHERE expires_at < ? OR used = 1')
      .bind(now)
      .first<{ count: number }>(),
    c.env.DB.prepare('SELECT COUNT(*) as count FROM refresh_tokens WHERE revoked = 1 OR expires_at < ?')
      .bind(now)
      .first<{ count: number }>(),
  ]);

  return c.json({
    ok: true,
    data: {
      stats: {
        users: usersCount?.count ?? 0,
        pendingDeveloperApplications: pendingDevs?.count ?? 0,
        apps: appsCount?.count ?? 0,
        activeRules: rulesCount?.count ?? 0,
      },
      settings: {
        require_email_verification: requireVerify === 'true',
      },
      maintenance: {
        auditLogsTotal: auditCounts?.total ?? 0,
        authFailureLogs: auditCounts?.auth_failures ?? 0,
        userLogs: auditCounts?.user_logs ?? 0,
        devLogs: auditCounts?.dev_logs ?? 0,
        oauthLogs: auditCounts?.oauth_logs ?? 0,
        adminLogs: auditCounts?.admin_logs ?? 0,
        expiredSessions: expiredSessions?.count ?? 0,
        expiredVerificationTokens: expiredTokens?.count ?? 0,
        staleOAuthCodes: staleCodes?.count ?? 0,
        staleRefreshTokens: staleRefresh?.count ?? 0,
      },
      recentAuditLogs: recentLogs.results || [],
    },
  });
});

adminRoutes.get('/users', async (c) => {
  const q = (c.req.query('q') || '').trim();
  const status = (c.req.query('status') || 'all').trim();
  const role = (c.req.query('role') || 'all').trim();
  const developerStatus = (c.req.query('developerStatus') || 'all').trim();
  const like = `%${q}%`;

  const clauses: string[] = ["(? = '' OR email LIKE ? OR name LIKE ?)"];
  const params: (string | number)[] = [q, like, like];

  if (status === 'active' || status === 'suspended') {
    clauses.push('status = ?');
    params.push(status);
  }
  if (role === 'user' || role === 'admin') {
    clauses.push('role = ?');
    params.push(role);
  }
  if (developerStatus === 'none' || developerStatus === 'pending' || developerStatus === 'approved' || developerStatus === 'revoked') {
    clauses.push('developer_status = ?');
    params.push(developerStatus);
  }

  const { results } = await c.env.DB.prepare(
    `SELECT id, email, name, role, developer_status, status, email_verified, totp_enabled, avatar_key, avatar_version, avatar_color, created_at
     FROM users
     WHERE ${clauses.join(' AND ')}
     ORDER BY created_at DESC
     LIMIT 100`
  )
    .bind(...params)
    .all<
      Pick<
        UserRow,
        | 'id'
        | 'email'
        | 'name'
        | 'role'
        | 'developer_status'
        | 'status'
        | 'email_verified'
        | 'totp_enabled'
        | 'avatar_key'
        | 'avatar_version'
        | 'avatar_color'
        | 'created_at'
      >
    >();

  return c.json({
    ok: true,
    data: (results || []).map(({ avatar_key, avatar_version, ...row }) => ({
      ...row,
      has_custom_avatar: Boolean(avatar_key),
      avatar_url: getUserAvatarUrl('', row.id, avatar_version),
    })),
  });
});

adminRoutes.patch('/users/:id/status', requireCsrf, async (c) => {
  const auth = c.get('auth')!;
  const targetId = c.req.param('id');
  const body = await c.req.json<{ status?: 'active' | 'suspended'; emailVerified?: boolean }>().catch(() => ({} as Record<string, unknown>));

  const target = await c.env.DB.prepare('SELECT id, role, status, email_verified FROM users WHERE id = ?')
    .bind(targetId)
    .first<Pick<UserRow, 'id' | 'role' | 'status' | 'email_verified'>>();
  if (!target) {
    return c.json({ ok: false, error: { code: 'NOT_FOUND', message: 'User not found.' } }, 404);
  }

  if (auth.user && targetId === auth.user.id && body.status === 'suspended') {
    return c.json(
      { ok: false, error: { code: 'SELF_ACTION_FORBIDDEN', message: 'You cannot suspend your own active account.' } },
      400
    );
  }
  if (!auth.isSuperuser && target.role === 'admin' && body.status === 'suspended') {
    return c.json(
      { ok: false, error: { code: 'FORBIDDEN', message: 'Only the Superuser can suspend an admin account.' } },
      403
    );
  }

  const nextStatus = body.status === 'active' || body.status === 'suspended' ? body.status : target.status;
  const nextVerified = typeof body.emailVerified === 'boolean' ? (body.emailVerified ? 1 : 0) : target.email_verified;

  const stmts: D1PreparedStatement[] = [
    c.env.DB.prepare('UPDATE users SET status = ?, email_verified = ?, updated_at = ? WHERE id = ?').bind(
      nextStatus,
      nextVerified,
      nowSec(),
      targetId
    ),
  ];
  if (nextStatus === 'suspended') {
    stmts.push(c.env.DB.prepare('DELETE FROM sessions WHERE user_id = ?').bind(targetId));
    stmts.push(c.env.DB.prepare('UPDATE refresh_tokens SET revoked = 1 WHERE user_id = ?').bind(targetId));
  }
  await c.env.DB.batch(stmts);

  await writeAuditLog(c.env.DB, {
    actorId: actorIdOf(c),
    action: 'admin.user.status',
    targetType: 'user',
    targetId,
    ipHash: await getIpHash(c),
    metadata: { status: nextStatus, emailVerified: nextVerified === 1 },
  });

  return c.json({ ok: true, data: { status: nextStatus, email_verified: nextVerified === 1 } });
});

// SUPERUSER ONLY: Assign or revoke Admin role
adminRoutes.patch('/users/:id/role', requireSuperuser, requireCsrf, async (c) => {
  const targetId = c.req.param('id');
  const body = await c.req.json<{ role?: 'user' | 'admin' }>().catch(() => ({} as Record<string, undefined>));
  if (body.role !== 'user' && body.role !== 'admin') {
    return c.json({ ok: false, error: { code: 'INVALID_ROLE', message: "Role must be 'user' or 'admin'." } }, 400);
  }

  const res = await c.env.DB.prepare('UPDATE users SET role = ?, updated_at = ? WHERE id = ?')
    .bind(body.role, nowSec(), targetId)
    .run();
  if (!res.meta.changes) {
    return c.json({ ok: false, error: { code: 'NOT_FOUND', message: 'User not found.' } }, 404);
  }

  await writeAuditLog(c.env.DB, {
    actorId: 'superuser',
    action: 'superuser.user.role',
    targetType: 'user',
    targetId,
    ipHash: await getIpHash(c),
    metadata: { role: body.role },
  });

  return c.json({ ok: true, data: { role: body.role } });
});

adminRoutes.patch('/users/:id/developer-status', requireCsrf, async (c) => {
  const targetId = c.req.param('id');
  const body = await c.req.json<{ developerStatus?: 'approved' | 'revoked' | 'none' }>().catch(() => ({} as Record<string, undefined>));
  if (body.developerStatus !== 'approved' && body.developerStatus !== 'revoked' && body.developerStatus !== 'none') {
    return c.json({ ok: false, error: { code: 'INVALID_STATUS', message: 'Invalid developer status.' } }, 400);
  }

  const res = await c.env.DB.prepare("UPDATE users SET developer_status = ?, updated_at = ? WHERE id = ? AND status != 'deleted'")
    .bind(body.developerStatus, nowSec(), targetId)
    .run();
  if (!res.meta.changes) {
    return c.json({ ok: false, error: { code: 'NOT_FOUND', message: 'User not found.' } }, 404);
  }

  await writeAuditLog(c.env.DB, {
    actorId: actorIdOf(c),
    action: 'admin.user.developer_status',
    targetType: 'user',
    targetId,
    ipHash: await getIpHash(c),
    metadata: { developerStatus: body.developerStatus },
  });

  return c.json({ ok: true, data: { developer_status: body.developerStatus } });
});

adminRoutes.post('/users/:id/password', requireCsrf, async (c) => {
  const auth = c.get('auth')!;
  const targetId = c.req.param('id');
  const body = await c.req.json<{ newPassword?: string }>().catch(() => ({} as Record<string, undefined>));
  const newPassword = typeof body.newPassword === 'string' ? body.newPassword : '';
  if (newPassword.length < 8 || newPassword.length > 128) {
    return c.json(
      { ok: false, error: { code: 'WEAK_PASSWORD', message: 'Password must be 8 to 128 characters.' } },
      400
    );
  }

  const target = await c.env.DB.prepare('SELECT id, role FROM users WHERE id = ?')
    .bind(targetId)
    .first<Pick<UserRow, 'id' | 'role'>>();
  if (!target) {
    return c.json({ ok: false, error: { code: 'NOT_FOUND', message: 'User not found.' } }, 404);
  }
  if (!auth.isSuperuser && target.role === 'admin' && target.id !== auth.user?.id) {
    return c.json(
      { ok: false, error: { code: 'FORBIDDEN', message: 'Only the Superuser can set another admin account password.' } },
      403
    );
  }

  const newHash = await hashPassword(newPassword, getPepper(c.env));
  const sessionStmt =
    auth.user && auth.user.id === targetId
      ? c.env.DB.prepare('DELETE FROM sessions WHERE user_id = ? AND id != ?').bind(targetId, auth.sessionId)
      : c.env.DB.prepare('DELETE FROM sessions WHERE user_id = ?').bind(targetId);

  await c.env.DB.batch([
    c.env.DB.prepare('UPDATE users SET password_hash = ?, updated_at = ? WHERE id = ?').bind(newHash, nowSec(), targetId),
    c.env.DB.prepare("DELETE FROM verification_tokens WHERE user_id = ? AND purpose = 'password_reset'").bind(targetId),
    c.env.DB.prepare('UPDATE refresh_tokens SET revoked = 1 WHERE user_id = ?').bind(targetId),
    sessionStmt,
  ]);

  await writeAuditLog(c.env.DB, {
    actorId: actorIdOf(c),
    action: 'admin.user.set_password',
    targetType: 'user',
    targetId,
    ipHash: await getIpHash(c),
  });

  return c.json({ ok: true, data: { updated: true } });
});

adminRoutes.post('/users/:id/revoke-sessions', requireCsrf, async (c) => {
  const auth = c.get('auth')!;
  const targetId = c.req.param('id');
  const target = await c.env.DB.prepare('SELECT id, role FROM users WHERE id = ?')
    .bind(targetId)
    .first<Pick<UserRow, 'id' | 'role'>>();
  if (!target) {
    return c.json({ ok: false, error: { code: 'NOT_FOUND', message: 'User not found.' } }, 404);
  }
  if (!auth.isSuperuser && target.role === 'admin' && target.id !== auth.user?.id) {
    return c.json(
      { ok: false, error: { code: 'FORBIDDEN', message: 'Only the Superuser can revoke sessions for another admin account.' } },
      403
    );
  }

  const sessionStmt =
    auth.user && auth.user.id === targetId
      ? c.env.DB.prepare('DELETE FROM sessions WHERE user_id = ? AND id != ?').bind(targetId, auth.sessionId)
      : c.env.DB.prepare('DELETE FROM sessions WHERE user_id = ?').bind(targetId);

  await c.env.DB.batch([
    sessionStmt,
    c.env.DB.prepare('UPDATE refresh_tokens SET revoked = 1 WHERE user_id = ?').bind(targetId),
  ]);

  await writeAuditLog(c.env.DB, {
    actorId: actorIdOf(c),
    action: 'admin.user.revoke_sessions',
    targetType: 'user',
    targetId,
    ipHash: await getIpHash(c),
  });

  return c.json({ ok: true, data: { revoked: true } });
});

adminRoutes.delete('/users/:id/2fa', requireCsrf, async (c) => {
  const auth = c.get('auth')!;
  const targetId = c.req.param('id');
  const target = await c.env.DB.prepare('SELECT id, role FROM users WHERE id = ?')
    .bind(targetId)
    .first<Pick<UserRow, 'id' | 'role'>>();
  if (!target) {
    return c.json({ ok: false, error: { code: 'NOT_FOUND', message: 'User not found.' } }, 404);
  }
  if (!auth.isSuperuser && target.role === 'admin' && target.id !== auth.user?.id) {
    return c.json(
      { ok: false, error: { code: 'FORBIDDEN', message: 'Only the Superuser can disable 2FA for another admin account.' } },
      403
    );
  }

  await c.env.DB.prepare('UPDATE users SET totp_enabled = 0, totp_secret = NULL, updated_at = ? WHERE id = ?')
    .bind(nowSec(), targetId)
    .run();

  await writeAuditLog(c.env.DB, {
    actorId: actorIdOf(c),
    action: 'admin.user.disable_2fa',
    targetType: 'user',
    targetId,
    ipHash: await getIpHash(c),
  });

  return c.json({ ok: true, data: { totpEnabled: false } });
});

adminRoutes.delete('/users/:id', requireCsrf, async (c) => {
  const auth = c.get('auth')!;
  const targetId = c.req.param('id');

  if (auth.user && targetId === auth.user.id) {
    return c.json(
      { ok: false, error: { code: 'SELF_ACTION_FORBIDDEN', message: 'You cannot delete your own active account.' } },
      400
    );
  }

  const target = await c.env.DB.prepare('SELECT id, email, role, avatar_key FROM users WHERE id = ?')
    .bind(targetId)
    .first<Pick<UserRow, 'id' | 'email' | 'role' | 'avatar_key'>>();
  if (!target) {
    return c.json({ ok: false, error: { code: 'NOT_FOUND', message: 'User not found.' } }, 404);
  }
  if (!auth.isSuperuser && target.role === 'admin') {
    return c.json(
      { ok: false, error: { code: 'FORBIDDEN', message: 'Only the Superuser can delete an admin account.' } },
      403
    );
  }

  await deleteUserAccountData(c.env.DB, c.env.MEDIA_BUCKET, target.id, target.avatar_key);

  await writeAuditLog(c.env.DB, {
    actorId: actorIdOf(c),
    action: 'admin.user.delete',
    targetType: 'user',
    targetId: target.id,
    ipHash: await getIpHash(c),
    metadata: { email: target.email },
  });

  return c.json({ ok: true, data: { deleted: true } });
});

// --- Developer Access Applications Review ---

adminRoutes.get('/dev-applications', async (c) => {
  const status = c.req.query('status') || 'all';
  const query =
    status === 'all'
      ? `SELECT da.*, u.email as user_email, u.name as user_name
         FROM developer_applications da
         JOIN users u ON u.id = da.user_id
         ORDER BY da.created_at DESC LIMIT 100`
      : `SELECT da.*, u.email as user_email, u.name as user_name
         FROM developer_applications da
         JOIN users u ON u.id = da.user_id
         WHERE da.status = ?
         ORDER BY da.created_at DESC LIMIT 100`;

  const stmt = status === 'all' ? c.env.DB.prepare(query) : c.env.DB.prepare(query).bind(status);
  const { results } = await stmt.all<DeveloperApplicationRow & { user_email: string; user_name: string }>();

  return c.json({ ok: true, data: results || [] });
});

adminRoutes.patch('/dev-applications/:id', requireCsrf, async (c) => {
  const appId = c.req.param('id');
  const body = await c.req.json<{ decision?: 'approved' | 'rejected'; reviewNote?: string }>().catch(() => ({} as Record<string, undefined>));

  if (body.decision !== 'approved' && body.decision !== 'rejected') {
    return c.json({ ok: false, error: { code: 'INVALID_DECISION', message: "Decision must be 'approved' or 'rejected'." } }, 400);
  }

  const app = await c.env.DB.prepare('SELECT * FROM developer_applications WHERE id = ?')
    .bind(appId)
    .first<DeveloperApplicationRow>();
  if (!app) {
    return c.json({ ok: false, error: { code: 'NOT_FOUND', message: 'Developer application not found.' } }, 404);
  }

  const now = nowSec();
  const actor = actorIdOf(c);
  const reviewNote = (body.reviewNote || '').trim().slice(0, 300);

  await c.env.DB.batch([
    c.env.DB.prepare(
      'UPDATE developer_applications SET status = ?, review_note = ?, reviewed_by = ?, reviewed_at = ? WHERE id = ?'
    ).bind(body.decision, reviewNote, actor, now, appId),
    c.env.DB.prepare("UPDATE users SET developer_status = ?, updated_at = ? WHERE id = ? AND status = 'active'").bind(
      body.decision,
      now,
      app.user_id
    ),
  ]);

  await writeAuditLog(c.env.DB, {
    actorId: actor,
    action: `admin.dev_application.${body.decision}`,
    targetType: 'developer_application',
    targetId: appId,
    ipHash: await getIpHash(c),
    metadata: { userId: app.user_id, serviceName: app.service_name },
  });

  return c.json({ ok: true, data: { status: body.decision } });
});

// --- OAuth Apps Moderation ---

adminRoutes.get('/apps', async (c) => {
  const { results } = await c.env.DB.prepare(
    `SELECT a.id, a.name, a.description, a.privilege_description, a.homepage_url, a.client_id, a.logo_key, a.logo_version, a.is_first_party, a.status, a.created_at, u.email as owner_email
     FROM apps a JOIN users u ON u.id = a.owner_user_id
     ORDER BY a.created_at DESC LIMIT 100`
  ).all<{
    id: string;
    name: string;
    description: string;
    privilege_description: string;
    homepage_url: string;
    client_id: string;
    logo_key: string | null;
    logo_version: number;
    is_first_party: number;
    status: string;
    created_at: number;
    owner_email: string;
  }>();

  return c.json({
    ok: true,
    data: (results || []).map(({ logo_key, logo_version, ...row }) => ({
      ...row,
      has_custom_logo: Boolean(logo_key),
      logo_url: logo_key ? getAppLogoUrl('', row.id, logo_version) : null,
    })),
  });
});

adminRoutes.patch('/apps/:id', requireCsrf, async (c) => {
  const appId = c.req.param('id');
  const body = await c.req.json<{ status?: 'approved' | 'suspended'; isFirstParty?: boolean }>().catch(() => ({} as Record<string, unknown>));

  const existing = await c.env.DB.prepare('SELECT id, status, is_first_party FROM apps WHERE id = ?')
    .bind(appId)
    .first<{ id: string; status: string; is_first_party: number }>();
  if (!existing) {
    return c.json({ ok: false, error: { code: 'NOT_FOUND', message: 'Application not found.' } }, 404);
  }

  const nextStatus = body.status === 'approved' || body.status === 'suspended' ? body.status : existing.status;
  const nextFirstParty = typeof body.isFirstParty === 'boolean' ? (body.isFirstParty ? 1 : 0) : existing.is_first_party;

  await c.env.DB.prepare('UPDATE apps SET status = ?, is_first_party = ?, updated_at = ? WHERE id = ?')
    .bind(nextStatus, nextFirstParty, nowSec(), appId)
    .run();

  await writeAuditLog(c.env.DB, {
    actorId: actorIdOf(c),
    action: 'admin.app.update',
    targetType: 'app',
    targetId: appId,
    ipHash: await getIpHash(c),
    metadata: { status: nextStatus, isFirstParty: nextFirstParty === 1 },
  });

  return c.json({ ok: true, data: { status: nextStatus, is_first_party: nextFirstParty === 1 } });
});

adminRoutes.delete('/apps/:id', requireCsrf, async (c) => {
  const appId = c.req.param('id');
  const existing = await c.env.DB.prepare('SELECT id, name, logo_key FROM apps WHERE id = ?')
    .bind(appId)
    .first<{ id: string; name: string; logo_key: string | null }>();
  if (!existing) {
    return c.json({ ok: false, error: { code: 'NOT_FOUND', message: 'Application not found.' } }, 404);
  }

  if (existing.logo_key) {
    await c.env.MEDIA_BUCKET.delete(existing.logo_key).catch(() => {});
  }

  await c.env.DB.batch([
    c.env.DB.prepare('DELETE FROM oauth_codes WHERE app_id = ?').bind(appId),
    c.env.DB.prepare('DELETE FROM refresh_tokens WHERE app_id = ?').bind(appId),
    c.env.DB.prepare('DELETE FROM apps WHERE id = ?').bind(appId),
  ]);

  await writeAuditLog(c.env.DB, {
    actorId: actorIdOf(c),
    action: 'admin.app.delete',
    targetType: 'app',
    targetId: appId,
    ipHash: await getIpHash(c),
    metadata: { name: existing.name },
  });

  return c.json({ ok: true, data: { deleted: true } });
});

// --- Registration Email Regex Rules ---

adminRoutes.get('/rules', async (c) => {
  const { results } = await c.env.DB.prepare(
    'SELECT * FROM registration_rules ORDER BY priority ASC, created_at ASC'
  ).all<RegistrationRuleRow>();

  return c.json({
    ok: true,
    data: {
      defaultPolicy: 'deny',
      templates: REGISTRATION_RULE_TEMPLATES,
      rules: results || [],
    },
  });
});

adminRoutes.post('/rules', requireCsrf, async (c) => {
  const body = await c.req.json<{
    ruleType?: 'allow' | 'deny';
    pattern?: string;
    description?: string;
    priority?: number;
    isActive?: boolean;
  }>().catch(() => ({} as Record<string, unknown>));

  if (body.ruleType !== 'allow' && body.ruleType !== 'deny') {
    return c.json({ ok: false, error: { code: 'INVALID_TYPE', message: "ruleType must be 'allow' or 'deny'." } }, 400);
  }
  const pattern = typeof body.pattern === 'string' ? body.pattern.trim() : '';
  const check = validateRulePattern(pattern);
  if (!check.valid) {
    return c.json({ ok: false, error: { code: 'INVALID_REGEX', message: check.error } }, 400);
  }

  const priority = typeof body.priority === 'number' && Number.isFinite(body.priority) ? Math.trunc(body.priority) : 100;
  const description = typeof body.description === 'string' ? body.description.trim().slice(0, 200) : '';
  const isActive = body.isActive === false ? 0 : 1;
  const id = crypto.randomUUID();
  const actor = actorIdOf(c);

  await c.env.DB.prepare(
    'INSERT INTO registration_rules (id, rule_type, pattern, description, priority, is_active, created_by, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?)'
  )
    .bind(id, body.ruleType, pattern, description, priority, isActive, actor, nowSec())
    .run();

  await invalidateRulesCache(c.env);
  await writeAuditLog(c.env.DB, {
    actorId: actor,
    action: 'admin.rule.create',
    targetType: 'registration_rule',
    targetId: id,
    ipHash: await getIpHash(c),
    metadata: { ruleType: body.ruleType, pattern, priority },
  });

  return c.json({ ok: true, data: { id } }, 201);
});

adminRoutes.patch('/rules/:id', requireCsrf, async (c) => {
  const ruleId = c.req.param('id');
  const existing = await c.env.DB.prepare('SELECT * FROM registration_rules WHERE id = ?')
    .bind(ruleId)
    .first<RegistrationRuleRow>();
  if (!existing) {
    return c.json({ ok: false, error: { code: 'NOT_FOUND', message: 'Rule not found.' } }, 404);
  }

  const body = await c.req.json<{
    ruleType?: 'allow' | 'deny';
    pattern?: string;
    description?: string;
    priority?: number;
    isActive?: boolean;
  }>().catch(() => ({} as Record<string, unknown>));

  const ruleType = body.ruleType === 'allow' || body.ruleType === 'deny' ? body.ruleType : existing.rule_type;
  const pattern = typeof body.pattern === 'string' ? body.pattern.trim() : existing.pattern;
  const check = validateRulePattern(pattern);
  if (!check.valid) {
    return c.json({ ok: false, error: { code: 'INVALID_REGEX', message: check.error } }, 400);
  }
  const priority = typeof body.priority === 'number' && Number.isFinite(body.priority) ? Math.trunc(body.priority) : existing.priority;
  const description = typeof body.description === 'string' ? body.description.trim().slice(0, 200) : existing.description;
  const isActive = typeof body.isActive === 'boolean' ? (body.isActive ? 1 : 0) : existing.is_active;

  await c.env.DB.prepare(
    'UPDATE registration_rules SET rule_type = ?, pattern = ?, description = ?, priority = ?, is_active = ? WHERE id = ?'
  )
    .bind(ruleType, pattern, description, priority, isActive, ruleId)
    .run();

  await invalidateRulesCache(c.env);
  return c.json({ ok: true, data: { updated: true } });
});

adminRoutes.delete('/rules/:id', requireCsrf, async (c) => {
  const ruleId = c.req.param('id');
  const res = await c.env.DB.prepare('DELETE FROM registration_rules WHERE id = ?').bind(ruleId).run();
  if (!res.meta.changes) {
    return c.json({ ok: false, error: { code: 'NOT_FOUND', message: 'Rule not found.' } }, 404);
  }
  await invalidateRulesCache(c.env);
  await writeAuditLog(c.env.DB, {
    actorId: actorIdOf(c),
    action: 'admin.rule.delete',
    targetType: 'registration_rule',
    targetId: ruleId,
    ipHash: await getIpHash(c),
  });
  return c.json({ ok: true, data: { deleted: true } });
});

adminRoutes.post('/rules/test', async (c) => {
  const body = await c.req.json<{ email?: string }>().catch(() => ({} as Record<string, undefined>));
  const { results } = await c.env.DB.prepare(
    'SELECT * FROM registration_rules WHERE is_active = 1 ORDER BY priority ASC, created_at ASC'
  ).all<RegistrationRuleRow>();

  const result = evaluateRegistrationEmail(body.email || '', results || []);
  return c.json({ ok: true, data: result });
});

// SUPERUSER ONLY: System Settings
adminRoutes.patch('/settings', requireSuperuser, requireCsrf, async (c) => {
  const body = await c.req.json<{ requireEmailVerification?: boolean }>().catch(() => ({} as Record<string, unknown>));
  if (typeof body.requireEmailVerification === 'boolean') {
    await c.env.DB.prepare(
      'INSERT INTO system_settings (key, value, updated_at) VALUES (?, ?, ?) ON CONFLICT(key) DO UPDATE SET value = excluded.value, updated_at = excluded.updated_at'
    )
      .bind('require_email_verification', body.requireEmailVerification ? 'true' : 'false', nowSec())
      .run();
  }
  return c.json({ ok: true, data: { updated: true } });
});

function auditCategoryWhere(category: string, now: number): { sql: string; binds: (string | number)[] } | null {
  switch (category) {
    case 'all':
      return { sql: '1 = 1', binds: [] };
    case 'user':
      return { sql: "action LIKE 'user.%'", binds: [] };
    case 'auth_failures':
      return { sql: "action LIKE '%login_failed%'", binds: [] };
    case 'dev':
      return { sql: "action LIKE 'dev.%'", binds: [] };
    case 'oauth':
      return { sql: "action LIKE 'oauth.%'", binds: [] };
    case 'admin':
      return { sql: "(action LIKE 'admin.%' OR action LIKE 'superuser.%')", binds: [] };
    case 'older_than_30d':
      return { sql: 'created_at < ?', binds: [now - 30 * 24 * 60 * 60] };
    default:
      return null;
  }
}

adminRoutes.get('/audit-logs', async (c) => {
  const category = (c.req.query('category') || 'all').trim();
  const q = (c.req.query('q') || '').trim();
  const cat = auditCategoryWhere(category, nowSec());
  if (!cat || category === 'older_than_30d') {
    return c.json({ ok: false, error: { code: 'INVALID_CATEGORY', message: 'Invalid audit log category.' } }, 400);
  }

  const like = `%${q}%`;
  const clauses = [cat.sql, "(? = '' OR action LIKE ? OR COALESCE(actor_id, '') LIKE ? OR COALESCE(target_id, '') LIKE ? OR COALESCE(metadata, '') LIKE ?)"];
  const binds: (string | number)[] = [...cat.binds, q, like, like, like, like];

  const { results } = await c.env.DB.prepare(
    `SELECT * FROM audit_logs WHERE ${clauses.join(' AND ')} ORDER BY created_at DESC LIMIT 100`
  )
    .bind(...binds)
    .all();
  return c.json({ ok: true, data: results || [] });
});

adminRoutes.post('/audit-logs/purge', requireCsrf, async (c) => {
  const body = await c.req.json<{ category?: string }>().catch(() => ({} as Record<string, undefined>));
  const category = (body.category || '').trim();
  const where = auditCategoryWhere(category, nowSec());
  if (!where) {
    return c.json({ ok: false, error: { code: 'INVALID_CATEGORY', message: 'Invalid audit log purge category.' } }, 400);
  }

  const res = await c.env.DB.prepare(`DELETE FROM audit_logs WHERE ${where.sql}`)
    .bind(...where.binds)
    .run();
  const deleted = res.meta.changes ?? 0;

  await writeAuditLog(c.env.DB, {
    actorId: actorIdOf(c),
    action: 'admin.audit_logs.purge',
    targetType: 'audit_logs',
    targetId: category,
    ipHash: await getIpHash(c),
    metadata: { category, deleted },
  });

  return c.json({ ok: true, data: { category, deleted } });
});

adminRoutes.post('/maintenance/purge', requireCsrf, async (c) => {
  const body = await c.req.json<{ target?: string }>().catch(() => ({} as Record<string, undefined>));
  const target = (body.target || '').trim();
  const now = nowSec();

  const queries: Record<string, () => D1PreparedStatement> = {
    expired_sessions: () => c.env.DB.prepare('DELETE FROM sessions WHERE expires_at < ?').bind(now),
    expired_tokens: () => c.env.DB.prepare('DELETE FROM verification_tokens WHERE expires_at < ?').bind(now),
    expired_oauth_codes: () => c.env.DB.prepare('DELETE FROM oauth_codes WHERE expires_at < ? OR used = 1').bind(now),
    revoked_refresh_tokens: () => c.env.DB.prepare('DELETE FROM refresh_tokens WHERE revoked = 1 OR expires_at < ?').bind(now),
  };

  let deleted = 0;
  if (target === 'all_stale') {
    const results = await c.env.DB.batch(Object.values(queries).map((fn) => fn()));
    deleted = results.reduce((sum, r) => sum + (r.meta.changes ?? 0), 0);
  } else if (queries[target]) {
    const res = await queries[target]().run();
    deleted = res.meta.changes ?? 0;
  } else {
    return c.json({ ok: false, error: { code: 'INVALID_TARGET', message: 'Invalid maintenance purge target.' } }, 400);
  }

  await writeAuditLog(c.env.DB, {
    actorId: actorIdOf(c),
    action: 'admin.maintenance.purge',
    targetType: 'maintenance',
    targetId: target,
    ipHash: await getIpHash(c),
    metadata: { target, deleted },
  });

  return c.json({ ok: true, data: { target, deleted } });
});

export default adminRoutes;
