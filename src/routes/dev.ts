import { Hono } from 'hono';
import type { AppEnv, AppRow, DeveloperApplicationRow } from '../types';
import { hashSecretValue, nowSec, randomBase64Url, randomHex, verifyPassword } from '../lib/crypto';
import { extractUploadedPng, getAppLogoUrl } from '../lib/images';
import { getIpHash, getPepper } from '../lib/session';
import { verifyTurnstile } from '../lib/turnstile';
import { writeAuditLog } from '../lib/audit';
import { requireApprovedDeveloper, requireCsrf, requireUser } from '../middleware/auth';

const ALLOWED_SCOPES = new Set(['openid', 'profile', 'email', 'offline_access']);

function parseValidRedirectUris(input: unknown): string[] | null {
  if (!Array.isArray(input) || input.length === 0 || input.length > 10) return null;
  const out: string[] = [];
  for (const raw of input) {
    if (typeof raw !== 'string') return null;
    const trimmed = raw.trim();
    if (trimmed.length > 500) return null;
    try {
      const u = new URL(trimmed);
      if ((u.protocol !== 'https:' && u.protocol !== 'http:') || u.hash) return null;
      out.push(u.toString());
    } catch {
      return null;
    }
  }
  return Array.from(new Set(out));
}

function parseScopes(input: unknown): string[] {
  if (!Array.isArray(input) || input.length === 0) return ['openid', 'profile', 'email'];
  const valid = input.filter((s): s is string => typeof s === 'string' && ALLOWED_SCOPES.has(s));
  if (!valid.includes('openid')) valid.unshift('openid');
  return Array.from(new Set(valid));
}

function isValidHttpUrl(value: string): boolean {
  if (!value || value.length > 500) return false;
  try {
    const u = new URL(value);
    return u.protocol === 'https:' || u.protocol === 'http:';
  } catch {
    return false;
  }
}

const devRoutes = new Hono<AppEnv>();

devRoutes.get('/status', requireUser, async (c) => {
  const user = c.get('auth')!.user!;
  const latest = await c.env.DB.prepare(
    'SELECT * FROM developer_applications WHERE user_id = ? ORDER BY created_at DESC LIMIT 5'
  )
    .bind(user.id)
    .all<DeveloperApplicationRow>();

  return c.json({
    ok: true,
    data: {
      developer_status: user.developer_status,
      applications: latest.results || [],
    },
  });
});

devRoutes.post('/apply', requireUser, requireCsrf, async (c) => {
  const user = c.get('auth')!.user!;
  if (user.developer_status === 'approved') {
    return c.json({ ok: false, error: { code: 'ALREADY_APPROVED', message: 'You already have developer access.' } }, 400);
  }
  if (user.developer_status === 'pending') {
    return c.json(
      { ok: false, error: { code: 'ALREADY_PENDING', message: 'Your developer application is already pending review.' } },
      400
    );
  }

  const body = await c.req.json<{
    serviceName?: string;
    serviceUrl?: string;
    reason?: string;
    turnstileToken?: string;
  }>().catch(() => ({} as Record<string, undefined>));

  const ts = await verifyTurnstile(body.turnstileToken, c.env.TURNSTILE_SECRET_KEY, c.req.header('cf-connecting-ip'));
  if (!ts.ok) {
    return c.json({ ok: false, error: { code: 'TURNSTILE_FAILED', message: ts.error } }, 400);
  }

  const serviceName = (body.serviceName || '').trim().slice(0, 80);
  const serviceUrl = (body.serviceUrl || '').trim();
  const reason = (body.reason || '').trim();

  if (serviceUrl && !isValidHttpUrl(serviceUrl)) {
    return c.json({ ok: false, error: { code: 'INVALID_URL', message: 'Service URL must be http:// or https://.' } }, 400);
  }
  if (reason.length < 10 || reason.length > 500) {
    return c.json({ ok: false, error: { code: 'INVALID_REASON', message: 'Please describe your use case (10-500 chars).' } }, 400);
  }

  const appId = crypto.randomUUID();
  const now = nowSec();
  await c.env.DB.batch([
    c.env.DB.prepare(
      'INSERT INTO developer_applications (id, user_id, service_name, service_url, reason, status, created_at) VALUES (?, ?, ?, ?, ?, ?, ?)'
    ).bind(appId, user.id, serviceName, serviceUrl, reason, 'pending', now),
    c.env.DB.prepare("UPDATE users SET developer_status = 'pending', updated_at = ? WHERE id = ?").bind(now, user.id),
  ]);

  await writeAuditLog(c.env.DB, {
    actorId: user.id,
    action: 'dev.apply',
    targetType: 'developer_application',
    targetId: appId,
    ipHash: await getIpHash(c),
    metadata: { serviceName },
  });

  return c.json({ ok: true, data: { id: appId, status: 'pending' } }, 201);
});

// --- All endpoints below require Approved Developer status ---

devRoutes.get('/apps', requireApprovedDeveloper, async (c) => {
  const user = c.get('auth')!.user!;
  const { results } = await c.env.DB.prepare(
    `SELECT id, name, description, privilege_description, homepage_url, client_id, client_secret_prefix, redirect_uris, allowed_scopes, logo_key, logo_version, is_first_party, status, created_at, updated_at
     FROM apps WHERE owner_user_id = ? ORDER BY created_at DESC`
  )
    .bind(user.id)
    .all<Omit<AppRow, 'owner_user_id' | 'client_secret_hash'>>();

  return c.json({
    ok: true,
    data: (results || []).map(({ logo_key, ...a }) => ({
      ...a,
      has_custom_logo: Boolean(logo_key),
      logo_url: logo_key ? getAppLogoUrl('', a.id, a.logo_version) : null,
      redirect_uris: JSON.parse(a.redirect_uris),
      allowed_scopes: JSON.parse(a.allowed_scopes),
    })),
  });
});

devRoutes.post('/apps', requireApprovedDeveloper, requireCsrf, async (c) => {
  const user = c.get('auth')!.user!;
  const body = await c.req.json<{
    name?: string;
    description?: string;
    privilegeDescription?: string;
    homepageUrl?: string;
    redirectUris?: string[];
    allowedScopes?: string[];
  }>().catch(() => ({} as Record<string, unknown>));

  const name = typeof body.name === 'string' ? body.name.trim() : '';
  const description = typeof body.description === 'string' ? body.description.trim().slice(0, 300) : '';
  const privilegeDescription =
    typeof body.privilegeDescription === 'string' ? body.privilegeDescription.trim().slice(0, 400) : '';
  const homepageUrl = typeof body.homepageUrl === 'string' ? body.homepageUrl.trim() : '';
  const redirectUris = parseValidRedirectUris(body.redirectUris);
  const allowedScopes = parseScopes(body.allowedScopes);

  if (name.length < 2 || name.length > 64) {
    return c.json({ ok: false, error: { code: 'INVALID_NAME', message: 'App name must be 2 to 64 characters.' } }, 400);
  }
  if (!isValidHttpUrl(homepageUrl)) {
    return c.json({ ok: false, error: { code: 'INVALID_HOMEPAGE', message: 'Valid http/https homepage URL required.' } }, 400);
  }
  if (!redirectUris) {
    return c.json(
      {
        ok: false,
        error: {
          code: 'INVALID_REDIRECT_URIS',
          message: 'Provide 1 to 10 valid http/https redirect URIs without URL fragments.',
        },
      },
      400
    );
  }

  const id = crypto.randomUUID();
  const clientId = `ja_${randomHex(10)}`;
  const clientSecret = `jas_${randomBase64Url(32)}`;
  const clientSecretHash = await hashSecretValue(clientSecret, getPepper(c.env));
  const clientSecretPrefix = clientSecret.slice(0, 12);
  const now = nowSec();

  // Approved immediately once user has approved developer access
  await c.env.DB.prepare(
    `INSERT INTO apps (id, owner_user_id, name, description, privilege_description, homepage_url, client_id, client_secret_hash, client_secret_prefix, redirect_uris, allowed_scopes, is_first_party, status, created_at, updated_at)
     VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 0, 'approved', ?, ?)`
  )
    .bind(
      id,
      user.id,
      name,
      description,
      privilegeDescription,
      homepageUrl,
      clientId,
      clientSecretHash,
      clientSecretPrefix,
      JSON.stringify(redirectUris),
      JSON.stringify(allowedScopes),
      now,
      now
    )
    .run();

  await writeAuditLog(c.env.DB, {
    actorId: user.id,
    action: 'dev.app.create',
    targetType: 'app',
    targetId: id,
    ipHash: await getIpHash(c),
    metadata: { clientId, name },
  });

  return c.json(
    {
      ok: true,
      data: {
        id,
        name,
        description,
        privilege_description: privilegeDescription,
        homepage_url: homepageUrl,
        client_id: clientId,
        client_secret: clientSecret,
        client_secret_prefix: clientSecretPrefix,
        redirect_uris: redirectUris,
        allowed_scopes: allowedScopes,
        has_custom_logo: false,
        logo_url: null,
        status: 'approved',
      },
    },
    201
  );
});

devRoutes.patch('/apps/:id', requireApprovedDeveloper, requireCsrf, async (c) => {
  const user = c.get('auth')!.user!;
  const appId = c.req.param('id');
  const existing = await c.env.DB.prepare('SELECT * FROM apps WHERE id = ? AND owner_user_id = ?')
    .bind(appId, user.id)
    .first<AppRow>();

  if (!existing) {
    return c.json({ ok: false, error: { code: 'NOT_FOUND', message: 'Application not found.' } }, 404);
  }

  const body = await c.req.json<{
    name?: string;
    description?: string;
    privilegeDescription?: string;
    homepageUrl?: string;
    redirectUris?: string[];
    allowedScopes?: string[];
  }>().catch(() => ({} as Record<string, unknown>));

  const name = typeof body.name === 'string' ? body.name.trim() : existing.name;
  const description = typeof body.description === 'string' ? body.description.trim().slice(0, 300) : existing.description;
  const privilegeDescription =
    typeof body.privilegeDescription === 'string'
      ? body.privilegeDescription.trim().slice(0, 400)
      : existing.privilege_description;
  const homepageUrl = typeof body.homepageUrl === 'string' ? body.homepageUrl.trim() : existing.homepage_url;
  const redirectUris = body.redirectUris !== undefined ? parseValidRedirectUris(body.redirectUris) : JSON.parse(existing.redirect_uris);
  const allowedScopes = body.allowedScopes !== undefined ? parseScopes(body.allowedScopes) : JSON.parse(existing.allowed_scopes);

  if (name.length < 2 || name.length > 64 || !isValidHttpUrl(homepageUrl) || !redirectUris) {
    return c.json({ ok: false, error: { code: 'INVALID_INPUT', message: 'Invalid application metadata or redirect URIs.' } }, 400);
  }

  await c.env.DB.prepare(
    'UPDATE apps SET name = ?, description = ?, privilege_description = ?, homepage_url = ?, redirect_uris = ?, allowed_scopes = ?, updated_at = ? WHERE id = ?'
  )
    .bind(name, description, privilegeDescription, homepageUrl, JSON.stringify(redirectUris), JSON.stringify(allowedScopes), nowSec(), appId)
    .run();

  return c.json({ ok: true, data: { updated: true } });
});

devRoutes.post('/apps/:id/logo', requireApprovedDeveloper, requireCsrf, async (c) => {
  const user = c.get('auth')!.user!;
  const appId = c.req.param('id');
  const existing = await c.env.DB.prepare(
    'SELECT id, logo_key, logo_version FROM apps WHERE id = ? AND owner_user_id = ?'
  )
    .bind(appId, user.id)
    .first<Pick<AppRow, 'id' | 'logo_key' | 'logo_version'>>();

  if (!existing) {
    return c.json({ ok: false, error: { code: 'NOT_FOUND', message: 'Application not found.' } }, 404);
  }

  const parsed = await extractUploadedPng(c.req.raw, ['file', 'logo']);
  if (!parsed.ok) {
    return c.json({ ok: false, error: { code: 'INVALID_IMAGE', message: parsed.message } }, 400);
  }

  const nextVersion = (existing.logo_version || 0) + 1;
  const key = `app-logos/${existing.id}/v${nextVersion}.png`;
  await c.env.MEDIA_BUCKET.put(key, parsed.bytes, {
    httpMetadata: { contentType: 'image/png' },
  });

  if (existing.logo_key && existing.logo_key !== key) {
    await c.env.MEDIA_BUCKET.delete(existing.logo_key).catch(() => {});
  }

  await c.env.DB.prepare('UPDATE apps SET logo_key = ?, logo_version = ?, updated_at = ? WHERE id = ?')
    .bind(key, nextVersion, nowSec(), existing.id)
    .run();

  await writeAuditLog(c.env.DB, {
    actorId: user.id,
    action: 'dev.app.logo_updated',
    targetType: 'app',
    targetId: existing.id,
    ipHash: await getIpHash(c),
  });

  return c.json({
    ok: true,
    data: {
      logo_url: getAppLogoUrl('', existing.id, nextVersion),
      logo_version: nextVersion,
      has_custom_logo: true,
    },
  });
});

devRoutes.delete('/apps/:id/logo', requireApprovedDeveloper, requireCsrf, async (c) => {
  const user = c.get('auth')!.user!;
  const appId = c.req.param('id');
  const existing = await c.env.DB.prepare(
    'SELECT id, logo_key, logo_version FROM apps WHERE id = ? AND owner_user_id = ?'
  )
    .bind(appId, user.id)
    .first<Pick<AppRow, 'id' | 'logo_key' | 'logo_version'>>();

  if (!existing) {
    return c.json({ ok: false, error: { code: 'NOT_FOUND', message: 'Application not found.' } }, 404);
  }

  if (existing.logo_key) {
    await c.env.MEDIA_BUCKET.delete(existing.logo_key).catch(() => {});
  }

  const nextVersion = (existing.logo_version || 0) + 1;
  await c.env.DB.prepare('UPDATE apps SET logo_key = NULL, logo_version = ?, updated_at = ? WHERE id = ?')
    .bind(nextVersion, nowSec(), existing.id)
    .run();

  await writeAuditLog(c.env.DB, {
    actorId: user.id,
    action: 'dev.app.logo_deleted',
    targetType: 'app',
    targetId: existing.id,
    ipHash: await getIpHash(c),
  });

  return c.json({
    ok: true,
    data: {
      logo_url: null,
      logo_version: nextVersion,
      has_custom_logo: false,
    },
  });
});

devRoutes.post('/apps/:id/rotate-secret', requireApprovedDeveloper, requireCsrf, async (c) => {
  const user = c.get('auth')!.user!;
  const appId = c.req.param('id');
  const body = await c.req.json<{ currentPassword?: string }>().catch(() => ({} as Record<string, undefined>));

  if (!(await verifyPassword(body.currentPassword || '', user.password_hash, getPepper(c.env)))) {
    return c.json({ ok: false, error: { code: 'INVALID_PASSWORD', message: 'Password confirmation failed.' } }, 401);
  }

  const existing = await c.env.DB.prepare('SELECT id FROM apps WHERE id = ? AND owner_user_id = ?')
    .bind(appId, user.id)
    .first();
  if (!existing) {
    return c.json({ ok: false, error: { code: 'NOT_FOUND', message: 'Application not found.' } }, 404);
  }

  const clientSecret = `jas_${randomBase64Url(32)}`;
  const clientSecretHash = await hashSecretValue(clientSecret, getPepper(c.env));
  const clientSecretPrefix = clientSecret.slice(0, 12);

  await c.env.DB.prepare(
    'UPDATE apps SET client_secret_hash = ?, client_secret_prefix = ?, updated_at = ? WHERE id = ?'
  )
    .bind(clientSecretHash, clientSecretPrefix, nowSec(), appId)
    .run();

  await writeAuditLog(c.env.DB, {
    actorId: user.id,
    action: 'dev.app.rotate_secret',
    targetType: 'app',
    targetId: appId,
    ipHash: await getIpHash(c),
  });

  return c.json({ ok: true, data: { client_secret: clientSecret, client_secret_prefix: clientSecretPrefix } });
});

devRoutes.delete('/apps/:id', requireApprovedDeveloper, requireCsrf, async (c) => {
  const user = c.get('auth')!.user!;
  const appId = c.req.param('id');

  const existing = await c.env.DB.prepare('SELECT id, logo_key FROM apps WHERE id = ? AND owner_user_id = ?')
    .bind(appId, user.id)
    .first<{ id: string; logo_key: string | null }>();
  if (!existing) {
    return c.json({ ok: false, error: { code: 'NOT_FOUND', message: 'Application not found.' } }, 404);
  }

  const res = await c.env.DB.prepare('DELETE FROM apps WHERE id = ? AND owner_user_id = ?').bind(appId, user.id).run();
  if (!res.meta.changes) {
    return c.json({ ok: false, error: { code: 'NOT_FOUND', message: 'Application not found.' } }, 404);
  }

  if (existing.logo_key) {
    await c.env.MEDIA_BUCKET.delete(existing.logo_key).catch(() => {});
  }

  await c.env.DB.batch([
    c.env.DB.prepare('DELETE FROM oauth_codes WHERE app_id = ?').bind(appId),
    c.env.DB.prepare('DELETE FROM refresh_tokens WHERE app_id = ?').bind(appId),
  ]);

  await writeAuditLog(c.env.DB, {
    actorId: user.id,
    action: 'dev.app.delete',
    targetType: 'app',
    targetId: appId,
    ipHash: await getIpHash(c),
  });

  return c.json({ ok: true, data: { deleted: true } });
});

export default devRoutes;
