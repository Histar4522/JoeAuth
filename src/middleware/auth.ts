import { createMiddleware } from 'hono/factory';
import { getCookie, setCookie } from 'hono/cookie';
import type { AppEnv } from '../types';
import { CSRF_COOKIE_NAME, isHttpsRequest, resolveSession } from '../lib/session';
import { randomBase64Url, timingSafeEqualBytes } from '../lib/crypto';

const enc = new TextEncoder();

export const sessionMiddleware = createMiddleware<AppEnv>(async (c, next) => {
  let csrf = getCookie(c, CSRF_COOKIE_NAME);
  if (!csrf) {
    csrf = randomBase64Url(24);
    setCookie(c, CSRF_COOKIE_NAME, csrf, {
      httpOnly: false,
      secure: isHttpsRequest(c),
      sameSite: 'Lax',
      path: '/',
      maxAge: 60 * 60 * 24 * 14,
    });
  }
  c.set('csrfToken', csrf);

  const auth = await resolveSession(c);
  c.set('auth', auth);
  await next();
});

export const requireCsrf = createMiddleware<AppEnv>(async (c, next) => {
  const method = c.req.method.toUpperCase();
  if (method === 'GET' || method === 'HEAD' || method === 'OPTIONS') {
    return next();
  }

  const origin = c.req.header('origin');
  const secFetchSite = c.req.header('sec-fetch-site');
  if (secFetchSite && secFetchSite !== 'same-origin' && secFetchSite !== 'none') {
    return c.json({ ok: false, error: { code: 'CSRF_ORIGIN_MISMATCH', message: 'Invalid request origin.' } }, 403);
  }
  if (origin) {
    const reqUrl = new URL(c.req.url);
    const allowedOrigins = new Set([reqUrl.origin]);
    const reqProto = reqUrl.protocol.replace(':', '');
    const host = c.req.header('host');
    if (host) allowedOrigins.add(`${reqProto}://${host}`);
    const fwdHost = c.req.header('x-forwarded-host');
    const fwdProto = c.req.header('x-forwarded-proto') || reqProto;
    if (fwdHost) allowedOrigins.add(`${fwdProto}://${fwdHost}`);

    if (origin === 'null') {
      if (secFetchSite && secFetchSite !== 'same-origin') {
        return c.json({ ok: false, error: { code: 'CSRF_ORIGIN_MISMATCH', message: 'Invalid request origin.' } }, 403);
      }
    } else if (!allowedOrigins.has(origin)) {
      return c.json({ ok: false, error: { code: 'CSRF_ORIGIN_MISMATCH', message: 'Invalid request origin.' } }, 403);
    }
  }

  const cookieCsrf = getCookie(c, CSRF_COOKIE_NAME);
  let submitted = c.req.header('x-csrf-token');

  if (!submitted && (c.req.header('content-type') || '').includes('application/x-www-form-urlencoded')) {
    const cloned = c.req.raw.clone();
    const form = await cloned.formData().catch(() => null);
    const val = form?.get('_csrf');
    if (typeof val === 'string') submitted = val;
  }

  if (!cookieCsrf || !submitted || !timingSafeEqualBytes(enc.encode(cookieCsrf), enc.encode(submitted))) {
    return c.json({ ok: false, error: { code: 'CSRF_INVALID', message: 'Invalid or missing CSRF token.' } }, 403);
  }

  await next();
});

export const requireUser = createMiddleware<AppEnv>(async (c, next) => {
  const auth = c.get('auth');
  if (!auth || !auth.user) {
    return c.json({ ok: false, error: { code: 'UNAUTHORIZED', message: 'Authentication required.' } }, 401);
  }
  await next();
});

export const requireApprovedDeveloper = createMiddleware<AppEnv>(async (c, next) => {
  const auth = c.get('auth');
  if (!auth || !auth.user) {
    return c.json({ ok: false, error: { code: 'UNAUTHORIZED', message: 'Authentication required.' } }, 401);
  }
  if (auth.user.developer_status !== 'approved') {
    return c.json(
      {
        ok: false,
        error: {
          code: 'DEVELOPER_APPROVAL_REQUIRED',
          message: 'Approved developer status is required to create or manage applications.',
        },
      },
      403
    );
  }
  await next();
});

export const requireAdmin = createMiddleware<AppEnv>(async (c, next) => {
  const auth = c.get('auth');
  if (!auth || !auth.sessionId) {
    return c.json({ ok: false, error: { code: 'UNAUTHORIZED', message: 'Admin authentication required.' } }, 401);
  }
  const allowed = auth.isSuperuser || auth.user?.role === 'admin';
  if (!allowed) {
    return c.json({ ok: false, error: { code: 'FORBIDDEN', message: 'Admin privileges required.' } }, 403);
  }
  await next();
});

export const requireSuperuser = createMiddleware<AppEnv>(async (c, next) => {
  const auth = c.get('auth');
  if (!auth || !auth.isSuperuser) {
    return c.json(
      { ok: false, error: { code: 'SUPERUSER_ONLY', message: 'Superuser privileges required for this action.' } },
      403
    );
  }
  await next();
});
