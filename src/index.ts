import { Hono } from 'hono';
import { cors } from 'hono/cors';
import { secureHeaders } from 'hono/secure-headers';
import type { AppEnv, Bindings } from './types';
import { nowSec } from './lib/crypto';
import { sessionMiddleware } from './middleware/auth';
import authRoutes from './routes/auth';
import userRoutes from './routes/user';
import devRoutes from './routes/dev';
import adminRoutes from './routes/admin';
import oauthRoutes from './routes/oauth';
import mediaRoutes from './routes/media';
import pageRoutes from './routes/pages';

const app = new Hono<AppEnv>();

app.use('/media/*', async (c, next) => {
  await next();
  c.header('Cross-Origin-Resource-Policy', 'cross-origin');
});

app.use(
  '*',
  secureHeaders({
    referrerPolicy: 'same-origin',
    contentSecurityPolicy: {
      defaultSrc: ["'self'"],
      scriptSrc: ["'self'", 'https://challenges.cloudflare.com'],
      frameSrc: ["'self'", 'https://challenges.cloudflare.com'],
      styleSrc: ["'self'", "'unsafe-inline'"],
      imgSrc: ["'self'", 'data:', 'blob:', 'https:'],
      connectSrc: ["'self'", 'https://challenges.cloudflare.com'],
    },
  })
);

app.use('/.well-known/*', cors({ origin: '*', allowMethods: ['GET', 'OPTIONS'] }));
app.use('/api/oauth/*', cors({ origin: '*', allowMethods: ['GET', 'POST', 'OPTIONS'] }));
app.use('/media/*', cors({ origin: '*', allowMethods: ['GET', 'OPTIONS'] }));

app.use('*', sessionMiddleware);

app.get('/api/health', (c) => c.json({ ok: true, service: c.env.APP_NAME || 'JoeAuth' }));

app.route('/', oauthRoutes);
app.route('/media', mediaRoutes);
app.route('/api/auth', authRoutes);
app.route('/api/user', userRoutes);
app.route('/api/dev', devRoutes);
app.route('/api/admin', adminRoutes);
app.route('/', pageRoutes);

app.onError((err, c) => {
  console.error('Unhandled error:', err);
  if (c.req.path.startsWith('/api/')) {
    return c.json({ ok: false, error: { code: 'INTERNAL_ERROR', message: 'Internal server error.' } }, 500);
  }
  return c.text('Internal Server Error', 500);
});

export async function runDailyCleanup(env: Bindings): Promise<void> {
  const now = nowSec();
  const auditCutoff = now - 60 * 60 * 24 * 90; // Keep 90 days of audit logs
  const errorLogCutoff = now - 60 * 60 * 24 * 14; // Keep 14 days of app error logs
  await env.DB.batch([
    env.DB.prepare('DELETE FROM sessions WHERE expires_at <= ?').bind(now),
    env.DB.prepare('DELETE FROM oauth_codes WHERE expires_at <= ? OR used = 1').bind(now),
    env.DB.prepare('DELETE FROM device_codes WHERE expires_at <= ?').bind(now),
    env.DB.prepare('DELETE FROM refresh_tokens WHERE expires_at <= ?').bind(now),
    env.DB.prepare('DELETE FROM verification_tokens WHERE expires_at <= ?').bind(now),
    env.DB.prepare('DELETE FROM audit_logs WHERE created_at < ?').bind(auditCutoff),
    env.DB.prepare('DELETE FROM oauth_error_logs WHERE created_at < ?').bind(errorLogCutoff),
  ]);
}

const SLOT_PATH_RE = /^\/u\/(superuser|[0-9]+)(\/.*)?$/;

function rewriteSlotRequest(request: Request): Request {
  const url = new URL(request.url);
  const match = SLOT_PATH_RE.exec(url.pathname);
  const headers = new Headers(request.headers);
  // Strip any client-supplied internal header; slot only comes from the URL prefix
  headers.delete('x-joe-slot');

  if (!match) {
    return new Request(request, { headers });
  }

  headers.set('x-joe-slot', match[1]);
  url.pathname = match[2] || '/';
  const init: RequestInit = {
    method: request.method,
    headers,
    redirect: request.redirect,
  };
  if (request.method !== 'GET' && request.method !== 'HEAD') {
    init.body = request.body;
  }
  return new Request(url.toString(), init);
}

export default {
  fetch(request: Request, env: Bindings, ctx: ExecutionContext) {
    return app.fetch(rewriteSlotRequest(request), env, ctx);
  },
  async scheduled(_controller: ScheduledController, env: Bindings, ctx: ExecutionContext) {
    ctx.waitUntil(runDailyCleanup(env));
  },
};
