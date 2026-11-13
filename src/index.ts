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
import pageRoutes from './routes/pages';

const app = new Hono<AppEnv>();

app.use(
  '*',
  secureHeaders({
    referrerPolicy: 'same-origin',
    contentSecurityPolicy: {
      defaultSrc: ["'self'"],
      scriptSrc: ["'self'", 'https://challenges.cloudflare.com'],
      frameSrc: ["'self'", 'https://challenges.cloudflare.com'],
      styleSrc: ["'self'", "'unsafe-inline'"],
      imgSrc: ["'self'", 'data:', 'https:'],
      connectSrc: ["'self'", 'https://challenges.cloudflare.com'],
    },
  })
);

app.use('/.well-known/*', cors({ origin: '*', allowMethods: ['GET', 'OPTIONS'] }));
app.use('/api/oauth/*', cors({ origin: '*', allowMethods: ['GET', 'POST', 'OPTIONS'] }));

app.use('*', sessionMiddleware);

app.get('/api/health', (c) => c.json({ ok: true, service: c.env.APP_NAME || 'JoeAuth' }));

app.route('/', oauthRoutes);
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
  await env.DB.batch([
    env.DB.prepare('DELETE FROM sessions WHERE expires_at <= ?').bind(now),
    env.DB.prepare('DELETE FROM oauth_codes WHERE expires_at <= ? OR used = 1').bind(now),
    env.DB.prepare('DELETE FROM refresh_tokens WHERE expires_at <= ?').bind(now),
    env.DB.prepare('DELETE FROM verification_tokens WHERE expires_at <= ?').bind(now),
    env.DB.prepare('DELETE FROM audit_logs WHERE created_at < ?').bind(auditCutoff),
  ]);
}

export default {
  fetch: app.fetch,
  async scheduled(_controller: ScheduledController, env: Bindings, ctx: ExecutionContext) {
    ctx.waitUntil(runDailyCleanup(env));
  },
};
