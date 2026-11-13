import { Hono } from 'hono';
import type { AppEnv, UserRow } from '../types';
import { renderInitialAvatarSvg } from '../lib/images';

const media = new Hono<AppEnv>();

media.get('/avatars/:userId', async (c) => {
  const userId = c.req.param('userId');
  const user = await c.env.DB.prepare(
    "SELECT id, name, email, avatar_key, avatar_color FROM users WHERE id = ? AND status = 'active' LIMIT 1"
  )
    .bind(userId)
    .first<Pick<UserRow, 'id' | 'name' | 'email' | 'avatar_key' | 'avatar_color'>>();

  if (!user) {
    return c.notFound();
  }

  if (user.avatar_key) {
    const obj = await c.env.MEDIA_BUCKET.get(user.avatar_key);
    if (obj) {
      return new Response(obj.body, {
        headers: {
          'Content-Type': 'image/png',
          'Cache-Control': 'public, max-age=3600',
          'X-Content-Type-Options': 'nosniff',
          'Cross-Origin-Resource-Policy': 'cross-origin',
        },
      });
    }
  }

  const svg = renderInitialAvatarSvg(user.name, user.avatar_color, user.email);
  return new Response(svg, {
    headers: {
      'Content-Type': 'image/svg+xml; charset=utf-8',
      'Cache-Control': 'public, max-age=300',
      'X-Content-Type-Options': 'nosniff',
      'Cross-Origin-Resource-Policy': 'cross-origin',
      'Content-Security-Policy': "default-src 'none'; style-src 'unsafe-inline'",
    },
  });
});

media.get('/app-logos/:appId', async (c) => {
  const appId = c.req.param('appId');
  const app = await c.env.DB.prepare('SELECT logo_key FROM apps WHERE id = ? LIMIT 1')
    .bind(appId)
    .first<{ logo_key: string | null }>();

  if (!app || !app.logo_key) {
    return c.notFound();
  }

  const obj = await c.env.MEDIA_BUCKET.get(app.logo_key);
  if (!obj) {
    return c.notFound();
  }

  return new Response(obj.body, {
    headers: {
      'Content-Type': 'image/png',
      'Cache-Control': 'public, max-age=3600',
      'X-Content-Type-Options': 'nosniff',
      'Cross-Origin-Resource-Policy': 'cross-origin',
    },
  });
});

export default media;
