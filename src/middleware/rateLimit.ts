import { createMiddleware } from 'hono/factory';
import type { AppEnv } from '../types';
import { getClientIp } from '../lib/session';

export function rateLimitMiddleware(limiterType: 'auth' | 'token') {
  return createMiddleware<AppEnv>(async (c, next) => {
    const limiter = limiterType === 'auth' ? c.env.AUTH_RATE_LIMITER : c.env.TOKEN_RATE_LIMITER;
    if (limiter && typeof limiter.limit === 'function') {
      const key = `${limiterType}:${getClientIp(c)}`;
      const outcome = await limiter.limit({ key }).catch(() => ({ success: true }));
      if (!outcome.success) {
        return c.json(
          {
            ok: false,
            error: {
              code: 'RATE_LIMITED',
              message: 'Too many requests. Please wait a minute and try again.',
            },
          },
          429
        );
      }
    }
    await next();
  });
}
