import type { Bindings } from '../types';
import { decryptSecretValue, signWebhookPayload } from './crypto';

export type WebhookEventType = 'consent.revoked' | 'user.suspended' | 'user.deleted' | 'webhook.test';

function isPrivateOrDisallowedIpv4(host: string): boolean {
  const parts = host.split('.');
  if (parts.length !== 4 || !parts.every((p) => /^\d{1,3}$/.test(p))) return false;
  const nums = parts.map((p) => Number(p));
  if (nums.some((n) => n < 0 || n > 255)) return true;
  const [a, b] = nums;
  if (a === 0 || a === 10 || a === 127) return true;
  if (a === 169 && b === 254) return true;
  if (a === 172 && b >= 16 && b <= 31) return true;
  if (a === 192 && b === 168) return true;
  if (a === 100 && b >= 64 && b <= 127) return true; // CGNAT
  if (a >= 224) return true; // multicast & reserved
  return false;
}

export function isSafeWebhookUrl(raw: string): boolean {
  try {
    const url = new URL(raw.trim());
    if (url.protocol !== 'https:') return false;
    if (url.username || url.password) return false;
    const host = url.hostname.toLowerCase().replace(/^\[|\]$/g, '');
    if (!host) return false;

    if (
      host === 'localhost' ||
      host.endsWith('.localhost') ||
      host.endsWith('.local') ||
      host.endsWith('.internal') ||
      host.endsWith('.localdomain')
    ) {
      return false;
    }

    // Disallow numeric/hex single-label IP representations
    if (/^\d+$/.test(host) || /^0x[0-9a-f]+$/i.test(host)) return false;

    if (isPrivateOrDisallowedIpv4(host)) return false;

    // Disallow IPv6 loopback, ULA (fc00::/7), link-local (fe80::/10), and IPv4-mapped
    if (host.includes(':')) {
      if (host === '::' || host === '::1' || host.startsWith('::ffff:')) return false;
      if (/^(fc|fd)/i.test(host) || /^fe[89ab]/i.test(host)) return false;
    }

    return true;
  } catch {
    return false;
  }
}

export async function recordOAuthAppError(
  db: D1Database,
  appId: string | null | undefined,
  endpoint: string,
  errorCode: string,
  errorDescription: string
): Promise<void> {
  if (!appId) return;
  try {
    await db
      .prepare(
        'INSERT INTO oauth_error_logs (id, app_id, endpoint, error_code, detail, created_at) VALUES (?, ?, ?, ?, ?, ?)'
      )
      .bind(
        crypto.randomUUID(),
        appId,
        endpoint.slice(0, 64),
        errorCode.slice(0, 64),
        errorDescription.slice(0, 300),
        Math.floor(Date.now() / 1000)
      )
      .run();
  } catch {
    // Non-fatal: logging must never break OAuth error responses
  }
}

async function deliverSingleWebhook(
  webhookUrl: string,
  secret: string,
  event: WebhookEventType,
  data: Record<string, unknown>
): Promise<{ ok: boolean; status: number }> {
  const timestamp = Math.floor(Date.now() / 1000);
  const body = JSON.stringify({
    id: crypto.randomUUID(),
    event,
    timestamp,
    data,
  });
  const sigHeader = await signWebhookPayload(secret, timestamp, body);

  for (let attempt = 0; attempt < 2; attempt++) {
    try {
      const res = await fetch(webhookUrl, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'X-JoeAuth-Event': event,
          'X-JoeAuth-Signature': sigHeader,
        },
        body,
        signal: AbortSignal.timeout(4000),
      });
      if (res.ok) return { ok: true, status: res.status };
      if (res.status < 500 || attempt === 1) return { ok: false, status: res.status };
    } catch {
      if (attempt === 1) return { ok: false, status: 0 };
    }
  }
  return { ok: false, status: 0 };
}

export async function dispatchAppWebhooks(
  env: Bindings,
  ctx: { waitUntil: (promise: Promise<unknown>) => void } | undefined,
  opts: {
    event: WebhookEventType;
    userId?: string;
    appId?: string;
    data?: Record<string, unknown>;
  }
): Promise<{ dispatched: number; delivered?: boolean; status?: number }> {
  const masterKey = env.WEBHOOK_ENC_KEY || env.PASSWORD_PEPPER || 'joe-auth-webhook-fallback';

  let targets: Array<{ id: string; webhook_url: string; webhook_secret_enc: string }> = [];
  if (opts.appId) {
    const row = await env.DB.prepare(
      `SELECT id, webhook_url, webhook_secret_enc FROM apps
       WHERE id = ? AND webhook_url != '' AND webhook_secret_enc IS NOT NULL`
    )
      .bind(opts.appId)
      .first<{ id: string; webhook_url: string; webhook_secret_enc: string }>();
    if (row) targets = [row];
  } else if (opts.userId) {
    const { results } = await env.DB.prepare(
      `SELECT DISTINCT a.id, a.webhook_url, a.webhook_secret_enc
       FROM apps a
       JOIN user_consents uc ON uc.app_id = a.id
       WHERE uc.user_id = ? AND a.webhook_url != '' AND a.webhook_secret_enc IS NOT NULL`
    )
      .bind(opts.userId)
      .all<{ id: string; webhook_url: string; webhook_secret_enc: string }>();
    targets = results || [];
  }

  const validTargets = targets.filter((t) => isSafeWebhookUrl(t.webhook_url));
  if (validTargets.length === 0) return { dispatched: 0 };

  if (opts.event === 'webhook.test' && validTargets.length === 1) {
    const target = validTargets[0];
    const secret = await decryptSecretValue(target.webhook_secret_enc, masterKey);
    if (!secret) return { dispatched: 0, delivered: false, status: 0 };
    const res = await deliverSingleWebhook(target.webhook_url, secret, opts.event, {
      app_id: target.id,
      ...(opts.data || {}),
    });
    return { dispatched: 1, delivered: res.ok, status: res.status };
  }

  const runAll = Promise.all(
    validTargets.map(async (target) => {
      const secret = await decryptSecretValue(target.webhook_secret_enc, masterKey);
      if (!secret) return;
      await deliverSingleWebhook(target.webhook_url, secret, opts.event, {
        app_id: target.id,
        ...(opts.userId ? { user_id: opts.userId } : {}),
        ...(opts.data || {}),
      });
    })
  );

  if (ctx) {
    ctx.waitUntil(runAll);
  } else {
    await runAll;
  }

  return { dispatched: validTargets.length };
}
