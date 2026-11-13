import type { Context } from 'hono';
import { deleteCookie, getCookie, setCookie } from 'hono/cookie';
import type { AppEnv, AuthContext, Bindings, ResolvedAccountSession, SessionRow, UserRow } from '../types';
import { nowSec, randomBase64Url, sha256Hex } from './crypto';

export const SESSION_COOKIE_NAME = 'joe_session'; // Legacy fallback read
export const SESSIONS_COOKIE_NAME = 'joe_sessions';
export const ACTIVE_COOKIE_NAME = 'joe_active';
export const CSRF_COOKIE_NAME = 'joe_csrf';
export const SESSION_TTL_SECONDS = 60 * 60 * 24 * 14; // 14 days
export const SUPERUSER_SESSION_TTL_SECONDS = 60 * 60 * 8; // 8 hours
export const MAX_BROWSER_SESSIONS = 8;

export function isHttpsRequest(c: Context<AppEnv>): boolean {
  const url = new URL(c.req.url);
  return url.protocol === 'https:' || c.req.header('x-forwarded-proto') === 'https';
}

export function getClientIp(c: Context<AppEnv>): string {
  return (
    c.req.header('cf-connecting-ip') ||
    c.req.header('x-forwarded-for')?.split(',')[0]?.trim() ||
    '127.0.0.1'
  );
}

export async function getIpHash(c: Context<AppEnv>): Promise<string> {
  const ip = getClientIp(c);
  const pepper = c.env.PASSWORD_PEPPER || 'local';
  return (await sha256Hex(`${pepper}:${ip}`)).slice(0, 16);
}

function readRawTokensFromCookies(c: Context<AppEnv>): string[] {
  const multi = getCookie(c, SESSIONS_COOKIE_NAME);
  const tokens = multi
    ? multi
        .split('.')
        .map((t) => t.trim())
        .filter((t) => /^[A-Za-z0-9_-]{16,128}$/.test(t))
    : [];

  if (tokens.length === 0) {
    const legacy = getCookie(c, SESSION_COOKIE_NAME);
    if (legacy && /^[A-Za-z0-9_-]{16,128}$/.test(legacy.trim())) {
      tokens.push(legacy.trim());
    }
  }
  return Array.from(new Set(tokens)).slice(0, MAX_BROWSER_SESSIONS);
}

function writeSessionsCookie(c: Context<AppEnv>, rawTokens: string[]): void {
  if (rawTokens.length === 0) {
    deleteCookie(c, SESSIONS_COOKIE_NAME, { path: '/' });
    deleteCookie(c, SESSION_COOKIE_NAME, { path: '/' });
    return;
  }
  setCookie(c, SESSIONS_COOKIE_NAME, rawTokens.slice(-MAX_BROWSER_SESSIONS).join('.'), {
    httpOnly: true,
    secure: isHttpsRequest(c),
    sameSite: 'Lax',
    path: '/',
    maxAge: SESSION_TTL_SECONDS,
  });
  deleteCookie(c, SESSION_COOKIE_NAME, { path: '/' });
}

function writeActiveCookie(c: Context<AppEnv>, sessionId: string | null, maxAge = SESSION_TTL_SECONDS): void {
  if (!sessionId) {
    deleteCookie(c, ACTIVE_COOKIE_NAME, { path: '/' });
    return;
  }
  setCookie(c, ACTIVE_COOKIE_NAME, sessionId, {
    httpOnly: true,
    secure: isHttpsRequest(c),
    sameSite: 'Lax',
    path: '/',
    maxAge,
  });
}

export async function createSession(
  c: Context<AppEnv>,
  opts: { userId: string; isSuperuser?: boolean }
): Promise<string> {
  const rawToken = randomBase64Url(32);
  const tokenHash = await sha256Hex(rawToken);
  const now = nowSec();
  const ttl = opts.isSuperuser ? SUPERUSER_SESSION_TTL_SECONDS : SESSION_TTL_SECONDS;
  const expiresAt = now + ttl;
  const ipHash = await getIpHash(c);
  const ua = (c.req.header('user-agent') || '').slice(0, 200);

  // Deduplicate existing browser session for the same userId / superuser
  const existingTokens = readRawTokensFromCookies(c);
  const keptTokens: string[] = [];
  if (existingTokens.length > 0) {
    const existingHashes = await Promise.all(existingTokens.map(sha256Hex));
    const placeholders = existingHashes.map(() => '?').join(',');
    const { results } = await c.env.DB.prepare(
      `SELECT id, user_id, is_superuser FROM sessions WHERE id IN (${placeholders})`
    )
      .bind(...existingHashes)
      .all<Pick<SessionRow, 'id' | 'user_id' | 'is_superuser'>>();

    const byHash = new Map((results || []).map((r) => [r.id, r]));
    const staleIds: string[] = [];
    for (let i = 0; i < existingTokens.length; i++) {
      const h = existingHashes[i];
      const row = byHash.get(h);
      if (!row) continue;
      const sameAccount = opts.isSuperuser
        ? row.is_superuser === 1
        : row.is_superuser === 0 && row.user_id === opts.userId;
      if (sameAccount) {
        staleIds.push(h);
      } else {
        keptTokens.push(existingTokens[i]);
      }
    }
    if (staleIds.length > 0) {
      await c.env.DB.prepare(`DELETE FROM sessions WHERE id IN (${staleIds.map(() => '?').join(',')})`)
        .bind(...staleIds)
        .run();
    }
  }

  await c.env.DB.prepare(
    'INSERT INTO sessions (id, user_id, is_superuser, ip_hash, user_agent, expires_at, created_at, last_seen_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?)'
  )
    .bind(tokenHash, opts.userId, opts.isSuperuser ? 1 : 0, ipHash, ua, expiresAt, now, now)
    .run();

  const updatedTokens = [...keptTokens, rawToken].slice(-MAX_BROWSER_SESSIONS);
  writeSessionsCookie(c, updatedTokens);
  writeActiveCookie(c, tokenHash, ttl);

  return tokenHash;
}

export async function switchActiveSession(c: Context<AppEnv>, targetSessionId: string): Promise<boolean> {
  const auth = c.get('auth');
  if (!auth) return false;
  const target = auth.accounts.find((a) => a.sessionId === targetSessionId);
  if (!target) return false;

  const ttl = target.isSuperuser ? SUPERUSER_SESSION_TTL_SECONDS : SESSION_TTL_SECONDS;
  writeActiveCookie(c, target.sessionId, ttl);
  c.set('auth', {
    sessionId: target.sessionId,
    isSuperuser: target.isSuperuser,
    user: target.user,
    accounts: auth.accounts,
  });
  return true;
}

export async function destroySession(
  c: Context<AppEnv>,
  opts: { sessionId?: string; all?: boolean } = {}
): Promise<void> {
  const rawTokens = readRawTokensFromCookies(c);
  if (rawTokens.length === 0) {
    writeSessionsCookie(c, []);
    writeActiveCookie(c, null);
    return;
  }

  const tokenHashes = await Promise.all(rawTokens.map(sha256Hex));
  const activeHash = getCookie(c, ACTIVE_COOKIE_NAME) || '';

  if (opts.all) {
    await c.env.DB.prepare(`DELETE FROM sessions WHERE id IN (${tokenHashes.map(() => '?').join(',')})`)
      .bind(...tokenHashes)
      .run();
    writeSessionsCookie(c, []);
    writeActiveCookie(c, null);
    return;
  }

  const targetHash = opts.sessionId || activeHash;
  if (!targetHash) return;

  const targetIdx = tokenHashes.indexOf(targetHash);
  if (targetIdx === -1) return;

  await c.env.DB.prepare('DELETE FROM sessions WHERE id = ?').bind(targetHash).run();
  const remaining = rawTokens.filter((_, idx) => idx !== targetIdx);
  writeSessionsCookie(c, remaining);

  if (targetHash === activeHash || remaining.length === 0) {
    writeActiveCookie(c, null);
  }
}

export async function destroyCurrentSession(c: Context<AppEnv>): Promise<void> {
  return destroySession(c, {});
}

export async function resolveSession(c: Context<AppEnv>): Promise<AuthContext | null> {
  const rawTokens = readRawTokensFromCookies(c);
  if (rawTokens.length === 0) return null;

  const tokenHashes = await Promise.all(rawTokens.map(sha256Hex));
  const now = nowSec();
  const placeholders = tokenHashes.map(() => '?').join(',');
  const { results: sessionRows } = await c.env.DB.prepare(
    `SELECT * FROM sessions WHERE id IN (${placeholders}) AND expires_at > ?`
  )
    .bind(...tokenHashes, now)
    .all<SessionRow>();

  const sessionMap = new Map((sessionRows || []).map((s) => [s.id, s]));
  const userIds = Array.from(
    new Set((sessionRows || []).filter((s) => s.is_superuser === 0).map((s) => s.user_id))
  );

  const userMap = new Map<string, UserRow>();
  if (userIds.length > 0) {
    const uPlaceholders = userIds.map(() => '?').join(',');
    const { results: userRows } = await c.env.DB.prepare(
      `SELECT * FROM users WHERE id IN (${uPlaceholders}) AND status = 'active'`
    )
      .bind(...userIds)
      .all<UserRow>();
    for (const u of userRows || []) {
      userMap.set(u.id, u);
    }
  }

  const validRawTokens: string[] = [];
  const accounts: ResolvedAccountSession[] = [];
  const deadSessionIds: string[] = [];
  const staleSeenIds: string[] = [];

  for (let i = 0; i < rawTokens.length; i++) {
    const hash = tokenHashes[i];
    const s = sessionMap.get(hash);
    if (!s) continue;

    if (s.is_superuser === 1) {
      validRawTokens.push(rawTokens[i]);
      accounts.push({ sessionId: s.id, isSuperuser: true, user: null, lastSeenAt: s.last_seen_at });
      if (now - s.last_seen_at > 300) staleSeenIds.push(s.id);
    } else {
      const user = userMap.get(s.user_id);
      if (!user) {
        deadSessionIds.push(s.id);
        continue;
      }
      validRawTokens.push(rawTokens[i]);
      accounts.push({ sessionId: s.id, isSuperuser: false, user, lastSeenAt: s.last_seen_at });
      if (now - s.last_seen_at > 300) staleSeenIds.push(s.id);
    }
  }

  // Self-heal cookie & DB if any token expired or user was suspended/deleted
  if (validRawTokens.length !== rawTokens.length || getCookie(c, SESSION_COOKIE_NAME)) {
    writeSessionsCookie(c, validRawTokens);
  }
  if (deadSessionIds.length > 0) {
    const p = c.env.DB.prepare(`DELETE FROM sessions WHERE id IN (${deadSessionIds.map(() => '?').join(',')})`)
      .bind(...deadSessionIds)
      .run();
    try { c.executionCtx.waitUntil(p); } catch { await p; }
  }
  if (staleSeenIds.length > 0) {
    const p = c.env.DB.prepare(`UPDATE sessions SET last_seen_at = ? WHERE id IN (${staleSeenIds.map(() => '?').join(',')})`)
      .bind(now, ...staleSeenIds)
      .run();
    try { c.executionCtx.waitUntil(p); } catch { await p; }
  }

  if (accounts.length === 0) {
    writeActiveCookie(c, null);
    return null;
  }

  const activeCookie = getCookie(c, ACTIVE_COOKIE_NAME);
  // Legacy single-cookie migration: if user came from old `joe_session`, treat that token as active
  const activeMatch = activeCookie
    ? accounts.find((a) => a.sessionId === activeCookie)
    : accounts.length === 1 && getCookie(c, SESSION_COOKIE_NAME)
      ? accounts[0]
      : undefined;

  if (activeCookie && !activeMatch) {
    writeActiveCookie(c, null);
  }

  return {
    sessionId: activeMatch ? activeMatch.sessionId : '',
    isSuperuser: activeMatch ? activeMatch.isSuperuser : false,
    user: activeMatch ? activeMatch.user : null,
    accounts,
  };
}

export async function getSystemSetting(db: D1Database, key: string, fallback: string): Promise<string> {
  const row = await db
    .prepare('SELECT value FROM system_settings WHERE key = ?')
    .bind(key)
    .first<{ value: string }>();
  return row ? row.value : fallback;
}

export async function isEmailVerificationRequired(env: Bindings): Promise<boolean> {
  if (!env.RESEND_API_KEY) return false;
  const setting = await getSystemSetting(env.DB, 'require_email_verification', env.REQUIRE_EMAIL_VERIFICATION || 'true');
  return setting === 'true';
}

export function getPepper(env: Bindings): string {
  return env.PASSWORD_PEPPER || 'joeauth-dev-fallback-pepper';
}
