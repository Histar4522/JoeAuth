import type { Bindings } from '../types';

const enc = new TextEncoder();
const dec = new TextDecoder();

export function nowSec(): number {
  return Math.floor(Date.now() / 1000);
}

export function bytesToHex(bytes: Uint8Array): string {
  return Array.from(bytes, (b) => b.toString(16).padStart(2, '0')).join('');
}

export function hexToBytes(hex: string): Uint8Array {
  if (!/^[0-9a-fA-F]*$/.test(hex) || hex.length % 2 !== 0) {
    return new Uint8Array(0);
  }
  const out = new Uint8Array(hex.length / 2);
  for (let i = 0; i < out.length; i++) {
    out[i] = parseInt(hex.slice(i * 2, i * 2 + 2), 16);
  }
  return out;
}

export function base64UrlEncode(input: Uint8Array | ArrayBuffer): string {
  const bytes = input instanceof Uint8Array ? input : new Uint8Array(input);
  let bin = '';
  for (let i = 0; i < bytes.length; i++) {
    bin += String.fromCharCode(bytes[i]);
  }
  return btoa(bin).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

export function base64UrlDecode(str: string): Uint8Array {
  const padded = str.replace(/-/g, '+').replace(/_/g, '/') + '==='.slice((str.length + 3) % 4);
  const bin = atob(padded);
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) {
    out[i] = bin.charCodeAt(i);
  }
  return out;
}

export function randomHex(byteLength = 32): string {
  return bytesToHex(crypto.getRandomValues(new Uint8Array(byteLength)));
}

export function randomBase64Url(byteLength = 32): string {
  return base64UrlEncode(crypto.getRandomValues(new Uint8Array(byteLength)));
}

export async function sha256Hex(value: string): Promise<string> {
  const digest = await crypto.subtle.digest('SHA-256', enc.encode(value));
  return bytesToHex(new Uint8Array(digest));
}

export async function sha256Base64Url(value: string): Promise<string> {
  const digest = await crypto.subtle.digest('SHA-256', enc.encode(value));
  return base64UrlEncode(digest);
}

export function timingSafeEqualBytes(a: Uint8Array, b: Uint8Array): boolean {
  if (a.byteLength !== b.byteLength || a.byteLength === 0) return false;
  if (typeof (crypto.subtle as unknown as { timingSafeEqual?: (x: BufferSource, y: BufferSource) => boolean }).timingSafeEqual === 'function') {
    return (crypto.subtle as unknown as { timingSafeEqual: (x: BufferSource, y: BufferSource) => boolean }).timingSafeEqual(a, b);
  }
  let diff = 0;
  for (let i = 0; i < a.length; i++) {
    diff |= a[i] ^ b[i];
  }
  return diff === 0;
}

export function timingSafeEqualHex(hexA: string, hexB: string): boolean {
  const a = hexToBytes(hexA.toLowerCase());
  const b = hexToBytes(hexB.toLowerCase());
  return timingSafeEqualBytes(a, b);
}

async function hmacSha256Hex(secret: string, message: string): Promise<string> {
  const key = await crypto.subtle.importKey(
    'raw',
    enc.encode(secret),
    { name: 'HMAC', hash: 'SHA-256' },
    false,
    ['sign']
  );
  const sig = await crypto.subtle.sign('HMAC', key, enc.encode(message));
  return bytesToHex(new Uint8Array(sig));
}

/**
 * Fast (< 0.1 ms CPU) password hashing for Cloudflare Workers Free Tier:
 * Per-user 16-byte random salt + server secret pepper via HMAC-SHA256.
 */
export async function hashPassword(password: string, pepper: string): Promise<string> {
  const salt = randomHex(16);
  const digest = await hmacSha256Hex(pepper, `${salt}:${password}`);
  return `hmac-sha256$${salt}$${digest}`;
}

export async function verifyPassword(password: string, stored: string, pepper: string): Promise<boolean> {
  const parts = stored.split('$');
  if (parts.length !== 3 || parts[0] !== 'hmac-sha256') return false;
  const [, salt, expectedHex] = parts;
  const actualHex = await hmacSha256Hex(pepper, `${salt}:${password}`);
  return timingSafeEqualHex(actualHex, expectedHex);
}

export async function hashSecretValue(value: string, pepper: string): Promise<string> {
  return hmacSha256Hex(pepper, `secret:${value}`);
}

export async function verifySuperuserPassword(password: string, expectedSha256Hex: string | undefined): Promise<boolean> {
  if (!expectedSha256Hex || !/^[0-9a-fA-F]{64}$/.test(expectedSha256Hex.trim())) {
    return false;
  }
  const actualHex = await sha256Hex(password);
  return timingSafeEqualHex(actualHex, expectedSha256Hex.trim());
}

// --- Ed25519 (EdDSA) JWT Sign / Verify ---

export interface Ed25519Jwk extends JsonWebKey {
  kty: string;
  crv: string;
  x: string;
  d?: string;
  kid?: string;
  alg?: string;
  use?: string;
}

export async function signEd25519Jwt(
  payload: Record<string, unknown>,
  privateJwkJson: string,
  expiresInSec: number
): Promise<string> {
  const jwk = JSON.parse(privateJwkJson) as Ed25519Jwk;
  const key = await crypto.subtle.importKey('jwk', jwk, { name: 'Ed25519' }, false, ['sign']);

  const now = nowSec();
  const header = {
    alg: 'EdDSA',
    typ: 'JWT',
    ...(jwk.kid ? { kid: jwk.kid } : {}),
  };
  const fullPayload = {
    iat: now,
    exp: now + expiresInSec,
    jti: crypto.randomUUID(),
    ...payload,
  };

  const encodedHeader = base64UrlEncode(enc.encode(JSON.stringify(header)));
  const encodedPayload = base64UrlEncode(enc.encode(JSON.stringify(fullPayload)));
  const signingInput = `${encodedHeader}.${encodedPayload}`;

  const signature = await crypto.subtle.sign('Ed25519', key, enc.encode(signingInput));
  return `${signingInput}.${base64UrlEncode(signature)}`;
}

export async function verifyEd25519Jwt(
  token: string,
  publicJwkJson: string
): Promise<Record<string, unknown> | null> {
  const parts = token.split('.');
  if (parts.length !== 3) return null;

  const [encodedHeader, encodedPayload, encodedSig] = parts;
  let header: { alg?: string };
  let payload: Record<string, unknown>;

  try {
    header = JSON.parse(dec.decode(base64UrlDecode(encodedHeader)));
    payload = JSON.parse(dec.decode(base64UrlDecode(encodedPayload)));
  } catch {
    return null;
  }

  if (header.alg !== 'EdDSA') return null;

  try {
    const jwk = JSON.parse(publicJwkJson) as Ed25519Jwk;
    const key = await crypto.subtle.importKey('jwk', jwk, { name: 'Ed25519' }, false, ['verify']);
    const sigBytes = base64UrlDecode(encodedSig);
    const valid = await crypto.subtle.verify(
      'Ed25519',
      key,
      sigBytes,
      enc.encode(`${encodedHeader}.${encodedPayload}`)
    );
    if (!valid) return null;
  } catch {
    return null;
  }

  const now = nowSec();
  if (typeof payload.exp === 'number' && payload.exp < now) return null;
  if (typeof payload.nbf === 'number' && payload.nbf > now) return null;
  return payload;
}

export async function getPublicJwks(env: Bindings): Promise<{ keys: Ed25519Jwk[] }> {
  const cached = await env.AUTH_CACHE.get('jwks:public', 'json').catch(() => null);
  if (cached && typeof cached === 'object' && 'keys' in cached) {
    return cached as { keys: Ed25519Jwk[] };
  }
  if (!env.JWT_PUBLIC_JWK) {
    return { keys: [] };
  }
  const jwk = JSON.parse(env.JWT_PUBLIC_JWK) as Ed25519Jwk;
  const sanitized: Ed25519Jwk = {
    kty: jwk.kty,
    crv: jwk.crv,
    x: jwk.x,
    kid: jwk.kid || 'joe-auth-ed25519',
    alg: 'EdDSA',
    use: 'sig',
  };
  const jwks = { keys: [sanitized] };
  await env.AUTH_CACHE.put('jwks:public', JSON.stringify(jwks), { expirationTtl: 3600 }).catch(() => {});
  return jwks;
}

// --- TOTP (RFC 6238 HMAC-SHA1, zero dependencies) ---

const BASE32_ALPHABET = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';

export function generateTotpSecret(byteLen = 20): string {
  const bytes = crypto.getRandomValues(new Uint8Array(byteLen));
  let bits = 0;
  let value = 0;
  let output = '';
  for (const byte of bytes) {
    value = (value << 8) | byte;
    bits += 8;
    while (bits >= 5) {
      output += BASE32_ALPHABET[(value >>> (bits - 5)) & 31];
      bits -= 5;
    }
  }
  if (bits > 0) {
    output += BASE32_ALPHABET[(value << (5 - bits)) & 31];
  }
  return output;
}

function base32Decode(input: string): Uint8Array {
  const clean = input.toUpperCase().replace(/[^A-Z2-7]/g, '');
  let bits = 0;
  let value = 0;
  const out: number[] = [];
  for (const ch of clean) {
    const idx = BASE32_ALPHABET.indexOf(ch);
    if (idx === -1) continue;
    value = (value << 5) | idx;
    bits += 5;
    if (bits >= 8) {
      out.push((value >>> (bits - 8)) & 0xff);
      bits -= 8;
    }
  }
  return new Uint8Array(out);
}

export function buildTotpUri(secret: string, email: string, issuer = 'JoeAuth'): string {
  const label = encodeURIComponent(`${issuer}:${email}`);
  return `otpauth://totp/${label}?secret=${secret}&issuer=${encodeURIComponent(issuer)}&algorithm=SHA1&digits=6&period=30`;
}

async function hotpCode(secretBytes: Uint8Array, counter: number): Promise<string> {
  const buf = new ArrayBuffer(8);
  const view = new DataView(buf);
  view.setUint32(0, Math.floor(counter / 0x100000000), false);
  view.setUint32(4, counter >>> 0, false);

  const key = await crypto.subtle.importKey(
    'raw',
    secretBytes,
    { name: 'HMAC', hash: 'SHA-1' },
    false,
    ['sign']
  );
  const sig = new Uint8Array(await crypto.subtle.sign('HMAC', key, buf));
  const offset = sig[sig.length - 1] & 0x0f;
  const binary =
    ((sig[offset] & 0x7f) << 24) |
    ((sig[offset + 1] & 0xff) << 16) |
    ((sig[offset + 2] & 0xff) << 8) |
    (sig[offset + 3] & 0xff);
  return String(binary % 1_000_000).padStart(6, '0');
}

export async function verifyTotpCode(secret: string, code: string, windowSteps = 1): Promise<boolean> {
  const cleanCode = code.trim();
  if (!/^\d{6}$/.test(cleanCode)) return false;
  const secretBytes = base32Decode(secret);
  if (secretBytes.length === 0) return false;

  const step = Math.floor(Date.now() / 1000 / 30);
  for (let delta = -windowSteps; delta <= windowSteps; delta++) {
    const candidate = await hotpCode(secretBytes, step + delta);
    if (timingSafeEqualBytes(enc.encode(candidate), enc.encode(cleanCode))) {
      return true;
    }
  }
  return false;
}
