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

export async function hmacSha256Hex(secret: string, message: string): Promise<string> {
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

export function normalizeRecoveryCode(code: string): string {
  return code.trim().toUpperCase().replace(/[^A-Z0-9]/g, '');
}

const RECOVERY_ALPHABET = '23456789ABCDEFGHJKLMNPQRSTUVWXYZ';

export function generateRecoveryCodes(count = 8): string[] {
  const codes: string[] = [];
  for (let i = 0; i < count; i++) {
    const rand = crypto.getRandomValues(new Uint8Array(8));
    let raw = '';
    for (let j = 0; j < 8; j++) {
      raw += RECOVERY_ALPHABET[rand[j] % RECOVERY_ALPHABET.length];
    }
    codes.push(`${raw.slice(0, 4)}-${raw.slice(4)}`);
  }
  return codes;
}

export async function signWebhookPayload(secret: string, timestamp: number, body: string): Promise<string> {
  const sig = await hmacSha256Hex(secret, `${timestamp}.${body}`);
  return `t=${timestamp},v1=${sig}`;
}

async function importAesKey(secret: string): Promise<CryptoKey> {
  const digest = await crypto.subtle.digest('SHA-256', enc.encode(`joeauth-enc:${secret}`));
  return crypto.subtle.importKey('raw', digest, 'AES-GCM', false, ['encrypt', 'decrypt']);
}

export async function encryptSecretValue(plaintext: string, masterSecret: string): Promise<string> {
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const key = await importAesKey(masterSecret);
  const cipherBuf = await crypto.subtle.encrypt({ name: 'AES-GCM', iv }, key, enc.encode(plaintext));
  return `aesgcm$${bytesToHex(iv)}$${bytesToHex(new Uint8Array(cipherBuf))}`;
}

export async function decryptSecretValue(ciphertext: string, masterSecret: string): Promise<string | null> {
  const parts = ciphertext.split('$');
  if (parts.length !== 3 || parts[0] !== 'aesgcm') return null;
  try {
    const iv = hexToBytes(parts[1]);
    const ct = hexToBytes(parts[2]);
    if (iv.length !== 12 || ct.length === 0) return null;
    const key = await importAesKey(masterSecret);
    const plainBuf = await crypto.subtle.decrypt({ name: 'AES-GCM', iv }, key, ct);
    return dec.decode(plainBuf);
  } catch {
    return null;
  }
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

function deriveKeyId(jwk: Ed25519Jwk): string {
  return jwk.kid || (jwk.x ? `ed25519-${jwk.x.slice(0, 8)}` : 'joe-auth-ed25519');
}

function sanitizePublicJwk(jwk: Ed25519Jwk): Ed25519Jwk {
  return {
    kty: jwk.kty,
    crv: jwk.crv,
    x: jwk.x,
    kid: deriveKeyId(jwk),
    alg: 'EdDSA',
    use: 'sig',
  };
}

function parseConfiguredPublicJwks(env: Bindings): Ed25519Jwk[] {
  const keys: Ed25519Jwk[] = [];
  const pushFromJson = (rawJson: string | undefined) => {
    if (!rawJson) return;
    try {
      const parsed = JSON.parse(rawJson) as Ed25519Jwk | Ed25519Jwk[];
      const list = Array.isArray(parsed) ? parsed : [parsed];
      for (const item of list) {
        if (item && item.kty === 'OKP' && item.crv === 'Ed25519' && item.x) {
          keys.push(sanitizePublicJwk(item));
        }
      }
    } catch {}
  };
  pushFromJson(env.JWT_PUBLIC_JWK);
  pushFromJson(env.JWT_PREVIOUS_PUBLIC_JWK);
  // Deduplicate by kid
  const seen = new Set<string>();
  return keys.filter((k) => {
    const id = k.kid || k.x;
    if (seen.has(id)) return false;
    seen.add(id);
    return true;
  });
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
    kid: deriveKeyId(jwk),
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

async function verifyJwtWithKeys(
  token: string,
  candidateKeys: Ed25519Jwk[],
  opts: { ignoreExpiration?: boolean } = {}
): Promise<Record<string, unknown> | null> {
  const parts = token.split('.');
  if (parts.length !== 3 || candidateKeys.length === 0) return null;

  const [encodedHeader, encodedPayload, encodedSig] = parts;
  let header: { alg?: string; kid?: string };
  let payload: Record<string, unknown>;

  try {
    header = JSON.parse(dec.decode(base64UrlDecode(encodedHeader)));
    payload = JSON.parse(dec.decode(base64UrlDecode(encodedPayload)));
  } catch {
    return null;
  }

  if (header.alg !== 'EdDSA') return null;

  const orderedKeys = header.kid
    ? [
        ...candidateKeys.filter((k) => k.kid === header.kid),
        ...candidateKeys.filter((k) => k.kid !== header.kid),
      ]
    : candidateKeys;

  const sigBytes = base64UrlDecode(encodedSig);
  const inputBytes = enc.encode(`${encodedHeader}.${encodedPayload}`);
  let verified = false;
  for (const jwk of orderedKeys) {
    try {
      const key = await crypto.subtle.importKey('jwk', jwk, { name: 'Ed25519' }, false, ['verify']);
      if (await crypto.subtle.verify('Ed25519', key, sigBytes, inputBytes)) {
        verified = true;
        break;
      }
    } catch {}
  }
  if (!verified) return null;

  const now = nowSec();
  if (!opts.ignoreExpiration && typeof payload.exp === 'number' && payload.exp < now) return null;
  if (typeof payload.nbf === 'number' && payload.nbf > now) return null;
  return payload;
}

export async function verifyEd25519Jwt(
  token: string,
  publicJwkJson: string,
  opts: { ignoreExpiration?: boolean } = {}
): Promise<Record<string, unknown> | null> {
  try {
    const parsed = JSON.parse(publicJwkJson) as Ed25519Jwk | Ed25519Jwk[];
    const keys = (Array.isArray(parsed) ? parsed : [parsed]).map(sanitizePublicJwk);
    return verifyJwtWithKeys(token, keys, opts);
  } catch {
    return null;
  }
}

export async function verifyEd25519JwtWithEnv(
  token: string,
  env: Bindings,
  opts: { ignoreExpiration?: boolean } = {}
): Promise<Record<string, unknown> | null> {
  return verifyJwtWithKeys(token, parseConfiguredPublicJwks(env), opts);
}

export async function getPublicJwks(env: Bindings): Promise<{ keys: Ed25519Jwk[] }> {
  return { keys: parseConfiguredPublicJwks(env) };
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
