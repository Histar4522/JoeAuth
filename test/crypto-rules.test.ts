import { describe, expect, it } from 'vitest';
import {
  buildTotpUri,
  decryptSecretValue,
  encryptSecretValue,
  generateRecoveryCodes,
  generateTotpSecret,
  hashPassword,
  hmacSha256Hex,
  normalizeRecoveryCode,
  sha256Hex,
  signEd25519Jwt,
  signWebhookPayload,
  verifyEd25519Jwt,
  verifyEd25519JwtWithEnv,
  verifyPassword,
  verifySuperuserPassword,
} from '../src/lib/crypto';
import { evaluateRegistrationEmail, validateRulePattern } from '../src/lib/rules';
import { MILD_AVATAR_PALETTE, pickRandomMildColor, renderInitialAvatarSvg, validatePng256 } from '../src/lib/images';
import { isSafeWebhookUrl } from '../src/lib/webhooks';
import { parseUserAgentSummary } from '../src/lib/session';
import type { Bindings, RegistrationRuleRow } from '../src/types';

describe('Crypto utilities', () => {
  it('hashes and verifies passwords with salt + pepper via HMAC-SHA256', async () => {
    const pepper = 'super-secret-pepper';
    const hash1 = await hashPassword('CorrectHorseBattery99', pepper);
    const hash2 = await hashPassword('CorrectHorseBattery99', pepper);

    expect(hash1.startsWith('hmac-sha256$')).toBe(true);
    expect(hash1).not.toBe(hash2);
    expect(await verifyPassword('CorrectHorseBattery99', hash1, pepper)).toBe(true);
    expect(await verifyPassword('WrongPassword', hash1, pepper)).toBe(false);
    expect(await verifyPassword('CorrectHorseBattery99', hash1, 'wrong-pepper')).toBe(false);
  });

  it('verifies superuser SHA-256 hex digest in constant time', async () => {
    const expected = await sha256Hex('MySuperSecretAdminPass!');
    expect(await verifySuperuserPassword('MySuperSecretAdminPass!', expected)).toBe(true);
    expect(await verifySuperuserPassword('wrong', expected)).toBe(false);
    expect(await verifySuperuserPassword('MySuperSecretAdminPass!', 'not-a-sha256')).toBe(false);
  });

  it('signs and verifies Ed25519 JWTs', async () => {
    const kp = (await crypto.subtle.generateKey({ name: 'Ed25519' }, true, ['sign', 'verify'])) as CryptoKeyPair;
    const priv = JSON.stringify({ ...(await crypto.subtle.exportKey('jwk', kp.privateKey)), kid: 'k1' });
    const pub = JSON.stringify({ ...(await crypto.subtle.exportKey('jwk', kp.publicKey)), kid: 'k1' });

    const token = await signEd25519Jwt({ sub: 'user-1', role: 'admin' }, priv, 300);
    const claims = await verifyEd25519Jwt(token, pub);
    expect(claims).not.toBeNull();
    expect(claims?.sub).toBe('user-1');
    expect(claims?.role).toBe('admin');

    const tampered = token.slice(0, -4) + 'AAAA';
    expect(await verifyEd25519Jwt(tampered, pub)).toBeNull();
  });

  it('generates valid TOTP base32 secrets and otpauth URIs', () => {
    const secret = generateTotpSecret();
    expect(secret).toMatch(/^[A-Z2-7]+$/);
    const uri = buildTotpUri(secret, 'joe@example.com', 'JoeAuth');
    expect(uri).toContain('otpauth://totp/JoeAuth');
    expect(uri).toContain(`secret=${secret}`);
  });
});

describe('Registration email regex rules', () => {
  it('denies everything by default when no rules exist', () => {
    const res = evaluateRegistrationEmail('joe@example.com', []);
    expect(res.allowed).toBe(false);
  });

  it('evaluates ordered priority rules (deny overrides lower-priority allow)', () => {
    const rules: RegistrationRuleRow[] = [
      {
        id: 'r1',
        rule_type: 'deny',
        pattern: '\\+[^@]*@',
        description: 'Block +aliases',
        priority: 10,
        is_active: 1,
        created_by: 'superuser',
        created_at: 0,
      },
      {
        id: 'r2',
        rule_type: 'allow',
        pattern: '^[^@]+@example\\.com$',
        description: 'Allow domain',
        priority: 100,
        is_active: 1,
        created_by: 'superuser',
        created_at: 0,
      },
    ];

    expect(evaluateRegistrationEmail('joe@example.com', rules).allowed).toBe(true);
    expect(evaluateRegistrationEmail('joe+spam@example.com', rules).allowed).toBe(false);
    expect(evaluateRegistrationEmail('other@invalid.example', rules).allowed).toBe(false);
  });

  it('rejects nested-quantifier ReDoS patterns', () => {
    expect(validateRulePattern('(a+)+$').valid).toBe(false);
    expect(validateRulePattern('^[^@]+@example\\.com$').valid).toBe(true);
  });
});

function buildTestPng(width: number, height: number, size = 48): Uint8Array {
  const buf = new Uint8Array(Math.max(size, 33));
  buf.set([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a], 0);
  const view = new DataView(buf.buffer);
  view.setUint32(8, 13, false);
  buf.set([0x49, 0x48, 0x44, 0x52], 12);
  view.setUint32(16, width, false);
  view.setUint32(20, height, false);
  return buf;
}

describe('Image validation & initial avatar helpers', () => {
  it('accepts 256x256 PNG <= 128 KiB and rejects non-PNG, wrong dimensions, and oversized files', () => {
    expect(validatePng256(buildTestPng(256, 256, 64)).ok).toBe(true);
    expect(validatePng256(buildTestPng(128, 256, 64)).ok).toBe(false);
    expect(validatePng256(buildTestPng(256, 256, 131073)).ok).toBe(false);
    expect(validatePng256(new Uint8Array([0xff, 0xd8, 0xff, 0xe0, 1, 2, 3])).ok).toBe(false);
  });

  it('generates mild palette colors and SVG initial avatars', () => {
    const color = pickRandomMildColor();
    expect(MILD_AVATAR_PALETTE.some((p) => p.bg === color)).toBe(true);
    const svg = renderInitialAvatarSvg('Joe Doe', color);
    expect(svg).toContain('width="256"');
    expect(svg).toContain(color);
    expect(svg).toContain('>J<');
  });
});

describe('Security rotation, recovery codes, encryption, and SSRF protection', () => {
  it('supports multi-key JWKS rotation & ignoreExpiration verification', async () => {
    const oldKp = (await crypto.subtle.generateKey({ name: 'Ed25519' }, true, ['sign', 'verify'])) as CryptoKeyPair;
    const newKp = (await crypto.subtle.generateKey({ name: 'Ed25519' }, true, ['sign', 'verify'])) as CryptoKeyPair;
    const oldPriv = JSON.stringify({ ...(await crypto.subtle.exportKey('jwk', oldKp.privateKey)), kid: 'old-k' });
    const oldPub = JSON.stringify({ ...(await crypto.subtle.exportKey('jwk', oldKp.publicKey)), kid: 'old-k' });
    const newPub = JSON.stringify({ ...(await crypto.subtle.exportKey('jwk', newKp.publicKey)), kid: 'new-k' });

    const token = await signEd25519Jwt({ sub: 'user-old' }, oldPriv, 300);
    const fakeEnv = {
      JWT_PUBLIC_JWK: newPub,
      JWT_PREVIOUS_PUBLIC_JWK: oldPub,
    } as unknown as Bindings;

    const claims = await verifyEd25519JwtWithEnv(token, fakeEnv);
    expect(claims?.sub).toBe('user-old');

    const expiredToken = await signEd25519Jwt({ sub: 'user-exp' }, oldPriv, -60);
    expect(await verifyEd25519JwtWithEnv(expiredToken, fakeEnv)).toBeNull();
    expect((await verifyEd25519JwtWithEnv(expiredToken, fakeEnv, { ignoreExpiration: true }))?.sub).toBe('user-exp');
  });

  it('generates and normalizes backup recovery codes', () => {
    const codes = generateRecoveryCodes(8);
    expect(codes).toHaveLength(8);
    for (const c of codes) {
      expect(c).toMatch(/^[A-Z2-9]{4}-[A-Z2-9]{4}$/);
      expect(normalizeRecoveryCode(c.toLowerCase())).toBe(c.replace('-', ''));
    }
  });

  it('encrypts and decrypts webhook secrets with AES-256-GCM and computes HMAC signatures', async () => {
    const enc = await encryptSecretValue('whsec_secret_123', 'master-pepper');
    expect(await decryptSecretValue(enc, 'master-pepper')).toBe('whsec_secret_123');
    expect(await decryptSecretValue(enc, 'wrong-pepper')).toBeNull();

    const sig = await signWebhookPayload('whsec_secret_123', 1700000000, '{"event":"test"}');
    const hex = await hmacSha256Hex('whsec_secret_123', '1700000000.{"event":"test"}');
    expect(sig).toBe(`t=1700000000,v1=${hex}`);
  });

  it('blocks private, loopback, link-local, and non-HTTPS webhook URLs', () => {
    expect(isSafeWebhookUrl('https://hooks.example.com/events')).toBe(true);
    expect(isSafeWebhookUrl('http://hooks.example.com/events')).toBe(false);
    expect(isSafeWebhookUrl('https://localhost/hook')).toBe(false);
    expect(isSafeWebhookUrl('https://127.0.0.1/hook')).toBe(false);
    expect(isSafeWebhookUrl('https://169.254.169.254/latest/meta-data')).toBe(false);
    expect(isSafeWebhookUrl('https://10.0.0.1/hook')).toBe(false);
    expect(isSafeWebhookUrl('https://192.168.1.50/hook')).toBe(false);
    expect(isSafeWebhookUrl('https://[::1]/hook')).toBe(false);
    expect(isSafeWebhookUrl('https://[fc00::1]/hook')).toBe(false);
    expect(isSafeWebhookUrl('https://service.local/hook')).toBe(false);
  });

  it('formats readable device summaries from User-Agent headers', () => {
    expect(
      parseUserAgentSummary('Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/128.0.0.0 Safari/537.36')
    ).toBe('Chrome on Windows');
    expect(parseUserAgentSummary('')).toBe('Unknown device');
  });
});
