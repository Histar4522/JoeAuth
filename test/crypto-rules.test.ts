import { describe, expect, it } from 'vitest';
import {
  buildTotpUri,
  generateTotpSecret,
  hashPassword,
  sha256Hex,
  signEd25519Jwt,
  verifyEd25519Jwt,
  verifyPassword,
  verifySuperuserPassword,
} from '../src/lib/crypto';
import { evaluateRegistrationEmail, validateRulePattern } from '../src/lib/rules';
import type { RegistrationRuleRow } from '../src/types';

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
    const uri = buildTotpUri(secret, 'joe@joeuniverse.com', 'JoeAuth');
    expect(uri).toContain('otpauth://totp/JoeAuth');
    expect(uri).toContain(`secret=${secret}`);
  });
});

describe('Registration email regex rules', () => {
  it('denies everything by default when no rules exist', () => {
    const res = evaluateRegistrationEmail('joe@joeuniverse.com', []);
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
        pattern: '^[^@]+@joeuniverse\\.com$',
        description: 'Allow domain',
        priority: 100,
        is_active: 1,
        created_by: 'superuser',
        created_at: 0,
      },
    ];

    expect(evaluateRegistrationEmail('alice@joeuniverse.com', rules).allowed).toBe(true);
    expect(evaluateRegistrationEmail('alice+spam@joeuniverse.com', rules).allowed).toBe(false);
    expect(evaluateRegistrationEmail('bob@gmail.com', rules).allowed).toBe(false);
  });

  it('rejects nested-quantifier ReDoS patterns', () => {
    expect(validateRulePattern('(a+)+$').valid).toBe(false);
    expect(validateRulePattern('^[^@]+@joeuniverse\\.com$').valid).toBe(true);
  });
});
