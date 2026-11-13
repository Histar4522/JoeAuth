import path from 'node:path';
import { createHash, generateKeyPairSync, randomBytes } from 'node:crypto';
import { defineConfig } from 'vitest/config';
import { cloudflareTest, readD1Migrations } from '@cloudflare/vitest-pool-workers';

export default defineConfig(async () => {
  const migrations = await readD1Migrations(path.join(import.meta.dirname, 'migrations'));
  const kp = generateKeyPairSync('ed25519');
  const priv = kp.privateKey.export({ format: 'jwk' }) as Record<string, string>;
  const pub = kp.publicKey.export({ format: 'jwk' }) as Record<string, string>;
  priv.kid = 'test-ed25519';
  priv.alg = 'EdDSA';
  priv.use = 'sig';
  pub.kid = 'test-ed25519';
  pub.alg = 'EdDSA';
  pub.use = 'sig';

  const superuserHash = createHash('sha256').update('test-superuser-pass', 'utf8').digest('hex');
  const pepper = randomBytes(32).toString('hex');

  return {
    plugins: [
      cloudflareTest({
        wrangler: { configPath: './wrangler.jsonc' },
        miniflare: {
          compatibilityDate: '2026-08-22',
          bindings: {
            TEST_MIGRATIONS: migrations,
            SUPERUSER_PASSWORD_HASH: superuserHash,
            PASSWORD_PEPPER: pepper,
            JWT_PRIVATE_JWK: JSON.stringify(priv),
            JWT_PUBLIC_JWK: JSON.stringify(pub),
            TURNSTILE_SECRET_KEY: '1x0000000000000000000000000000000AA',
            RESEND_API_KEY: 're_test_key',
          },
        },
      }),
    ],
  };
});
