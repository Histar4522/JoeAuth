#!/usr/bin/env node
import { createHash, randomBytes, webcrypto } from 'node:crypto';

const subtle = webcrypto.subtle;

async function main() {
  const superuserPassword = process.argv[2] || 'change-me-superuser-password';
  const superuserHash = createHash('sha256').update(superuserPassword, 'utf8').digest('hex');
  const pepper = randomBytes(32).toString('hex');

  const keyPair = await subtle.generateKey({ name: 'Ed25519' }, true, ['sign', 'verify']);
  const privateJwk = await subtle.exportKey('jwk', keyPair.privateKey);
  const publicJwk = await subtle.exportKey('jwk', keyPair.publicKey);
  const kid = 'ja-' + randomBytes(6).toString('hex');

  privateJwk.kid = kid;
  privateJwk.alg = 'EdDSA';
  privateJwk.use = 'sig';

  publicJwk.kid = kid;
  publicJwk.alg = 'EdDSA';
  publicJwk.use = 'sig';

  console.log('# Generated JoeAuth local secrets (.dev.vars)');
  if (!process.argv[2]) {
    console.log(`# WARNING: Using default password "${superuserPassword}". Pass your own: npm run gen:keys -- "YourStrongPassword"`);
  }
  console.log(`SUPERUSER_PASSWORD_HASH=${superuserHash}`);
  console.log(`PASSWORD_PEPPER=${pepper}`);
  console.log(`JWT_PRIVATE_JWK=${JSON.stringify(privateJwk)}`);
  console.log(`JWT_PUBLIC_JWK=${JSON.stringify(publicJwk)}`);
  console.log('TURNSTILE_SECRET_KEY=1x0000000000000000000000000000000AA');
  console.log('RESEND_API_KEY=');
}

main().catch((err) => {
  console.error(err);
  process.exit(1);
});
