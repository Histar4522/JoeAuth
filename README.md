# JoeAuth

Centralized Single Sign-On (SSO) and OpenID Connect / OAuth 2.0 Identity Provider built with **Hono** on **Cloudflare Workers** (`$0/mo` Free Tier).

## Stack & Features
- **Cloudflare Workers + Hono JSX**: Edge OAuth/OIDC APIs & server-rendered UI (`./src`).
- **Workers Static Assets**: Serves `./public` CSS, Bootstrap assets, and client scripts.
- **Cloudflare D1**: Relational storage for users, sessions (with `device_label` & `auth_time`), WebAuthn passkeys, 2FA recovery codes, OAuth apps, codes, device codes, refresh tokens, error logs, registration rules, and audit logs.
- **Workers KV (`AUTH_CACHE`)**: Low-write edge cache for Ed25519 JWKS, compiled registration rules, failed-login lockouts, and email cooldowns.
- **Cloudflare R2 (`MEDIA_BUCKET`)**: Stores user avatars and OAuth app logos (`256x256` PNGs).
- **Cloudflare Turnstile & Workers Rate Limiting**: Bot and brute-force protection.
- **Workers Cron Triggers**: Daily cleanup (`0 3 * * *` UTC) of expired tokens, sessions, device codes, and old OAuth app error logs.
- **Resend API**: Verification, email-change, and password-reset emails.
- **Cryptography & Auth**: `Ed25519` (`EdDSA`) JWTs with multi-key rotation (`JWT_PREVIOUS_PUBLIC_JWK`), salted `HMAC-SHA256` + pepper password hashing, constant-time Superuser login, TOTP 2FA with backup recovery codes, and zero-dependency WebAuthn passkeys.
- **OAuth 2.0 / OIDC**: Confidential and public PKCE (`S256`) clients, `prompt` / `login_hint` / `max_age`, RFC 8628 Device Authorization Grant (`/device`), RP-Initiated Logout (`/oauth/logout`), HMAC-signed lifecycle webhooks, and multi-account session switching.

## Documentation

Full integration and API docs live in **[docs/](./docs/README.md)**:
- **[Documentation Hub & Integration Workflow](./docs/README.md)**
- **[OAuth 2.0 & OIDC Endpoint Reference](./docs/oauth-oidc-reference.md)**
- **[Token Verification & Signed Webhooks](./docs/webhooks-and-verification.md)**
- **[Framework Integration Presets](./docs/framework-presets.md)**

## Local Setup

1. Install dependencies & apply local D1 migrations:
   ```bash
   npm install
   npm run db:migrate:local
   ```
2. Generate local secrets and create `.dev.vars`:
   ```bash
   npm run gen:keys -- "YourStrongSuperuserPassword"
   ```
   Copy `.dev.vars.example` to `.dev.vars`, paste the generated `SUPERUSER_PASSWORD_HASH`, `PASSWORD_PEPPER`, `JWT_PRIVATE_JWK`, `JWT_PUBLIC_JWK`, and add your `RESEND_API_KEY`.
3. Start the local dev server (and optionally the standalone OAuth test client server):
   ```bash
   npm run dev
   npm run test:server
   ```
4. Visit `http://localhost:8787/admin/login` with your Superuser password and add your first email registration rule (registration is **approve-nothing by default**).

## Testing & Verification

```bash
npm run typecheck
npm test
npx wrangler deploy --dry-run
```

## Production Deployment

1. Create your Cloudflare D1 database, KV namespace, and R2 bucket, then update `wrangler.jsonc`:
   ```bash
   npx wrangler d1 create joe-auth-db
   npx wrangler kv namespace create AUTH_CACHE
   npx wrangler r2 bucket create joe-auth-media
   ```
2. Update `ISSUER_URL`, `EMAIL_FROM`, and `TURNSTILE_SITE_KEY` in `wrangler.jsonc`.
3. Apply remote D1 migrations & upload secrets:
   ```bash
   npm run db:migrate:remote
   npx wrangler secret put SUPERUSER_PASSWORD_HASH
   npx wrangler secret put PASSWORD_PEPPER
   npx wrangler secret put JWT_PRIVATE_JWK
   npx wrangler secret put JWT_PUBLIC_JWK
   npx wrangler secret put TURNSTILE_SECRET_KEY
   npx wrangler secret put RESEND_API_KEY
   ```
4. Deploy:
   ```bash
   npm run deploy
   ```
