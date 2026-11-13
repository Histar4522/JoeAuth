# JoeAuth

Centralized Single Sign-On (SSO) and OpenID Connect / OAuth 2.0 Identity Provider for the **Joe Universe**, built with **Hono** on **Cloudflare Workers** (`$0/mo` Free Tier).

## Stack & Cloudflare Free-Tier Services
- **Cloudflare Workers + Hono JSX**: Edge API & server-rendered HTML UI (`./src`).
- **Workers Static Assets**: Serves `./public/styles.css` and `./public/app.js`.
- **Cloudflare D1**: Relational storage for users, sessions, developer applications, OAuth apps, codes, refresh tokens, registration rules, and audit logs.
- **Workers KV (`AUTH_CACHE`)**: Low-write edge cache for Ed25519 JWKS & compiled registration rules.
- **Cloudflare Turnstile & Workers Rate Limiting**: Bot and brute-force protection.
- **Workers Cron Triggers**: Daily cleanup (`0 3 * * *` UTC) of expired tokens/sessions.
- **Resend API**: Verification and password-reset emails.
- **Cryptography**: `Ed25519` (`EdDSA`) JWTs, `PBKDF2`-free fast salted `HMAC-SHA256` + server pepper password hashing (`< 0.1 ms` CPU), and `SHA-256` constant-time Superuser login.

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
3. Start local dev server:
   ```bash
   npm run dev
   ```
4. Visit `http://localhost:8787/admin/login` with your Superuser password and add your first email registration rule (registration is **approve-nothing by default**).

## Testing & Verification

```bash
npm run typecheck
npm test
npx wrangler deploy --dry-run
```

## Production Deployment

1. Create your Cloudflare D1 database and KV namespace, then update `database_id` and `id` in `wrangler.jsonc`:
   ```bash
   npx wrangler d1 create joe-auth-db
   npx wrangler kv namespace create AUTH_CACHE
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
