# JoeAuth Developer Documentation

JoeAuth is an OAuth 2.0 + PKCE (`S256`) + OpenID Connect (OIDC) Identity Provider using **Ed25519** (`EdDSA`) JWTs, running on Cloudflare Workers.

## Documentation Index

- **[OAuth 2.0 & OIDC Reference](./oauth-oidc-reference.md)** — Discovery metadata, JWKS multi-key rotation, authorization parameters (`prompt`, `login_hint`, `max_age`), token grants (`authorization_code`, `refresh_token`, `client_credentials`, `device_code`), `userinfo`, `introspect`, `revoke`, `end_session_endpoint`, and JWT claims.
- **[Token Verification & Webhooks](./webhooks-and-verification.md)** — Token exchange, M2M `client_credentials`, introspection, zero-dependency local Ed25519 JWT verification (Cloudflare Workers & Python), and `X-JoeAuth-Signature` HMAC-SHA256 webhook verification.
- **[Framework Integration Presets](./framework-presets.md)** — Ready-to-use configuration snippets for Auth.js / NextAuth v5, Hono (`oauth4webapi`), FastAPI (`Authlib`), Go (`go-oidc`), and Public SPAs (PKCE `S256`).

---

## Integration Workflow

1. **Register an account** at `/register` (gated by admin-configured email regex rules — approve-nothing by default).
2. **Apply for developer access** at `/developer` and wait for Admin or Superuser approval.
3. **Create an OAuth application** in `/developer` (activated immediately):
   - Choose **`confidential`** (server-side backend with a one-time `client_secret`) or **`public`** (SPA / mobile / CLI app without a `client_secret`, where PKCE `S256` is mandatory).
   - Register exact `redirect_uris` and optional `post_logout_redirect_uris`.
   - Optionally upload a `256x256` PNG app logo, set `description` / `privilegeDescription`, or configure an `https://` lifecycle webhook URL.
4. **Authenticate users** via `/oauth/authorize` with PKCE (`S256`) (or via Device Authorization Grant at `/api/oauth/device_code` + `/device`), exchange codes at `/api/oauth/token`, and verify tokens via `/.well-known/jwks.json` or `/api/oauth/introspect`.
5. **Debug & inspect** integration errors in `/developer` using the per-app OAuth Error Logs viewer and inline browser Ed25519 JWT Inspector, or use the local OAuth test client (`npm run test:server` on `http://127.0.0.1:8788`).

## Supported Scopes

Scopes are fixed globally to keep consent clear and predictable:

| Scope | Claims / Behavior |
| :--- | :--- |
| `openid` | Returns user identifier `sub` and issues an OIDC `id_token` |
| `profile` | Includes `name`, `picture` (`256x256` PNG or generated SVG avatar URL), `role`, and `developer_status` |
| `email` | Includes `email` and `email_verified` |
| `offline_access` | Issues a 30-day rotating opaque `refresh_token` |
