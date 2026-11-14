# OAuth 2.0 & OIDC Interface Reference

All examples below use `https://auth.example.com` as the base issuer (`ISSUER_URL`).

---

## `GET /.well-known/openid-configuration`

- **Auth:** Public · **CORS:** `*`
- **Behavior:** Returns the standard OpenID Connect Discovery metadata document.

```json
{
  "issuer": "https://auth.example.com",
  "authorization_endpoint": "https://auth.example.com/oauth/authorize",
  "token_endpoint": "https://auth.example.com/api/oauth/token",
  "device_authorization_endpoint": "https://auth.example.com/api/oauth/device_code",
  "userinfo_endpoint": "https://auth.example.com/api/oauth/userinfo",
  "introspection_endpoint": "https://auth.example.com/api/oauth/introspect",
  "revocation_endpoint": "https://auth.example.com/api/oauth/revoke",
  "end_session_endpoint": "https://auth.example.com/oauth/logout",
  "jwks_uri": "https://auth.example.com/.well-known/jwks.json",
  "response_types_supported": ["code"],
  "grant_types_supported": [
    "authorization_code",
    "refresh_token",
    "client_credentials",
    "urn:ietf:params:oauth:grant-type:device_code"
  ],
  "subject_types_supported": ["public"],
  "id_token_signing_alg_values_supported": ["EdDSA"],
  "token_endpoint_auth_methods_supported": ["client_secret_post", "client_secret_basic", "none"],
  "scopes_supported": ["openid", "profile", "email", "offline_access"],
  "code_challenge_methods_supported": ["S256"],
  "prompt_values_supported": ["none", "login", "consent", "select_account"],
  "claims_supported": [
    "sub", "iss", "aud", "exp", "iat", "auth_time",
    "name", "picture", "email", "email_verified", "role", "developer_status"
  ]
}
```

---

## `GET /.well-known/jwks.json`

- **Auth:** Public · **Cache:** `public, max-age=300`
- **Behavior:** Exposes the active Ed25519 (`EdDSA`) public key—plus an optional previous public key (`JWT_PREVIOUS_PUBLIC_JWK`) during zero-downtime key rotation—so services can verify `access_token` and `id_token` signatures locally.

```json
{
  "keys": [
    { "kty": "OKP", "crv": "Ed25519", "x": "<base64url>", "kid": "<key-id>", "alg": "EdDSA", "use": "sig" }
  ]
}
```

---

## `GET /oauth/authorize` & `POST /oauth/authorize`

- **Auth:** User session cookie (redirects to `/login?return_to=...` when unauthenticated unless `prompt=none`).
- **Behavior:** Validates that `client_id` belongs to an `approved` app and that `redirect_uri` matches one of the app's registered URIs **exactly**. Invalid `client_id` or `redirect_uri` renders a `400` error page directly (never redirects to an unverified URI). Public clients (`client_type = "public"`) require `code_challenge` with `code_challenge_method=S256`.

| Query Parameter | Required | Description |
| :--- | :--- | :--- |
| `client_id` | Yes | Application ID (`ja_...`) |
| `redirect_uri` | Yes | Exact match of a registered redirect URI |
| `response_type` | No | Must be `code` (default `code`) |
| `scope` | No | Space-delimited scopes (default `openid profile email`) |
| `state` | Recommended | Opaque CSRF/state string echoed back on redirect |
| `code_challenge` | Required for Public clients | Base64URL-encoded SHA-256 of `code_verifier` |
| `code_challenge_method` | If PKCE | Must be `S256` |
| `nonce` | No | OIDC replay-protection value embedded into `id_token` |
| `prompt` | No | `none`, `login`, `consent`, or `select_account` |
| `login_hint` | No | Pre-fills the sign-in email field |
| `max_age` | No | Maximum authentication age in seconds before forcing re-authentication |

**Redirects (`302 Found` to `redirect_uri`):**
- Approved: `{redirect_uri}?code=jac_...&state={state}` (`60s` single-use code)
- Denied: `{redirect_uri}?error=access_denied&state={state}`
- Prompt/session failure: `{redirect_uri}?error=login_required|consent_required|interaction_required&state={state}`

---

## `POST /api/oauth/token`

- **Rate Limit:** `60 req / 60s` per IP · **Content-Type:** `application/x-www-form-urlencoded` or `application/json`
- **Client Auth:** HTTP Basic (`client_id:client_secret`) or body fields (`client_id` alone is accepted for `public` clients using `authorization_code` + PKCE or `device_code`).

### Supported `grant_type` Values

- **`authorization_code`**: Atomically consumes the single-use `code` (`60s` TTL), verifies `redirect_uri`, enforces PKCE `S256(code_verifier) === code_challenge` (mandatory for `public` clients; confidential clients validate `client_secret` unless PKCE was used, and validate both when both are provided), and confirms the user is `active`.
- **`refresh_token`**: Validates `refresh_token` against `app_id` and rotates it. Submitting an already-revoked refresh token immediately revokes the entire token family (reuse detection).
- **`client_credentials`**: Requires confidential `client_id` + `client_secret`. Issues a 1-hour Ed25519 M2M `access_token` (`token_type: "app"`, `sub: client_id`).
- **`urn:ietf:params:oauth:grant-type:device_code`**: Exchanges an approved `device_code` for `access_token`, `id_token`, and optional `refresh_token`.

```json
// 200 OK (authorization_code / refresh_token / device_code)
{
  "token_type": "Bearer",
  "expires_in": 900,
  "scope": "openid profile email offline_access",
  "access_token": "eyJ...",
  "id_token": "eyJ...",
  "refresh_token": "jar_..."
}
```

```json
// 200 OK (client_credentials)
{
  "token_type": "Bearer",
  "expires_in": 3600,
  "scope": "app:service",
  "access_token": "eyJ..."
}
```

```json
// 400 / 401 Error
{
  "error": "invalid_request | invalid_client | invalid_grant | unsupported_grant_type | authorization_pending | slow_down | expired_token",
  "error_description": "Human-readable reason"
}
```

---

## `POST /api/oauth/device_code` & `GET /device`

- **Rate Limit:** `60 req / 60s` per IP · **Auth:** `client_id` (plus `client_secret` for confidential clients if provided)
- **Behavior:** Implements RFC 8628 Device Authorization Grant (`10m` TTL). Returns `device_code`, `user_code` (`XXXX-XXXX`), `verification_uri` (`https://auth.example.com/device`), `verification_uri_complete`, `expires_in`, and `interval` (5 seconds).

---

## `GET /api/oauth/userinfo`

- **Auth:** `Authorization: Bearer <access_token>` (user token only; M2M `token_type: "app"` tokens are rejected)
- **Behavior:** Verifies the Ed25519 signature (against active and previous JWKS keys) and expiration, verifies the user is `active`, and returns live claims filtered by token `scope`.

```json
{
  "sub": "user-uuid",
  "name": "Joe Doe",
  "picture": "https://auth.example.com/media/avatars/user-uuid?v=1",
  "role": "user",
  "developer_status": "approved",
  "email": "joe@example.com",
  "email_verified": true
}
```

---

## `POST /api/oauth/introspect`

- **Auth:** Client credentials (`client_id` + `client_secret`, HTTP Basic or body) · **Rate Limit:** `60 req / 60s`
- **Behavior:** RFC 7662 token introspection. Authenticates the calling app (`401 invalid_client` if invalid), verifies the submitted token signature and expiration (including rotated keys), and for user tokens checks that the user is `active`. Returns `{ "active": false }` with HTTP `200` for invalid, expired, or suspended-user tokens.

---

## `POST /api/oauth/revoke`

- **Rate Limit:** `60 req / 60s` · **Body:** `token=<refresh_token>`
- **Behavior:** Marks the submitted `refresh_token` as revoked. Idempotent (`200 { "ok": true }`).

---

## `GET /oauth/logout` & `POST /oauth/logout`

- **Behavior:** OIDC RP-Initiated Logout (`end_session_endpoint`). Accepts `id_token_hint`, `client_id`, optional `state`, and `post_logout_redirect_uri`.
- When `id_token_hint` validates and `post_logout_redirect_uri` matches one of the app's registered `post_logout_redirect_uris`, signs out the active session immediately and redirects to `post_logout_redirect_uri` (appending `state` if given).
- When `id_token_hint` is omitted or unverified, presents a CSRF-protected logout confirmation prompt before signing out and redirecting.

---

## JWT Claims Reference (Ed25519 / `EdDSA`)

| Token | TTL | Claims Included |
| :--- | :--- | :--- |
| User `access_token` | `900s` (15m) | `iss`, `sub` (user ID), `aud` (`client_id`), `client_id`, `scope`, `token_type: "user"`, `role`, `iat`, `exp`, `jti` |
| OIDC `id_token` | `3600s` (1h) | `iss`, `sub`, `aud`, `auth_time`, `nonce` (if given), `name` / `picture` / `role` / `developer_status` (`profile`), `email` / `email_verified` (`email`), `iat`, `exp`, `jti` |
| App `access_token` (`client_credentials`) | `3600s` (1h) | `iss`, `sub` (`client_id`), `aud` (`iss`), `client_id`, `app_id`, `owner_user_id`, `scope`, `token_type: "app"`, `iat`, `exp`, `jti` |
