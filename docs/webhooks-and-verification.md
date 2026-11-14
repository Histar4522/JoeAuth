# Token Exchange, Local Verification & Webhooks

All examples below use `https://auth.example.com` as the JoeAuth issuer URL.

---

## Token Exchange (`authorization_code`)

```js
const resp = await fetch('https://auth.example.com/api/oauth/token', {
  method: 'POST',
  headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
  body: new URLSearchParams({
    grant_type: 'authorization_code',
    client_id: 'YOUR_CLIENT_ID',
    client_secret: 'YOUR_CLIENT_SECRET', // Omit for public clients using PKCE
    code: callbackCode,
    redirect_uri: 'https://app.example.com/callback',
    code_verifier: pkceVerifier,         // Required for PKCE & all public clients
  }),
});
const tokens = await resp.json();
```

## M2M Service Token (`client_credentials`)

```js
const resp = await fetch('https://auth.example.com/api/oauth/token', {
  method: 'POST',
  headers: {
    'Authorization': 'Basic ' + btoa('YOUR_CLIENT_ID:YOUR_CLIENT_SECRET'),
    'Content-Type': 'application/x-www-form-urlencoded',
  },
  body: new URLSearchParams({
    grant_type: 'client_credentials',
    scope: 'app:service',
  }),
});
const { access_token, expires_in } = await resp.json();
```

## Server-Side Introspection (`/api/oauth/introspect`)

```js
const check = await fetch('https://auth.example.com/api/oauth/introspect', {
  method: 'POST',
  headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
  body: new URLSearchParams({
    client_id: 'YOUR_CLIENT_ID',
    client_secret: 'YOUR_CLIENT_SECRET',
    token: bearerAccessToken,
  }),
});
const result = await check.json();
// result.active === true -> result.sub, result.scope, result.user
```

---

## Local Ed25519 JWT Verification

### Cloudflare Workers / Browser (Zero-Dependency Web Crypto)

```js
const jwksResp = await fetch('https://auth.example.com/.well-known/jwks.json');
const { keys } = await jwksResp.json();

const [h, p, s] = token.split('.');
const header = JSON.parse(atob(h.replace(/-/g, '+').replace(/_/g, '/')));
const jwk = keys.find((k) => k.kid === header.kid) || keys[0];

const pubKey = await crypto.subtle.importKey('jwk', jwk, { name: 'Ed25519' }, false, ['verify']);
const sig = Uint8Array.from(atob(s.replace(/-/g, '+').replace(/_/g, '/')), (c) => c.charCodeAt(0));
const valid = await crypto.subtle.verify('Ed25519', pubKey, sig, new TextEncoder().encode(`${h}.${p}`));
if (!valid) throw new Error('Invalid signature');

const claims = JSON.parse(atob(p.replace(/-/g, '+').replace(/_/g, '/')));
if (claims.exp < Math.floor(Date.now() / 1000)) throw new Error('Token expired');
if (claims.iss !== 'https://auth.example.com' || claims.aud !== 'YOUR_CLIENT_ID') {
  throw new Error('Claim mismatch');
}
```

### Python (`PyJWT` + `cryptography`)

```python
import jwt
from jwt import PyJWKClient

jwks_client = PyJWKClient("https://auth.example.com/.well-known/jwks.json")
signing_key = jwks_client.get_signing_key_from_jwt(access_token)
claims = jwt.decode(
    access_token,
    signing_key.key,
    algorithms=["EdDSA"],
    audience="YOUR_CLIENT_ID",
    issuer="https://auth.example.com",
)
```

---

## Signed Lifecycle Webhooks

Approved OAuth apps can configure an `https://` webhook URL in `/developer` (private/loopback/internal IP literals are blocked for SSRF protection).

### Events Delivered

- `consent.revoked` — User revoked consent for the app (`userId`, `appId`, `timestamp`)
- `user.suspended` — Admin/Superuser suspended a user with consent for the app (`userId`, `appId`, `timestamp`)
- `user.deleted` — User deleted their account or was deleted by an admin (`userId`, `appId`, `timestamp`)
- `webhook.test` — Triggered manually from the Developer Portal test button

### Verifying `X-JoeAuth-Signature`

Each delivery includes `X-JoeAuth-Event` and `X-JoeAuth-Signature: t=<unix_seconds>,v1=<hex_hmac_sha256>`. Compute `HMAC-SHA256(webhook_secret, "${t}.${rawBody}")` and compare the hex digest to `v1` in constant time:

```js
// Verify JoeAuth Webhook X-JoeAuth-Signature: t=...,v1=...
const parts = Object.fromEntries(sigHeader.split(',').map((s) => s.split('=')));
const msg = `${parts.t}.${rawBody}`;
// Compute HMAC-SHA256(webhook_secret, msg) as lowercase hex and timing-safe compare to parts.v1
```
