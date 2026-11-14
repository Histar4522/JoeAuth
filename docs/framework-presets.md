# Framework Integration Presets

Replace `https://auth.example.com` with your JoeAuth `ISSUER_URL`.

## Auth.js / NextAuth v5

```js
export default {
  id: "joeauth",
  name: "JoeAuth",
  type: "oidc",
  issuer: "https://auth.example.com",
  clientId: process.env.JOEAUTH_CLIENT_ID,
  clientSecret: process.env.JOEAUTH_CLIENT_SECRET,
  authorization: { params: { scope: "openid profile email" } },
};
```

## Hono / Edge (`oauth4webapi`)

```js
import * as oauth from 'oauth4webapi';

const issuer = new URL('https://auth.example.com');
const as = await oauth.discoveryRequest(issuer).then((r) => oauth.processDiscoveryResponse(issuer, r));
const client = { client_id: 'YOUR_CLIENT_ID' };
const clientAuth = oauth.ClientSecretPost('YOUR_CLIENT_SECRET');
```

## FastAPI (`Authlib`)

```python
from authlib.integrations.starlette_client import OAuth

oauth = OAuth()
oauth.register(
    name="joeauth",
    server_metadata_url="https://auth.example.com/.well-known/openid-configuration",
    client_id="YOUR_CLIENT_ID",
    client_secret="YOUR_CLIENT_SECRET",
    client_kwargs={"scope": "openid profile email", "code_challenge_method": "S256"},
)
```

## Go (`coreos/go-oidc`)

```go
provider, err := oidc.NewProvider(ctx, "https://auth.example.com")
oauth2Config := oauth2.Config{
    ClientID:     os.Getenv("JOEAUTH_CLIENT_ID"),
    ClientSecret: os.Getenv("JOEAUTH_CLIENT_SECRET"),
    RedirectURL:  "https://app.example.com/callback",
    Endpoint:     provider.Endpoint(),
    Scopes:       []string{oidc.ScopeOpenID, "profile", "email"},
}
```

## Public SPA / Mobile / CLI (PKCE `S256`)

1. Create the app in `/developer` with **`clientType: "public"`** (no `client_secret` is issued or required).
2. Redirect users to `https://auth.example.com/oauth/authorize` with `code_challenge` and `code_challenge_method=S256`.
3. Exchange the returned `code` via `POST https://auth.example.com/api/oauth/token` with `client_id`, `code`, `redirect_uri`, and `code_verifier`.
4. For CLI / smart-TV / headless devices, use `POST https://auth.example.com/api/oauth/device_code` and direct users to `https://auth.example.com/device`.
