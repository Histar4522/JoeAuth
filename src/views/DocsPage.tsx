import type { FC } from 'hono/jsx';
import type { AuthContext } from '../types';
import { Layout } from './Layout';

export const DocsPage: FC<{
  appName: string;
  issuer: string;
  auth: AuthContext | null;
  csrfToken: string;
}> = ({ appName, issuer, auth, csrfToken }) => {
  const cfWorkerVerifySnippet = `// Verify Ed25519 access_token or id_token on any Cloudflare Worker (zero dependencies)
const jwksResp = await fetch('${issuer}/.well-known/jwks.json');
const { keys } = await jwksResp.json();
const pubKey = await crypto.subtle.importKey('jwk', keys[0], { name: 'Ed25519' }, false, ['verify']);

const [h, p, s] = token.split('.');
const sig = Uint8Array.from(atob(s.replace(/-/g, '+').replace(/_/g, '/')), c => c.charCodeAt(0));
const valid = await crypto.subtle.verify('Ed25519', pubKey, sig, new TextEncoder().encode(\`\${h}.\${p}\`));
if (!valid) throw new Error('Invalid signature');

const claims = JSON.parse(atob(p.replace(/-/g, '+').replace(/_/g, '/')));
if (claims.exp < Math.floor(Date.now() / 1000)) throw new Error('Token expired');
if (claims.iss !== '${issuer}' || claims.aud !== 'YOUR_CLIENT_ID') throw new Error('Claim mismatch');`;

  const tokenExchangeSnippet = `// Exchange authorization_code for access_token + id_token + refresh_token
const resp = await fetch('${issuer}/api/oauth/token', {
  method: 'POST',
  headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
  body: new URLSearchParams({
    grant_type: 'authorization_code',
    client_id: 'YOUR_CLIENT_ID',
    client_secret: 'YOUR_CLIENT_SECRET', // Required if PKCE was not used
    code: callbackCode,
    redirect_uri: 'https://your-service.example/callback',
    code_verifier: pkceVerifier,         // Required if code_challenge was sent
  }),
});
const tokens = await resp.json();`;

  const clientCredentialsSnippet = `// Obtain a service-to-service App Token (client_credentials)
const resp = await fetch('${issuer}/api/oauth/token', {
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
const { access_token, expires_in } = await resp.json();`;

  const introspectSnippet = `// Server-side verification & live user status check
const check = await fetch('${issuer}/api/oauth/introspect', {
  method: 'POST',
  headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
  body: new URLSearchParams({
    client_id: 'YOUR_CLIENT_ID',
    client_secret: 'YOUR_CLIENT_SECRET',
    token: bearerAccessToken,
  }),
});
const result = await check.json();
// result.active === true -> result.sub, result.scope, result.user`;

  const pythonSnippet = `# Python (PyJWT + cryptography) verification using JWKS
import jwt
from jwt import PyJWKClient

jwks_client = PyJWKClient("${issuer}/.well-known/jwks.json")
signing_key = jwks_client.get_signing_key_from_jwt(access_token)
claims = jwt.decode(
    access_token,
    signing_key.key,
    algorithms=["EdDSA"],
    audience="YOUR_CLIENT_ID",
    issuer="${issuer}",
)`;

  return (
    <Layout title="Developer Docs" auth={auth} csrfToken={csrfToken} showNav>
      <div class="mb-4">
        <h1 class="h3 fw-semibold mb-1">
          <i class="bi bi-book me-2 text-primary"></i>{appName} Developer Documentation
        </h1>
        <p class="text-body-secondary mb-0">
          OAuth 2.0 + PKCE (<code>S256</code>) + OpenID Connect identity provider using <strong>Ed25519</strong> (<code>EdDSA</code>) JWTs.
          Base issuer URL: <code>{issuer}</code>
        </p>
      </div>

      <section class="card shadow-sm mb-4">
        <div class="card-body">
          <h2 class="h5 fw-semibold mb-3">
            <i class="bi bi-diagram-3 me-2 text-primary"></i>1. Integration Workflow
          </h2>
          <ol class="ps-3 mb-3">
            <li class="mb-1">Register an account at <a href="/register">/register</a> (subject to admin email regex rules).</li>
            <li class="mb-1">Apply for developer access at <a href="/developer">/developer</a> and wait for Admin/Superuser approval.</li>
            <li class="mb-1">
              Once approved, create an OAuth application in <a href="/developer">/developer</a> (activated immediately) to obtain a{' '}
              <code>client_id</code>, one-time <code>client_secret</code>, and register exact <code>redirect_uris</code>.
            </li>
            <li>
              Redirect users to <code>/oauth/authorize</code> with PKCE (<code>S256</code>), exchange the returned <code>code</code> at{' '}
              <code>/api/oauth/token</code>, and verify tokens via <code>/.well-known/jwks.json</code> or <code>/api/oauth/introspect</code>.
            </li>
          </ol>
          <p class="text-body-secondary small mb-0">
            <strong>Supported Scopes:</strong> <code>openid</code> (user ID <code>sub</code> &amp; <code>id_token</code>),{' '}
            <code>profile</code> (<code>name</code>, <code>role</code>, <code>developer_status</code>),{' '}
            <code>email</code> (<code>email</code>, <code>email_verified</code>),{' '}
            <code>offline_access</code> (issues rotating 30-day <code>refresh_token</code>).
          </p>
        </div>
      </section>

      <section class="card shadow-sm mb-4">
        <div class="card-body">
          <h2 class="h5 fw-semibold mb-1">
            <i class="bi bi-magic me-2 text-primary"></i>2. Interactive Authorize URL &amp; PKCE Builder
          </h2>
          <p class="text-body-secondary small mb-3">
            Generate a live <code>/oauth/authorize</code> link with a browser-generated <code>S256</code> PKCE challenge.
          </p>
          <div id="docs-url-builder" data-issuer={issuer} class="row g-2 align-items-center">
            <div class="col-md-3">
              <input class="form-control" type="text" id="doc-client-id" placeholder="client_id (e.g. ja_...)" />
            </div>
            <div class="col-md-4">
              <input class="form-control" type="url" id="doc-redirect-uri" placeholder="https://your-service.example/callback" />
            </div>
            <div class="col-md-3">
              <input class="form-control" type="text" id="doc-scope" value="openid profile email offline_access" />
            </div>
            <div class="col-md-2 d-grid">
              <button type="button" id="doc-generate-btn" class="btn btn-primary">
                <i class="bi bi-link-45deg me-1"></i>Generate
              </button>
            </div>
          </div>
          <div id="doc-generated-out" class="hidden mt-3">
            <p class="small mb-2">
              <strong>PKCE code_verifier</strong> (save for <code>/api/oauth/token</code>): <code id="doc-verifier"></code>
            </p>
            <pre class="code-block mb-2" id="doc-auth-url"></pre>
            <a id="doc-launch-link" class="btn btn-sm btn-outline-secondary" href="#" target="_blank" rel="noopener noreferrer">
              <i class="bi bi-box-arrow-up-right me-1"></i>Open Authorize URL
            </a>
          </div>
        </div>
      </section>

      <section class="card shadow-sm mb-4">
        <div class="card-body">
          <h2 class="h5 fw-semibold mb-3">
            <i class="bi bi-terminal me-2 text-primary"></i>3. Interface Reference
          </h2>

          <hr />
          <h3 class="h6 fw-semibold"><code>GET /.well-known/openid-configuration</code></h3>
          <p class="small mb-1"><strong>Auth:</strong> Public · <strong>CORS:</strong> <code>*</code></p>
          <p class="small text-body-secondary">
            <strong>Behavior:</strong> Returns the standard OpenID Connect Discovery metadata document describing endpoints,
            supported grant types (<code>authorization_code</code>, <code>refresh_token</code>, <code>client_credentials</code>),
            signing algorithm (<code>EdDSA</code>), scopes, and PKCE methods (<code>S256</code>).
          </p>
          <pre class="code-block mb-3">{`200 OK (application/json)
{
  "issuer": "${issuer}",
  "authorization_endpoint": "${issuer}/oauth/authorize",
  "token_endpoint": "${issuer}/api/oauth/token",
  "userinfo_endpoint": "${issuer}/api/oauth/userinfo",
  "introspection_endpoint": "${issuer}/api/oauth/introspect",
  "revocation_endpoint": "${issuer}/api/oauth/revoke",
  "jwks_uri": "${issuer}/.well-known/jwks.json",
  "response_types_supported": ["code"],
  "grant_types_supported": ["authorization_code", "refresh_token", "client_credentials"],
  "id_token_signing_alg_values_supported": ["EdDSA"],
  "scopes_supported": ["openid", "profile", "email", "offline_access"],
  "code_challenge_methods_supported": ["S256"]
}`}</pre>

          <hr />
          <h3 class="h6 fw-semibold"><code>GET /.well-known/jwks.json</code></h3>
          <p class="small mb-1"><strong>Auth:</strong> Public · <strong>Cache:</strong> <code>public, max-age=300</code> (edge KV-cached)</p>
          <p class="small text-body-secondary">
            <strong>Behavior:</strong> Exposes the active Ed25519 public key(s) in JSON Web Key Set format so client services
            can verify <code>access_token</code> and <code>id_token</code> signatures locally with zero network calls per request.
          </p>
          <pre class="code-block mb-3">{`200 OK (application/json)
{
  "keys": [
    { "kty": "OKP", "crv": "Ed25519", "x": "<base64url>", "kid": "<key-id>", "alg": "EdDSA", "use": "sig" }
  ]
}`}</pre>

          <hr />
          <h3 class="h6 fw-semibold"><code>GET /oauth/authorize</code> &amp; <code>POST /oauth/authorize</code></h3>
          <p class="small mb-1"><strong>Auth:</strong> User session cookie (redirects to <code>/login?return_to=...</code> if unauthenticated)</p>
          <p class="small text-body-secondary">
            <strong>Behavior:</strong> Validates that <code>client_id</code> belongs to an <code>approved</code> app and that
            <code>redirect_uri</code> matches one of the app's registered URIs <em>exactly</em>. Invalid <code>client_id</code> or
            <code>redirect_uri</code> renders a <code>400</code> error page directly (never redirects to an unverified URI).
            Requested scopes are filtered to the app's <code>allowed_scopes</code>. If the app is marked first-party or the user
            already consented to those scopes, a single-use authorization code (<strong>60s TTL</strong>) is issued immediately;
            otherwise the account chooser / consent screen is shown.
          </p>
          <div class="table-responsive mb-3">
            <table class="table table-sm align-middle mb-0">
              <thead>
                <tr><th>Query Parameter</th><th>Required</th><th>Description</th></tr>
              </thead>
              <tbody>
                <tr><td><code>client_id</code></td><td>Yes</td><td>Application ID (<code>ja_...</code>)</td></tr>
                <tr><td><code>redirect_uri</code></td><td>Yes</td><td>Exact match of a registered redirect URI</td></tr>
                <tr><td><code>response_type</code></td><td>No</td><td>Must be <code>code</code> (default <code>code</code>)</td></tr>
                <tr><td><code>scope</code></td><td>No</td><td>Space-delimited scopes (default <code>openid profile email</code>)</td></tr>
                <tr><td><code>state</code></td><td>Recommended</td><td>Opaque CSRF/state string echoed back on redirect</td></tr>
                <tr><td><code>code_challenge</code></td><td>Recommended</td><td>Base64URL-encoded SHA-256 of <code>code_verifier</code></td></tr>
                <tr><td><code>code_challenge_method</code></td><td>If PKCE</td><td>Must be <code>S256</code></td></tr>
                <tr><td><code>nonce</code></td><td>No</td><td>OIDC replay-protection value embedded into <code>id_token</code></td></tr>
              </tbody>
            </table>
          </div>
          <pre class="code-block mb-3">{`// Return Values (302 Found to redirect_uri):
// Approved: {redirect_uri}?code=jac_...&state={state}   (code expires in 60s, single-use)
// Denied:   {redirect_uri}?error=access_denied&state={state}
// Bad req:  {redirect_uri}?error=unsupported_response_type|invalid_request&state={state}`}</pre>

          <hr />
          <h3 class="h6 fw-semibold"><code>POST /api/oauth/token</code></h3>
          <p class="small mb-1">
            <strong>Rate Limit:</strong> 60 req / 60s per IP · <strong>Content-Type:</strong>{' '}
            <code>application/x-www-form-urlencoded</code> or <code>application/json</code> ·{' '}
            <strong>Client Auth:</strong> HTTP Basic (<code>client_id:client_secret</code>) or body fields
          </p>
          <p class="small text-body-secondary mb-1">
            <strong>Behavior by <code>grant_type</code>:</strong>
          </p>
          <ul class="small ps-3">
            <li class="mb-1">
              <strong><code>authorization_code</code></strong>: Atomically consumes the single-use <code>code</code> (60s TTL),
              verifies <code>redirect_uri</code> matches, verifies PKCE <code>S256(code_verifier) === code_challenge</code> (or requires
              <code>client_secret</code> if PKCE was omitted; if both are present, both are checked), and checks the user is <code>active</code>.
              Returns <code>access_token</code> (15m), <code>id_token</code> (1h, if <code>openid</code>), and <code>refresh_token</code> (30d, if <code>offline_access</code>).
            </li>
            <li class="mb-1">
              <strong><code>refresh_token</code></strong>: Validates <code>refresh_token</code> against <code>app_id</code> and rotates it
              (marks old token revoked, issues new <code>refresh_token</code> + fresh JWTs). <strong>Reuse detection:</strong> submitting an
              already-revoked refresh token immediately revokes the entire token family.
            </li>
            <li>
              <strong><code>client_credentials</code></strong>: Requires valid <code>client_id</code> + <code>client_secret</code>. Issues a
              1-hour Ed25519 M2M <code>access_token</code> with <code>token_type: "app"</code> and <code>sub: client_id</code>.
            </li>
          </ul>
          <pre class="code-block mb-3">{`200 OK (authorization_code / refresh_token)
{
  "token_type": "Bearer",
  "expires_in": 900,
  "scope": "openid profile email offline_access",
  "access_token": "eyJ...",   // EdDSA JWT (15 min TTL)
  "id_token": "eyJ...",       // EdDSA JWT (1 hour TTL, present if scope includes 'openid')
  "refresh_token": "jar_..."  // Opaque rotating token (30 day TTL, present if 'offline_access')
}

200 OK (client_credentials)
{
  "token_type": "Bearer",
  "expires_in": 3600,
  "scope": "app:service",
  "access_token": "eyJ..."    // EdDSA JWT (1 hour TTL, token_type: "app")
}

400 / 401 Error
{
  "error": "invalid_request | invalid_client | invalid_grant | unsupported_grant_type",
  "error_description": "Human-readable reason"
}`}</pre>

          <hr />
          <h3 class="h6 fw-semibold"><code>GET /api/oauth/userinfo</code></h3>
          <p class="small mb-1"><strong>Auth:</strong> <code>Authorization: Bearer &lt;access_token&gt;</code> (user token only)</p>
          <p class="small text-body-secondary">
            <strong>Behavior:</strong> Verifies the Ed25519 signature and expiration of the user <code>access_token</code>
            (rejects M2M <code>token_type: "app"</code> tokens), queries the database to confirm the user is still <code>active</code>,
            and returns live user claims filtered by the token's <code>scope</code>.
          </p>
          <pre class="code-block mb-3">{`200 OK
{
  "sub": "user-uuid",
  "name": "Joe Explorer",          // if scope includes 'profile'
  "role": "user",                  // if scope includes 'profile' ('user' | 'admin')
  "developer_status": "approved",  // if scope includes 'profile'
  "email": "joe@example.com",      // if scope includes 'email'
  "email_verified": true           // if scope includes 'email'
}

401 Unauthorized: { "error": "invalid_token" }`}</pre>

          <hr />
          <h3 class="h6 fw-semibold"><code>POST /api/oauth/introspect</code></h3>
          <p class="small mb-1">
            <strong>Auth:</strong> Client credentials (HTTP Basic or body <code>client_id</code> + <code>client_secret</code>) ·{' '}
            <strong>Rate Limit:</strong> 60 req / 60s
          </p>
          <p class="small text-body-secondary">
            <strong>Behavior:</strong> RFC 7662 token introspection for backends that prefer server-side validation. Authenticates the
            calling application (`401 invalid_client` if invalid), verifies the submitted <code>token</code>'s Ed25519 signature &amp;
            expiration, and for user tokens verifies the user account is still <code>active</code> in D1. Always returns <code>200</code> with{' '}
            <code>{`{ "active": false }`}</code> for invalid, expired, or suspended-user tokens.
          </p>
          <pre class="code-block mb-3">{`200 OK (active user token)
{
  "active": true,
  "iss": "${issuer}",
  "sub": "user-uuid",
  "aud": "ja_...",
  "client_id": "ja_...",
  "scope": "openid profile email",
  "token_type": "user",
  "role": "user",
  "iat": 1700000000,
  "exp": 1700000900,
  "user": {
    "id": "user-uuid",
    "email": "joe@example.com",
    "name": "Joe Explorer",
    "role": "user",
    "developer_status": "approved",
    "email_verified": true
  }
}

200 OK (inactive / expired / invalid): { "active": false }
401 Unauthorized: { "error": "invalid_client" }`}</pre>

          <hr />
          <h3 class="h6 fw-semibold"><code>POST /api/oauth/revoke</code></h3>
          <p class="small mb-1"><strong>Rate Limit:</strong> 60 req / 60s · <strong>Body:</strong> <code>token=&lt;refresh_token&gt;</code></p>
          <p class="small text-body-secondary mb-0">
            <strong>Behavior:</strong> Hashes the submitted <code>refresh_token</code> and marks it <code>revoked = 1</code> in D1.
            Idempotent — always returns <code>200 {`{ "ok": true }`}</code> even if the token was already revoked or unknown.
          </p>
        </div>
      </section>

      <section class="card shadow-sm mb-4">
        <div class="card-body">
          <h2 class="h5 fw-semibold mb-3">
            <i class="bi bi-card-checklist me-2 text-primary"></i>4. JWT Claims Reference (Ed25519 / EdDSA)
          </h2>
          <div class="table-responsive">
            <table class="table table-sm align-middle mb-0">
              <thead>
                <tr><th>Token</th><th>TTL</th><th>Claims Included</th></tr>
              </thead>
              <tbody>
                <tr>
                  <td>User <code>access_token</code></td>
                  <td>900s (15m)</td>
                  <td><code>iss</code>, <code>sub</code> (user ID), <code>aud</code> (<code>client_id</code>), <code>client_id</code>, <code>scope</code>, <code>token_type: "user"</code>, <code>role</code>, <code>iat</code>, <code>exp</code>, <code>jti</code></td>
                </tr>
                <tr>
                  <td>OIDC <code>id_token</code></td>
                  <td>3600s (1h)</td>
                  <td><code>iss</code>, <code>sub</code>, <code>aud</code>, <code>nonce</code> (if given), <code>name</code>/<code>role</code>/<code>developer_status</code> (<code>profile</code>), <code>email</code>/<code>email_verified</code> (<code>email</code>), <code>iat</code>, <code>exp</code>, <code>jti</code></td>
                </tr>
                <tr>
                  <td>App <code>access_token</code> (<code>client_credentials</code>)</td>
                  <td>3600s (1h)</td>
                  <td><code>iss</code>, <code>sub</code> (<code>client_id</code>), <code>aud</code> (<code>iss</code>), <code>client_id</code>, <code>app_id</code>, <code>owner_user_id</code>, <code>scope</code>, <code>token_type: "app"</code>, <code>iat</code>, <code>exp</code>, <code>jti</code></td>
                </tr>
              </tbody>
            </table>
          </div>
        </div>
      </section>

      <div class="row g-4">
        <div class="col-lg-6">
          <section class="card shadow-sm h-100">
            <div class="card-body">
              <h3 class="h5 fw-semibold mb-3">
                <i class="bi bi-code-slash me-2 text-primary"></i>5. Token Exchange &amp; M2M Examples
              </h3>
              <pre class="code-block mb-3">{tokenExchangeSnippet}</pre>
              <pre class="code-block mb-3">{clientCredentialsSnippet}</pre>
              <pre class="code-block">{introspectSnippet}</pre>
            </div>
          </section>
        </div>

        <div class="col-lg-6">
          <section class="card shadow-sm h-100">
            <div class="card-body">
              <h3 class="h5 fw-semibold mb-3">
                <i class="bi bi-shield-check me-2 text-primary"></i>6. Local Ed25519 Verification
              </h3>
              <pre class="code-block mb-3">{cfWorkerVerifySnippet}</pre>
              <pre class="code-block">{pythonSnippet}</pre>
            </div>
          </section>
        </div>
      </div>
    </Layout>
  );
};
