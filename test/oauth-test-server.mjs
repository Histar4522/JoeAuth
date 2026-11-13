import http from 'node:http';
import crypto from 'node:crypto';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const BOOTSTRAP_CSS = fs.readFileSync(path.join(__dirname, '..', 'public', 'vendor', 'bootstrap.min.css'), 'utf8');
const BOOTSTRAP_ICONS_CSS = fs.readFileSync(path.join(__dirname, '..', 'public', 'vendor', 'bootstrap-icons.min.css'), 'utf8');
const BOOTSTRAP_ICONS_WOFF2 = fs.readFileSync(path.join(__dirname, '..', 'public', 'vendor', 'fonts', 'bootstrap-icons.woff2'));
const BOOTSTRAP_ICONS_WOFF = fs.readFileSync(path.join(__dirname, '..', 'public', 'vendor', 'fonts', 'bootstrap-icons.woff'));
const THEME_JS = fs.readFileSync(path.join(__dirname, '..', 'public', 'theme.js'), 'utf8');

const portArg = process.argv.find((a) => a.startsWith('--port='));
const PORT = Number(process.env.PORT || (portArg ? portArg.split('=')[1] : 8788));
const HOST = '127.0.0.1';
const SELF_ORIGIN = `http://${HOST}:${PORT}`;
const CALLBACK_URI = `${SELF_ORIGIN}/callback`;

const pendingAuths = new Map();
const authResults = new Map();

function pruneStores() {
  const now = Date.now();
  for (const [k, v] of pendingAuths.entries()) {
    if (v.expiresAt <= now) pendingAuths.delete(k);
  }
  for (const [k, v] of authResults.entries()) {
    if (v.expiresAt <= now) authResults.delete(k);
  }
}

function toBase64Url(buf) {
  return Buffer.from(buf).toString('base64url');
}

function fromBase64Url(str) {
  return Buffer.from(str, 'base64url');
}

function normalizeBaseUrl(raw) {
  const parsed = new URL(String(raw || '').trim());
  if (parsed.protocol !== 'http:' && parsed.protocol !== 'https:') {
    throw new Error('Server Base URL must use http:// or https://');
  }
  return parsed.toString().replace(/\/+$/, '');
}

async function readJsonBody(req) {
  const chunks = [];
  let total = 0;
  for await (const chunk of req) {
    total += chunk.length;
    if (total > 1024 * 1024) throw new Error('Request body too large');
    chunks.push(chunk);
  }
  const text = Buffer.concat(chunks).toString('utf8');
  return text ? JSON.parse(text) : {};
}

function sendJson(res, status, payload) {
  res.writeHead(status, { 'Content-Type': 'application/json; charset=utf-8' });
  res.end(JSON.stringify(payload));
}

function renderHtml() {
  return `<!doctype html>
<html lang="en" data-bs-theme="dark">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>JoeAuth OAuth Test Server</title>
  <script src="/theme.js"></script>
  <link rel="stylesheet" href="/bootstrap.min.css">
  <link rel="stylesheet" href="/bootstrap-icons.min.css">
  <style>
    pre.resp-pre {
      margin: 0.75rem 0 0;
      background: var(--bs-tertiary-bg);
      color: var(--bs-body-color);
      border: 1px solid var(--bs-border-color);
      border-radius: var(--bs-border-radius);
      padding: 0.9rem;
      font-size: 0.82rem;
      line-height: 1.45;
      max-height: 460px;
      overflow-x: auto;
      white-space: pre-wrap;
      word-break: break-word;
    }
    .hidden { display: none !important; }
  </style>
</head>
<body>
  <div class="container py-4" style="max-width: 960px;">
    <div class="card shadow-sm mb-3">
      <div class="card-body d-flex justify-content-between align-items-start flex-wrap gap-3">
        <div>
          <h1 class="h4 fw-semibold mb-1"><i class="bi bi-shield-check me-2 text-primary"></i>JoeAuth OAuth &amp; API Test Server</h1>
          <div class="text-body-secondary small">
            Running at <code>${SELF_ORIGIN}</code> · Callback URI: <code id="callback-uri">${CALLBACK_URI}</code>
            <button type="button" id="copy-callback-btn" class="btn btn-sm btn-outline-secondary py-0 px-2 ms-1"><i class="bi bi-clipboard me-1"></i>Copy</button>
          </div>
        </div>
        <div class="input-group input-group-sm w-auto">
          <span class="input-group-text"><i class="bi bi-circle-half"></i></span>
          <select class="form-select form-select-sm w-auto" data-theme-select aria-label="Theme">
            <option value="auto" selected>Auto</option>
            <option value="dark">Dark</option>
            <option value="light">Light</option>
          </select>
        </div>
      </div>
    </div>

    <div class="card shadow-sm mb-3">
      <div class="card-body">
        <h2 class="h5 fw-semibold mb-3"><i class="bi bi-sliders me-2 text-primary"></i>1. Target Server &amp; Token</h2>
        <div class="row g-3 mb-3">
          <div class="col-md-6">
            <label class="form-label" for="base-url">Server Base URL</label>
            <input id="base-url" class="form-control" type="url" value="http://127.0.0.1:8787" placeholder="http://127.0.0.1:8787">
          </div>
          <div class="col-md-6">
            <label class="form-label" for="scope">Scope (for OAuth Authorize / M2M)</label>
            <input id="scope" class="form-control" type="text" value="openid profile email offline_access">
          </div>
        </div>

        <div class="mb-3">
          <label class="form-label" for="token">Access / Bearer / JWT Token</label>
          <textarea id="token" class="form-control font-monospace small" rows="3" placeholder="Paste an access_token or id_token here (or sign in below to fill automatically)"></textarea>
        </div>

        <div id="received-tokens" class="d-flex flex-wrap align-items-center gap-2 mb-3 hidden">
          <span class="text-body-secondary small">Received tokens:</span>
          <button type="button" id="use-access-token" class="btn btn-sm btn-outline-secondary hidden">Use access_token</button>
          <button type="button" id="use-id-token" class="btn btn-sm btn-outline-secondary hidden">Use id_token</button>
        </div>

        <div class="row g-3 mb-3">
          <div class="col-md-6">
            <label class="form-label" for="client-id">Client ID (optional for bearer; required for OAuth / Introspect)</label>
            <input id="client-id" class="form-control font-monospace" type="text" placeholder="ja_...">
          </div>
          <div class="col-md-6">
            <label class="form-label" for="client-secret">Client Secret (optional for PKCE; required for Introspect / M2M)</label>
            <input id="client-secret" class="form-control font-monospace" type="password" placeholder="jas_...">
          </div>
        </div>

        <div class="mb-3">
          <label class="form-label" for="refresh-token">Refresh Token (optional)</label>
          <input id="refresh-token" class="form-control font-monospace" type="text" placeholder="jar_...">
        </div>

        <div class="d-flex flex-wrap gap-2">
          <button type="button" class="btn btn-primary" id="btn-authorize"><i class="bi bi-box-arrow-in-right me-1"></i>Authorize / Sign in with JoeAuth (PKCE S256)</button>
          <button type="button" class="btn btn-outline-secondary" id="btn-m2m"><i class="bi bi-key me-1"></i>Client Credentials (M2M)</button>
        </div>
      </div>
    </div>

    <div class="card shadow-sm mb-3">
      <div class="card-body">
        <h2 class="h5 fw-semibold mb-3"><i class="bi bi-terminal me-2 text-primary"></i>2. Test API Endpoints</h2>
        <div class="d-flex flex-wrap gap-2 mb-3">
          <button type="button" class="btn btn-primary" id="btn-userinfo"><i class="bi bi-person-vcard me-1"></i>GET UserInfo</button>
          <button type="button" class="btn btn-outline-secondary" id="btn-verify-jwt"><i class="bi bi-patch-check me-1"></i>Verify Ed25519 JWT</button>
          <button type="button" class="btn btn-outline-secondary" id="btn-introspect"><i class="bi bi-search me-1"></i>POST Introspect</button>
          <button type="button" class="btn btn-outline-secondary" id="btn-refresh"><i class="bi bi-arrow-repeat me-1"></i>POST Refresh Token</button>
          <button type="button" class="btn btn-outline-secondary" id="btn-revoke"><i class="bi bi-slash-circle me-1"></i>POST Revoke Token</button>
          <button type="button" class="btn btn-outline-secondary" id="btn-discovery"><i class="bi bi-compass me-1"></i>GET OIDC Discovery</button>
          <button type="button" class="btn btn-outline-secondary" id="btn-jwks"><i class="bi bi-braces me-1"></i>GET JWKS</button>
        </div>

        <div class="row g-3 mb-3">
          <div class="col-md-4">
            <label class="form-label" for="custom-method">Custom Method</label>
            <select id="custom-method" class="form-select">
              <option>GET</option>
              <option>POST</option>
              <option>PUT</option>
              <option>PATCH</option>
              <option>DELETE</option>
            </select>
          </div>
          <div class="col-md-8">
            <label class="form-label" for="custom-path">Custom Path (relative to Base URL)</label>
            <input id="custom-path" class="form-control font-monospace" type="text" value="/api/health" placeholder="/api/oauth/userinfo">
          </div>
        </div>
        <div class="mb-3">
          <label class="form-label" for="custom-body">Custom JSON Body (optional, for POST/PUT/PATCH)</label>
          <textarea id="custom-body" class="form-control font-monospace small" rows="2" placeholder='{"key":"value"}'></textarea>
        </div>
        <div class="d-flex flex-wrap align-items-center gap-3">
          <div class="form-check mb-0">
            <input id="custom-use-bearer" class="form-check-input" type="checkbox" checked>
            <label class="form-check-label small" for="custom-use-bearer">
              Send <code>Authorization: Bearer &lt;Token&gt;</code>
            </label>
          </div>
          <button type="button" class="btn btn-outline-primary" id="btn-custom"><i class="bi bi-send me-1"></i>Send Custom Request</button>
        </div>
      </div>
    </div>

    <div class="card shadow-sm">
      <div class="card-body">
        <div class="d-flex justify-content-between align-items-center flex-wrap gap-2">
          <h2 class="h5 fw-semibold mb-0"><i class="bi bi-code-square me-2 text-primary"></i>3. Response</h2>
          <div class="d-flex align-items-center gap-2">
            <span id="resp-meta" class="text-body-secondary small">No request run yet.</span>
            <span id="resp-status" class="badge hidden"></span>
          </div>
        </div>
        <div id="resp-picture-bar" class="d-flex align-items-center gap-3 p-2 rounded bg-body-tertiary border mt-3 hidden">
          <img id="resp-picture-img" src="" alt="OIDC picture claim preview" width="48" height="48" class="rounded-circle border object-fit-cover flex-shrink-0">
          <div class="small min-w-0">
            <div class="fw-semibold" id="resp-picture-name">Profile Picture Claim</div>
            <div class="text-body-secondary text-break font-monospace" id="resp-picture-url"></div>
          </div>
        </div>
        <pre id="resp-out" class="resp-pre">Click any test button above to inspect the response.</pre>
      </div>
    </div>
  </div>

  <script>
    (function () {
      const STORAGE_KEY = 'joeauth_test_server_state_v1';
      const fields = {
        baseUrl: document.getElementById('base-url'),
        scope: document.getElementById('scope'),
        token: document.getElementById('token'),
        clientId: document.getElementById('client-id'),
        clientSecret: document.getElementById('client-secret'),
        refreshToken: document.getElementById('refresh-token'),
        customMethod: document.getElementById('custom-method'),
        customPath: document.getElementById('custom-path'),
        customBody: document.getElementById('custom-body'),
        customUseBearer: document.getElementById('custom-use-bearer'),
      };

      const respMeta = document.getElementById('resp-meta');
      const respStatus = document.getElementById('resp-status');
      const respOut = document.getElementById('resp-out');
      const tokenRow = document.getElementById('received-tokens');
      const useAccessBtn = document.getElementById('use-access-token');
      const useIdBtn = document.getElementById('use-id-token');
      let lastTokenBundle = {};

      function saveState() {
        try {
          localStorage.setItem(STORAGE_KEY, JSON.stringify({
            baseUrl: fields.baseUrl.value,
            scope: fields.scope.value,
            token: fields.token.value,
            clientId: fields.clientId.value,
            clientSecret: fields.clientSecret.value,
            refreshToken: fields.refreshToken.value,
          }));
        } catch {}
      }

      function loadState() {
        try {
          const saved = JSON.parse(localStorage.getItem(STORAGE_KEY) || '{}');
          if (saved.baseUrl) fields.baseUrl.value = saved.baseUrl;
          if (saved.scope) fields.scope.value = saved.scope;
          if (saved.token) fields.token.value = saved.token;
          if (saved.clientId) fields.clientId.value = saved.clientId;
          if (saved.clientSecret) fields.clientSecret.value = saved.clientSecret;
          if (saved.refreshToken) fields.refreshToken.value = saved.refreshToken;
        } catch {}
      }

      for (const el of Object.values(fields)) {
        el.addEventListener('input', saveState);
      }

      function renderOutput(meta, status, data) {
        respMeta.textContent = meta;
        if (typeof status === 'number') {
          respStatus.textContent = String(status);
          respStatus.className = 'badge ' + (status >= 200 && status < 300 ? 'text-bg-success' : 'text-bg-danger');
        } else if (status === 'VALID') {
          respStatus.textContent = 'VALID';
          respStatus.className = 'badge text-bg-success';
        } else if (status === 'INVALID') {
          respStatus.textContent = 'INVALID';
          respStatus.className = 'badge text-bg-danger';
        } else {
          respStatus.className = 'badge hidden';
        }
        respOut.textContent = typeof data === 'string' ? data : JSON.stringify(data, null, 2);
        const picBar = document.getElementById('resp-picture-bar');
        const picUrl =
          data && typeof data === 'object'
            ? (data.picture || data.user?.picture || data.payload?.picture || '')
            : '';
        if (picBar && typeof picUrl === 'string' && picUrl) {
          document.getElementById('resp-picture-img').src = picUrl;
          document.getElementById('resp-picture-name').textContent =
            data.name || data.user?.name || data.payload?.name || 'OIDC picture claim';
          document.getElementById('resp-picture-url').textContent = picUrl;
          picBar.classList.remove('hidden');
        } else if (picBar) {
          picBar.classList.add('hidden');
        }
      }

      function applyTokenBundle(bundle) {
        if (!bundle || typeof bundle !== 'object') return;
        lastTokenBundle = bundle;
        if (bundle.access_token) fields.token.value = bundle.access_token;
        else if (bundle.id_token) fields.token.value = bundle.id_token;
        if (bundle.refresh_token) fields.refreshToken.value = bundle.refresh_token;

        useAccessBtn.classList.toggle('hidden', !bundle.access_token);
        useIdBtn.classList.toggle('hidden', !bundle.id_token);
        tokenRow.classList.toggle('hidden', !bundle.access_token && !bundle.id_token);
        saveState();
      }

      useAccessBtn.addEventListener('click', () => {
        if (lastTokenBundle.access_token) {
          fields.token.value = lastTokenBundle.access_token;
          saveState();
        }
      });
      useIdBtn.addEventListener('click', () => {
        if (lastTokenBundle.id_token) {
          fields.token.value = lastTokenBundle.id_token;
          saveState();
        }
      });

      document.getElementById('copy-callback-btn').addEventListener('click', async () => {
        try {
          await navigator.clipboard.writeText(document.getElementById('callback-uri').textContent || '');
        } catch {}
      });

      async function proxyRequest(opts) {
        saveState();
        const resp = await fetch('/local/proxy', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({
            baseUrl: fields.baseUrl.value,
            ...opts,
          }),
        });
        const res = await resp.json();
        if (!res.ok) {
          renderOutput('Proxy Error', 'INVALID', res);
          return null;
        }
        renderOutput(
          opts.method + ' ' + res.targetUrl + ' (' + res.durationMs + ' ms)',
          res.status,
          res.json !== undefined ? res.json : res.body
        );
        return res;
      }

      document.getElementById('btn-authorize').addEventListener('click', async () => {
        saveState();
        const resp = await fetch('/local/oauth/start', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({
            baseUrl: fields.baseUrl.value,
            clientId: fields.clientId.value.trim(),
            clientSecret: fields.clientSecret.value,
            scope: fields.scope.value.trim() || 'openid profile email',
          }),
        });
        const data = await resp.json();
        if (!resp.ok || !data.ok) {
          renderOutput('OAuth Start Failed', resp.status, data);
          return;
        }
        location.href = data.authorizeUrl;
      });

      document.getElementById('btn-m2m').addEventListener('click', async () => {
        const res = await proxyRequest({
          method: 'POST',
          path: '/api/oauth/token',
          formBody: {
            grant_type: 'client_credentials',
            client_id: fields.clientId.value.trim(),
            client_secret: fields.clientSecret.value,
            scope: fields.scope.value.trim() || 'app:service',
          },
        });
        if (res && res.status >= 200 && res.status < 300 && res.json) {
          applyTokenBundle(res.json);
        }
      });

      document.getElementById('btn-userinfo').addEventListener('click', () => {
        proxyRequest({
          method: 'GET',
          path: '/api/oauth/userinfo',
          bearerToken: fields.token.value.trim(),
        });
      });

      document.getElementById('btn-discovery').addEventListener('click', () => {
        proxyRequest({ method: 'GET', path: '/.well-known/openid-configuration' });
      });

      document.getElementById('btn-jwks').addEventListener('click', () => {
        proxyRequest({ method: 'GET', path: '/.well-known/jwks.json' });
      });

      document.getElementById('btn-introspect').addEventListener('click', () => {
        proxyRequest({
          method: 'POST',
          path: '/api/oauth/introspect',
          formBody: {
            token: fields.token.value.trim(),
            client_id: fields.clientId.value.trim(),
            client_secret: fields.clientSecret.value,
          },
        });
      });

      document.getElementById('btn-refresh').addEventListener('click', async () => {
        const refreshTok = fields.refreshToken.value.trim() || fields.token.value.trim();
        const res = await proxyRequest({
          method: 'POST',
          path: '/api/oauth/token',
          formBody: {
            grant_type: 'refresh_token',
            refresh_token: refreshTok,
            client_id: fields.clientId.value.trim(),
            ...(fields.clientSecret.value ? { client_secret: fields.clientSecret.value } : {}),
          },
        });
        if (res && res.status >= 200 && res.status < 300 && res.json) {
          applyTokenBundle(res.json);
        }
      });

      document.getElementById('btn-revoke').addEventListener('click', () => {
        const tok = fields.refreshToken.value.trim() || fields.token.value.trim();
        proxyRequest({
          method: 'POST',
          path: '/api/oauth/revoke',
          formBody: {
            token: tok,
            client_id: fields.clientId.value.trim(),
          },
        });
      });

      document.getElementById('btn-verify-jwt').addEventListener('click', async () => {
        saveState();
        const resp = await fetch('/local/verify-jwt', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({
            baseUrl: fields.baseUrl.value,
            token: fields.token.value.trim(),
          }),
        });
        const data = await resp.json();
        renderOutput(
          'Ed25519 JWT Verification against ' + fields.baseUrl.value + '/.well-known/jwks.json',
          data.valid ? 'VALID' : 'INVALID',
          data
        );
      });

      document.getElementById('btn-custom').addEventListener('click', () => {
        const method = fields.customMethod.value;
        const path = fields.customPath.value.trim() || '/';
        const rawBody = fields.customBody.value.trim();
        const bearerToken = fields.customUseBearer.checked ? fields.token.value.trim() : '';
        proxyRequest({
          method,
          path,
          bearerToken,
          rawBody: rawBody || undefined,
          contentType: rawBody ? 'application/json' : undefined,
        });
      });

      loadState();

      // Load callback result if redirected back from /callback
      const params = new URLSearchParams(location.search);
      const resultId = params.get('result');
      if (resultId) {
        fetch('/local/oauth/result?id=' + encodeURIComponent(resultId))
          .then((r) => r.json())
          .then((res) => {
            if (res.ok && res.result) {
              if (res.result.tokens) applyTokenBundle(res.result.tokens);
              renderOutput(
                'OAuth Callback -> Token Exchange (' + (res.result.durationMs || 0) + ' ms)',
                res.result.status || (res.result.error ? 400 : 200),
                res.result
              );
            }
          })
          .finally(() => {
            params.delete('result');
            const next = location.pathname + (params.toString() ? '?' + params.toString() : '');
            history.replaceState(null, '', next);
          });
      }
    })();
  </script>
</body>
</html>`;
}

async function handleVerifyJwt(req, res) {
  const body = await readJsonBody(req);
  const baseUrl = normalizeBaseUrl(body.baseUrl);
  const token = String(body.token || '').trim();
  if (!token) {
    return sendJson(res, 400, { ok: false, valid: false, error: 'Token is required' });
  }
  const parts = token.split('.');
  if (parts.length !== 3) {
    return sendJson(res, 400, { ok: false, valid: false, error: 'Token is not a 3-part JWT (it may be an opaque refresh token)' });
  }

  const header = JSON.parse(fromBase64Url(parts[0]).toString('utf8'));
  const payload = JSON.parse(fromBase64Url(parts[1]).toString('utf8'));
  if (header.alg !== 'EdDSA') {
    return sendJson(res, 400, { ok: false, valid: false, error: `Unsupported JWT alg: ${header.alg}`, header, payload });
  }

  const jwksResp = await fetch(`${baseUrl}/.well-known/jwks.json`);
  if (!jwksResp.ok) {
    return sendJson(res, 502, { ok: false, valid: false, error: `Failed to fetch JWKS (${jwksResp.status})`, header, payload });
  }
  const jwks = await jwksResp.json();
  const keys = Array.isArray(jwks.keys) ? jwks.keys : [];
  const jwk = (header.kid ? keys.find((k) => k.kid === header.kid) : null) || keys.find((k) => k.crv === 'Ed25519');
  if (!jwk) {
    return sendJson(res, 400, { ok: false, valid: false, error: 'No matching Ed25519 public key found in JWKS', header, payload });
  }

  const publicKey = crypto.createPublicKey({ key: jwk, format: 'jwk' });
  const signingInput = Buffer.from(`${parts[0]}.${parts[1]}`, 'utf8');
  const sigValid = crypto.verify(null, signingInput, publicKey, fromBase64Url(parts[2]));

  const now = Math.floor(Date.now() / 1000);
  const expired = typeof payload.exp === 'number' && payload.exp <= now;
  const notYetValid = typeof payload.nbf === 'number' && payload.nbf > now;

  return sendJson(res, 200, {
    ok: true,
    valid: Boolean(sigValid && !expired && !notYetValid),
    signatureValid: sigValid,
    expired,
    notYetValid,
    kid: jwk.kid || null,
    header,
    payload,
  });
}

async function handleProxy(req, res) {
  const body = await readJsonBody(req);
  const baseUrl = normalizeBaseUrl(body.baseUrl);
  const relPath = String(body.path || '/');
  const target = relPath.startsWith('http://') || relPath.startsWith('https://')
    ? new URL(relPath)
    : new URL(relPath.startsWith('/') ? relPath : `/${relPath}`, `${baseUrl}/`);

  if (target.protocol !== 'http:' && target.protocol !== 'https:') {
    return sendJson(res, 400, { ok: false, error: 'Invalid target protocol' });
  }

  const method = String(body.method || 'GET').toUpperCase();
  const headers = {};
  if (body.bearerToken) {
    headers['Authorization'] = `Bearer ${String(body.bearerToken).trim()}`;
  }

  let fetchBody;
  if (method !== 'GET' && method !== 'HEAD') {
    if (body.formBody && typeof body.formBody === 'object') {
      const params = new URLSearchParams();
      for (const [k, v] of Object.entries(body.formBody)) {
        if (v !== undefined && v !== null) params.set(k, String(v));
      }
      headers['Content-Type'] = 'application/x-www-form-urlencoded';
      fetchBody = params.toString();
    } else if (body.rawBody !== undefined) {
      if (body.contentType) headers['Content-Type'] = String(body.contentType);
      fetchBody = String(body.rawBody);
    }
  }

  const started = Date.now();
  const upstream = await fetch(target.toString(), { method, headers, body: fetchBody });
  const durationMs = Date.now() - started;
  const text = await upstream.text();

  let json;
  try {
    json = JSON.parse(text);
  } catch {}

  return sendJson(res, 200, {
    ok: true,
    targetUrl: target.toString(),
    status: upstream.status,
    statusText: upstream.statusText,
    durationMs,
    body: text,
    ...(json !== undefined ? { json } : {}),
  });
}

const server = http.createServer(async (req, res) => {
  pruneStores();
  try {
    const reqUrl = new URL(req.url || '/', SELF_ORIGIN);

    if (req.method === 'GET' && reqUrl.pathname === '/') {
      res.writeHead(200, { 'Content-Type': 'text/html; charset=utf-8' });
      return res.end(renderHtml());
    }

    if (req.method === 'GET' && reqUrl.pathname === '/bootstrap.min.css') {
      res.writeHead(200, { 'Content-Type': 'text/css; charset=utf-8' });
      return res.end(BOOTSTRAP_CSS);
    }

    if (req.method === 'GET' && reqUrl.pathname === '/bootstrap-icons.min.css') {
      res.writeHead(200, { 'Content-Type': 'text/css; charset=utf-8' });
      return res.end(BOOTSTRAP_ICONS_CSS);
    }

    if (req.method === 'GET' && reqUrl.pathname === '/fonts/bootstrap-icons.woff2') {
      res.writeHead(200, { 'Content-Type': 'font/woff2' });
      return res.end(BOOTSTRAP_ICONS_WOFF2);
    }

    if (req.method === 'GET' && reqUrl.pathname === '/fonts/bootstrap-icons.woff') {
      res.writeHead(200, { 'Content-Type': 'font/woff' });
      return res.end(BOOTSTRAP_ICONS_WOFF);
    }

    if (req.method === 'GET' && reqUrl.pathname === '/theme.js') {
      res.writeHead(200, { 'Content-Type': 'application/javascript; charset=utf-8' });
      return res.end(THEME_JS);
    }

    if (req.method === 'GET' && reqUrl.pathname === '/health') {
      return sendJson(res, 200, { ok: true, callbackUri: CALLBACK_URI });
    }

    if (req.method === 'POST' && reqUrl.pathname === '/local/oauth/start') {
      const body = await readJsonBody(req);
      const baseUrl = normalizeBaseUrl(body.baseUrl);
      const clientId = String(body.clientId || '').trim();
      if (!clientId) {
        return sendJson(res, 400, { ok: false, error: 'Client ID is required to start OAuth authorization flow' });
      }
      const state = toBase64Url(crypto.randomBytes(16));
      const nonce = toBase64Url(crypto.randomBytes(16));
      const codeVerifier = toBase64Url(crypto.randomBytes(32));
      const codeChallenge = toBase64Url(crypto.createHash('sha256').update(codeVerifier).digest());

      pendingAuths.set(state, {
        baseUrl,
        clientId,
        clientSecret: String(body.clientSecret || ''),
        codeVerifier,
        expiresAt: Date.now() + 10 * 60 * 1000,
      });

      const authUrl = new URL(`${baseUrl}/oauth/authorize`);
      authUrl.searchParams.set('client_id', clientId);
      authUrl.searchParams.set('redirect_uri', CALLBACK_URI);
      authUrl.searchParams.set('response_type', 'code');
      authUrl.searchParams.set('scope', String(body.scope || 'openid profile email'));
      authUrl.searchParams.set('state', state);
      authUrl.searchParams.set('nonce', nonce);
      authUrl.searchParams.set('code_challenge', codeChallenge);
      authUrl.searchParams.set('code_challenge_method', 'S256');

      return sendJson(res, 200, { ok: true, authorizeUrl: authUrl.toString() });
    }

    if (req.method === 'GET' && reqUrl.pathname === '/callback') {
      const state = reqUrl.searchParams.get('state') || '';
      const error = reqUrl.searchParams.get('error');
      const code = reqUrl.searchParams.get('code');
      const pending = pendingAuths.get(state);
      pendingAuths.delete(state);

      const resultId = toBase64Url(crypto.randomBytes(12));
      if (!pending) {
        authResults.set(resultId, {
          expiresAt: Date.now() + 5 * 60 * 1000,
          status: 400,
          error: 'Invalid or expired OAuth state',
        });
      } else if (error) {
        authResults.set(resultId, {
          expiresAt: Date.now() + 5 * 60 * 1000,
          status: 400,
          error,
          error_description: reqUrl.searchParams.get('error_description') || '',
        });
      } else if (!code) {
        authResults.set(resultId, {
          expiresAt: Date.now() + 5 * 60 * 1000,
          status: 400,
          error: 'Missing authorization code in callback',
        });
      } else {
        const started = Date.now();
        const form = new URLSearchParams({
          grant_type: 'authorization_code',
          client_id: pending.clientId,
          code,
          redirect_uri: CALLBACK_URI,
          code_verifier: pending.codeVerifier,
        });
        if (pending.clientSecret) form.set('client_secret', pending.clientSecret);

        const tokenResp = await fetch(`${pending.baseUrl}/api/oauth/token`, {
          method: 'POST',
          headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
          body: form.toString(),
        });
        const durationMs = Date.now() - started;
        const tokenJson = await tokenResp.json().catch(() => ({ error: 'invalid_json' }));
        authResults.set(resultId, {
          expiresAt: Date.now() + 5 * 60 * 1000,
          status: tokenResp.status,
          durationMs,
          tokens: tokenResp.ok ? tokenJson : undefined,
          rawResponse: tokenJson,
        });
      }

      res.writeHead(302, { Location: `/?result=${encodeURIComponent(resultId)}` });
      return res.end();
    }

    if (req.method === 'GET' && reqUrl.pathname === '/local/oauth/result') {
      const id = reqUrl.searchParams.get('id') || '';
      const result = authResults.get(id) || null;
      if (result) authResults.delete(id);
      return sendJson(res, 200, { ok: Boolean(result), result });
    }

    if (req.method === 'POST' && reqUrl.pathname === '/local/proxy') {
      return await handleProxy(req, res);
    }

    if (req.method === 'POST' && reqUrl.pathname === '/local/verify-jwt') {
      return await handleVerifyJwt(req, res);
    }

    return sendJson(res, 404, { ok: false, error: 'Not found' });
  } catch (err) {
    return sendJson(res, 500, { ok: false, error: err instanceof Error ? err.message : 'Internal error' });
  }
});

server.listen(PORT, HOST, () => {
  console.log(`JoeAuth OAuth Test Server listening at ${SELF_ORIGIN}`);
  console.log(`OAuth Callback URI: ${CALLBACK_URI}`);
});
