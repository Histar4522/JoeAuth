import http from 'node:http';
import crypto from 'node:crypto';

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
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>JoeAuth OAuth Test Server</title>
  <style>
    :root {
      --bg: #f8fafc; --surface: #ffffff; --border: #e2e8f0;
      --text: #0f172a; --muted: #64748b; --primary: #2563eb;
      --primary-hover: #1d4ed8; --ok: #16a34a; --bad: #dc2626;
    }
    * { box-sizing: border-box; }
    body {
      margin: 0; padding: 24px 16px; background: var(--bg); color: var(--text);
      font-family: system-ui, -apple-system, Segoe UI, Roboto, sans-serif; line-height: 1.5;
    }
    .wrap { max-width: 920px; margin: 0 auto; display: flex; flex-direction: column; gap: 16px; }
    .card {
      background: var(--surface); border: 1px solid var(--border);
      border-radius: 10px; padding: 18px 20px;
    }
    h1 { margin: 0 0 4px; font-size: 1.35rem; }
    h2 { margin: 0 0 12px; font-size: 1.05rem; }
    .muted { color: var(--muted); font-size: 0.88rem; }
    .grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(250px, 1fr)); gap: 12px; }
    label { display: flex; flex-direction: column; gap: 5px; font-size: 0.88rem; font-weight: 600; margin-bottom: 10px; }
    input, textarea, select {
      width: 100%; padding: 8px 10px; border: 1px solid var(--border); border-radius: 7px;
      font: inherit; font-size: 0.9rem; background: #fff; color: var(--text);
    }
    textarea { font-family: ui-monospace, SFMono-Regular, Menlo, Consolas, monospace; font-size: 0.82rem; resize: vertical; }
    .row { display: flex; flex-wrap: wrap; gap: 8px; align-items: center; }
    button {
      border: 1px solid var(--border); border-radius: 7px; padding: 8px 12px;
      background: #fff; color: var(--text); font: inherit; font-size: 0.88rem; font-weight: 600;
      cursor: pointer;
    }
    button:hover { background: #f1f5f9; }
    button.primary { background: var(--primary); border-color: var(--primary); color: #fff; }
    button.primary:hover { background: var(--primary-hover); }
    .badge {
      display: inline-block; padding: 2px 8px; border-radius: 999px;
      font-size: 0.78rem; font-weight: 700; background: #e2e8f0; color: #334155;
    }
    .badge.ok { background: #dcfce7; color: #166534; }
    .badge.bad { background: #fee2e2; color: #991b1b; }
    pre {
      margin: 10px 0 0; background: #0f172a; color: #e2e8f0; padding: 14px;
      border-radius: 8px; overflow-x: auto; font-size: 0.82rem; line-height: 1.45;
      max-height: 460px; white-space: pre-wrap; word-break: break-word;
    }
    code { font-family: ui-monospace, SFMono-Regular, Menlo, Consolas, monospace; font-size: 0.86em; }
    .hidden { display: none; }
  </style>
</head>
<body>
  <div class="wrap">
    <div class="card">
      <h1>JoeAuth OAuth &amp; API Test Server</h1>
      <div class="muted">
        Running at <code>${SELF_ORIGIN}</code> · Callback URI: <code id="callback-uri">${CALLBACK_URI}</code>
        <button type="button" id="copy-callback-btn" style="padding:2px 8px;margin-left:6px;font-size:0.78rem;">Copy Callback URI</button>
      </div>
    </div>

    <div class="card">
      <h2>1. Target Server &amp; Token</h2>
      <div class="grid">
        <label>
          Server Base URL
          <input id="base-url" type="url" value="http://127.0.0.1:8787" placeholder="http://127.0.0.1:8787">
        </label>
        <label>
          Scope (for OAuth Authorize / M2M)
          <input id="scope" type="text" value="openid profile email offline_access">
        </label>
      </div>

      <label>
        Access / Bearer / JWT Token
        <textarea id="token" rows="3" placeholder="Paste an access_token or id_token here (or sign in below to fill automatically)"></textarea>
      </label>

      <div id="received-tokens" class="row hidden" style="margin-bottom:10px;">
        <span class="muted">Received tokens:</span>
        <button type="button" id="use-access-token" class="hidden">Use access_token</button>
        <button type="button" id="use-id-token" class="hidden">Use id_token</button>
      </div>

      <div class="grid">
        <label>
          Client ID (optional for bearer tests; required for OAuth / Introspect)
          <input id="client-id" type="text" placeholder="ja_...">
        </label>
        <label>
          Client Secret (optional for PKCE; required for Introspect / M2M)
          <input id="client-secret" type="password" placeholder="jas_...">
        </label>
      </div>

      <label>
        Refresh Token (optional)
        <input id="refresh-token" type="text" placeholder="jar_...">
      </label>

      <div class="row">
        <button type="button" class="primary" id="btn-authorize">Authorize / Sign in with JoeAuth (PKCE S256)</button>
        <button type="button" id="btn-m2m">Client Credentials (M2M)</button>
      </div>
    </div>

    <div class="card">
      <h2>2. Test API Endpoints</h2>
      <div class="row" style="margin-bottom:14px;">
        <button type="button" class="primary" id="btn-userinfo">GET UserInfo</button>
        <button type="button" id="btn-verify-jwt">Verify Ed25519 JWT</button>
        <button type="button" id="btn-introspect">POST Introspect</button>
        <button type="button" id="btn-refresh">POST Refresh Token</button>
        <button type="button" id="btn-revoke">POST Revoke Token</button>
        <button type="button" id="btn-discovery">GET OIDC Discovery</button>
        <button type="button" id="btn-jwks">GET JWKS</button>
      </div>

      <div class="grid">
        <label>
          Custom Method
          <select id="custom-method">
            <option>GET</option>
            <option>POST</option>
            <option>PUT</option>
            <option>PATCH</option>
            <option>DELETE</option>
          </select>
        </label>
        <label>
          Custom Path (relative to Base URL)
          <input id="custom-path" type="text" value="/api/health" placeholder="/api/oauth/userinfo">
        </label>
      </div>
      <label>
        Custom JSON Body (optional, for POST/PUT/PATCH)
        <textarea id="custom-body" rows="2" placeholder='{"key":"value"}'></textarea>
      </label>
      <div class="row">
        <label style="flex-direction:row;align-items:center;gap:6px;margin:0;font-weight:500;">
          <input id="custom-use-bearer" type="checkbox" checked style="width:auto;">
          Send <code>Authorization: Bearer &lt;Token&gt;</code>
        </label>
        <button type="button" id="btn-custom">Send Custom Request</button>
      </div>
    </div>

    <div class="card">
      <div class="row" style="justify-content:space-between;">
        <h2 style="margin:0;">3. Response</h2>
        <div class="row">
          <span id="resp-meta" class="muted">No request run yet.</span>
          <span id="resp-status" class="badge hidden"></span>
        </div>
      </div>
      <pre id="resp-out">Click any test button above to inspect the response.</pre>
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
          respStatus.className = 'badge ' + (status >= 200 && status < 300 ? 'ok' : 'bad');
        } else if (status === 'VALID') {
          respStatus.textContent = 'VALID';
          respStatus.className = 'badge ok';
        } else if (status === 'INVALID') {
          respStatus.textContent = 'INVALID';
          respStatus.className = 'badge bad';
        } else {
          respStatus.className = 'badge hidden';
        }
        respOut.textContent = typeof data === 'string' ? data : JSON.stringify(data, null, 2);
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
