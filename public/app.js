(function () {
  const csrf = document.querySelector('meta[name="csrf-token"]')?.getAttribute('content') || '';
  const pathSlotMatch = /^\/u\/(superuser|[0-9]+)(?=\/|$)/.exec(location.pathname);
  const accountBase =
    document.querySelector('meta[name="account-base"]')?.getAttribute('content') ||
    (pathSlotMatch ? `/u/${pathSlotMatch[1]}` : '');

  async function api(url, opts = {}) {
    const resolvedUrl = accountBase && typeof url === 'string' && url.startsWith('/api/') ? `${accountBase}${url}` : url;
    const headers = new Headers(opts.headers || {});
    if (csrf) headers.set('X-CSRF-Token', csrf);
    if (opts.body && typeof opts.body === 'object' && !(opts.body instanceof FormData)) {
      headers.set('Content-Type', 'application/json');
      opts.body = JSON.stringify(opts.body);
    }
    const resp = await fetch(resolvedUrl, { credentials: 'same-origin', ...opts, headers });
    const data = await resp.json().catch(() => ({ ok: false, error: { message: 'Invalid response' } }));
    if (!resp.ok || data.ok === false) {
      const err = new Error(data?.error?.message || data?.error_description || 'Request failed');
      err.code = data?.error?.code;
      throw err;
    }
    return data.data;
  }

  function showAlert(el, msg, type = 'error') {
    if (!el) return;
    el.textContent = msg;
    el.className = `alert ${type === 'success' ? 'alert-success' : 'alert-danger'}`;
  }

  function getTurnstileToken(form) {
    return form.querySelector('[name="cf-turnstile-response"]')?.value || '';
  }

  function resetTurnstile() {
    if (window.turnstile && typeof window.turnstile.reset === 'function') {
      try { window.turnstile.reset(); } catch {}
    }
  }

  function esc(str) {
    return String(str ?? '')
      .replace(/&/g, '&amp;')
      .replace(/</g, '&lt;')
      .replace(/>/g, '&gt;')
      .replace(/"/g, '&quot;');
  }

  function sanitizeReturnTo(raw, fallback = '/account') {
    const val = String(raw || '').trim();
    if (!val.startsWith('/') || val.startsWith('//') || val.startsWith('/\\')) return fallback;
    try {
      const u = new URL(val, 'https://placeholder.invalid');
      return u.origin === 'https://placeholder.invalid' ? `${u.pathname}${u.search}${u.hash}` : fallback;
    } catch {
      return fallback;
    }
  }

  function resolveAccountRedirect(rawReturnTo, slot, userCount) {
    const clean = sanitizeReturnTo(rawReturnTo, '/account');
    const stripped = clean.replace(/^\/u\/(superuser|[0-9]+)(?=\/|$)/, '') || '/account';
    if (stripped.startsWith('/oauth/')) return clean;
    if (userCount > 1 && slot) {
      return `/u/${slot}${stripped === '/' ? '/account' : stripped}`;
    }
    return stripped;
  }

  function safeHttpUrl(raw) {
    try {
      const u = new URL(String(raw || '').trim());
      return u.protocol === 'https:' || u.protocol === 'http:' ? u.toString() : '#';
    } catch {
      return '#';
    }
  }

  function renderAppLogoHtml(app, size = 36) {
    if (app.logo_url) {
      return `<img src="${esc(app.logo_url)}" alt="${esc(app.name)} logo" width="${size}" height="${size}" class="rounded border object-fit-cover flex-shrink-0" style="width:${size}px;height:${size}px;">`;
    }
    return `<span class="app-icon-badge" style="width:${size}px;height:${size}px;font-size:${Math.round(size * 0.52)}px;"><i class="bi bi-app-indicator"></i></span>`;
  }

  function canvasToPngBlob(cvs) {
    return new Promise((resolve) => cvs.toBlob(resolve, 'image/png'));
  }

  async function exportPngUnder128KiB(sourceCanvas) {
    let blob = await canvasToPngBlob(sourceCanvas);
    if (blob && blob.size <= 131072) return blob;

    const levels = [64, 48, 32, 24, 16, 12, 8];
    const scratch = document.createElement('canvas');
    scratch.width = 256;
    scratch.height = 256;
    const sctx = scratch.getContext('2d');
    const srcData = sourceCanvas.getContext('2d').getImageData(0, 0, 256, 256);

    for (const lvl of levels) {
      const out = sctx.createImageData(256, 256);
      const step = 255 / (lvl - 1);
      for (let i = 0; i < srcData.data.length; i += 4) {
        out.data[i] = Math.round(Math.round(srcData.data[i] / step) * step);
        out.data[i + 1] = Math.round(Math.round(srcData.data[i + 1] / step) * step);
        out.data[i + 2] = Math.round(Math.round(srcData.data[i + 2] / step) * step);
        out.data[i + 3] = srcData.data[i + 3];
      }
      sctx.putImageData(out, 0, 0);
      blob = await canvasToPngBlob(scratch);
      if (blob && blob.size <= 131072) return blob;
    }
    throw new Error('Could not fit PNG under 128 KiB. Try a simpler crop.');
  }

  function openImageCropper(file, { title = 'Crop 256×256 PNG', onConfirm }) {
    if (!file) return;
    const objUrl = URL.createObjectURL(file);
    const img = new Image();
    img.onload = () => {
      const SIZE = 256;
      const backdrop = document.createElement('div');
      backdrop.className = 'cropper-backdrop';
      backdrop.innerHTML = `
        <div class="card shadow-lg cropper-dialog">
          <div class="card-body p-3">
            <div class="d-flex justify-content-between align-items-center mb-2">
              <h2 class="h6 fw-semibold mb-0"><i class="bi bi-crop me-2 text-primary"></i>${esc(title)}</h2>
              <button type="button" class="btn-close" aria-label="Close" data-crop-cancel></button>
            </div>
            <p class="text-body-secondary small mb-2">Drag to reposition and zoom. Output is 256×256 PNG (≤ 128 KiB).</p>
            <canvas width="256" height="256" class="cropper-canvas mb-3"></canvas>
            <div class="mb-3">
              <label class="form-label small d-flex justify-content-between mb-1">
                <span>Zoom</span>
                <span class="text-body-secondary" data-crop-zoom-val>1.00×</span>
              </label>
              <input type="range" class="form-range" min="1" max="4" step="0.05" value="1" data-crop-zoom>
            </div>
            <div class="alert alert-danger py-1 px-2 small hidden" data-crop-err></div>
            <div class="d-flex gap-2">
              <button type="button" class="btn btn-outline-secondary flex-fill" data-crop-cancel>Cancel</button>
              <button type="button" class="btn btn-primary flex-fill" data-crop-apply>
                <i class="bi bi-check-lg me-1"></i>Apply
              </button>
            </div>
          </div>
        </div>
      `;
      document.body.appendChild(backdrop);

      const canvas = backdrop.querySelector('canvas');
      const ctx = canvas.getContext('2d');
      const zoomInput = backdrop.querySelector('[data-crop-zoom]');
      const zoomVal = backdrop.querySelector('[data-crop-zoom-val]');
      const errEl = backdrop.querySelector('[data-crop-err]');
      const applyBtn = backdrop.querySelector('[data-crop-apply]');

      const baseScale = Math.max(SIZE / img.naturalWidth, SIZE / img.naturalHeight);
      let zoom = 1;
      let offsetX = 0;
      let offsetY = 0;
      let dragging = false;
      let startX = 0;
      let startY = 0;

      function clampOffsets() {
        const w = img.naturalWidth * baseScale * zoom;
        const h = img.naturalHeight * baseScale * zoom;
        const maxX = Math.max(0, (w - SIZE) / 2);
        const maxY = Math.max(0, (h - SIZE) / 2);
        offsetX = Math.max(-maxX, Math.min(maxX, offsetX));
        offsetY = Math.max(-maxY, Math.min(maxY, offsetY));
      }

      function draw() {
        clampOffsets();
        ctx.clearRect(0, 0, SIZE, SIZE);
        const w = img.naturalWidth * baseScale * zoom;
        const h = img.naturalHeight * baseScale * zoom;
        const x = (SIZE - w) / 2 + offsetX;
        const y = (SIZE - h) / 2 + offsetY;
        ctx.drawImage(img, x, y, w, h);
      }

      draw();

      zoomInput.addEventListener('input', () => {
        zoom = parseFloat(zoomInput.value) || 1;
        zoomVal.textContent = `${zoom.toFixed(2)}×`;
        draw();
      });

      canvas.addEventListener('pointerdown', (ev) => {
        dragging = true;
        startX = ev.clientX - offsetX;
        startY = ev.clientY - offsetY;
        canvas.setPointerCapture(ev.pointerId);
      });
      canvas.addEventListener('pointermove', (ev) => {
        if (!dragging) return;
        offsetX = ev.clientX - startX;
        offsetY = ev.clientY - startY;
        draw();
      });
      const stopDrag = () => { dragging = false; };
      canvas.addEventListener('pointerup', stopDrag);
      canvas.addEventListener('pointercancel', stopDrag);

      function cleanup() {
        URL.revokeObjectURL(objUrl);
        backdrop.remove();
      }

      backdrop.querySelectorAll('[data-crop-cancel]').forEach((b) => b.addEventListener('click', cleanup));
      applyBtn.addEventListener('click', async () => {
        applyBtn.disabled = true;
        errEl.classList.add('hidden');
        try {
          const blob = await exportPngUnder128KiB(canvas);
          await onConfirm(blob);
          cleanup();
        } catch (err) {
          errEl.textContent = err?.message || 'Failed to export image.';
          errEl.classList.remove('hidden');
          applyBtn.disabled = false;
        }
      });
    };
    img.onerror = () => {
      URL.revokeObjectURL(objUrl);
      const alertEl = document.getElementById('panel-alert');
      if (alertEl) showAlert(alertEl, 'Could not load that image file.');
    };
    img.src = objUrl;
  }

  // Global Logout & Account Chooser
  document.querySelector('[data-logout-btn]')?.addEventListener('click', async () => {
    await api('/api/auth/logout', { method: 'POST', body: {} }).catch(() => {});
    location.href = '/login';
  });

  document.querySelector('[data-logout-all-btn]')?.addEventListener('click', async () => {
    await api('/api/auth/logout', { method: 'POST', body: { all: true } }).catch(() => {});
    location.href = '/login';
  });

  for (const btn of document.querySelectorAll('[data-switch-session]')) {
    btn.addEventListener('click', async () => {
      const alertEl = document.getElementById('form-alert');
      try {
        await api('/api/auth/switch', {
          method: 'POST',
          body: { sessionId: btn.dataset.switchSession },
        });
        location.href = resolveAccountRedirect(
          btn.dataset.returnTo,
          btn.dataset.targetSlot,
          btn.dataset.multiUser === '1' ? 2 : 1
        );
      } catch (err) {
        showAlert(alertEl, err.message);
      }
    });
  }

  for (const btn of document.querySelectorAll('[data-remove-session]')) {
    btn.addEventListener('click', async () => {
      const alertEl = document.getElementById('form-alert');
      try {
        await api('/api/auth/logout', {
          method: 'POST',
          body: { sessionId: btn.dataset.removeSession },
        });
        location.reload();
      } catch (err) {
        showAlert(alertEl, err.message);
      }
    });
  }

  // --- Auth Forms ---
  const loginForm = document.getElementById('login-form');
  if (loginForm) {
    const alertEl = document.getElementById('form-alert');
    loginForm.addEventListener('submit', async (e) => {
      e.preventDefault();
      const fd = new FormData(loginForm);
      try {
        const res = await api('/api/auth/login', {
          method: 'POST',
          body: {
            email: fd.get('email'),
            password: fd.get('password'),
            totpCode: fd.get('totpCode') || undefined,
            turnstileToken: getTurnstileToken(loginForm),
          },
        });
        location.href = resolveAccountRedirect(loginForm.dataset.returnTo, res.slot, res.userCount);
      } catch (err) {
        if (err.code === 'TOTP_REQUIRED') {
          document.getElementById('totp-group')?.classList.remove('hidden');
        }
        resetTurnstile();
        showAlert(alertEl, err.message);
      }
    });
  }

  const registerForm = document.getElementById('register-form');
  if (registerForm) {
    const alertEl = document.getElementById('form-alert');
    registerForm.addEventListener('submit', async (e) => {
      e.preventDefault();
      const fd = new FormData(registerForm);
      try {
        const res = await api('/api/auth/register', {
          method: 'POST',
          body: {
            name: fd.get('name'),
            email: fd.get('email'),
            password: fd.get('password'),
            turnstileToken: getTurnstileToken(registerForm),
          },
        });
        if (res.requiresEmailVerification) {
          showAlert(alertEl, res.message, 'success');
          registerForm.reset();
        } else {
          location.href = resolveAccountRedirect(registerForm.dataset.returnTo, res.slot, res.userCount);
        }
      } catch (err) {
        resetTurnstile();
        showAlert(alertEl, err.message);
      }
    });
  }

  const forgotForm = document.getElementById('forgot-form');
  if (forgotForm) {
    const alertEl = document.getElementById('form-alert');
    forgotForm.addEventListener('submit', async (e) => {
      e.preventDefault();
      const fd = new FormData(forgotForm);
      try {
        const res = await api('/api/auth/forgot-password', {
          method: 'POST',
          body: { email: fd.get('email'), turnstileToken: getTurnstileToken(forgotForm) },
        });
        showAlert(alertEl, res.message, 'success');
      } catch (err) {
        resetTurnstile();
        showAlert(alertEl, err.message);
      }
    });
  }

  const resetForm = document.getElementById('reset-form');
  if (resetForm) {
    const alertEl = document.getElementById('form-alert');
    resetForm.addEventListener('submit', async (e) => {
      e.preventDefault();
      const fd = new FormData(resetForm);
      try {
        const res = await api('/api/auth/reset-password', {
          method: 'POST',
          body: { token: fd.get('token'), newPassword: fd.get('newPassword') },
        });
        showAlert(alertEl, res.message, 'success');
        setTimeout(() => { location.href = '/login'; }, 1200);
      } catch (err) {
        showAlert(alertEl, err.message);
      }
    });
  }

  const suForm = document.getElementById('superuser-login-form');
  if (suForm) {
    const alertEl = document.getElementById('form-alert');
    suForm.addEventListener('submit', async (e) => {
      e.preventDefault();
      const fd = new FormData(suForm);
      try {
        await api('/api/admin/superuser/login', {
          method: 'POST',
          body: { password: fd.get('password'), turnstileToken: getTurnstileToken(suForm) },
        });
        location.href = '/u/superuser/admin';
      } catch (err) {
        resetTurnstile();
        showAlert(alertEl, err.message);
      }
    });
  }

  // --- User Panel ---
  const panelAlert = document.getElementById('panel-alert');

  function updateUserAvatarNodes(avatarUrl) {
    for (const [elId, size] of [['account-header-avatar', 52], ['avatar-preview', 64]]) {
      const node = document.getElementById(elId);
      if (!node) continue;
      if (node.tagName === 'IMG') {
        node.src = avatarUrl;
      } else {
        const img = document.createElement('img');
        img.id = elId;
        img.src = avatarUrl;
        img.alt = 'Profile avatar';
        img.width = size;
        img.height = size;
        img.className = 'rounded-circle object-fit-cover border flex-shrink-0';
        img.style.width = `${size}px`;
        img.style.height = `${size}px`;
        node.replaceWith(img);
      }
    }
  }

  const avatarInput = document.getElementById('avatar-file-input');
  avatarInput?.addEventListener('change', () => {
    const file = avatarInput.files?.[0];
    avatarInput.value = '';
    if (!file) return;
    openImageCropper(file, {
      title: 'Crop Profile Picture (256×256 PNG)',
      onConfirm: async (blob) => {
        const fd = new FormData();
        fd.append('file', blob, 'avatar.png');
        const res = await api('/api/user/avatar', { method: 'POST', body: fd });
        updateUserAvatarNodes(res.avatar_url);
        document.getElementById('remove-avatar-btn')?.classList.remove('hidden');
        showAlert(panelAlert, 'Profile picture updated.', 'success');
      },
    });
  });

  document.getElementById('remove-avatar-btn')?.addEventListener('click', async () => {
    try {
      const res = await api('/api/user/avatar', { method: 'DELETE', body: {} });
      updateUserAvatarNodes(res.avatar_url);
      document.getElementById('remove-avatar-btn')?.classList.add('hidden');
      showAlert(panelAlert, 'Custom profile picture removed. Reverted to initial avatar.', 'success');
    } catch (err) { showAlert(panelAlert, err.message); }
  });

  document.getElementById('profile-form')?.addEventListener('submit', async (e) => {
    e.preventDefault();
    const fd = new FormData(e.target);
    try {
      await api('/api/user/profile', { method: 'PATCH', body: { name: fd.get('name') } });
      showAlert(panelAlert, 'Display name updated.', 'success');
    } catch (err) { showAlert(panelAlert, err.message); }
  });

  document.getElementById('email-form')?.addEventListener('submit', async (e) => {
    e.preventDefault();
    const fd = new FormData(e.target);
    try {
      const res = await api('/api/user/change-email', {
        method: 'POST',
        body: { newEmail: fd.get('newEmail'), currentPassword: fd.get('currentPassword') },
      });
      showAlert(panelAlert, res.message || 'Email updated.', 'success');
      e.target.reset();
    } catch (err) { showAlert(panelAlert, err.message); }
  });

  document.getElementById('password-form')?.addEventListener('submit', async (e) => {
    e.preventDefault();
    const fd = new FormData(e.target);
    try {
      const res = await api('/api/user/change-password', {
        method: 'POST',
        body: { currentPassword: fd.get('currentPassword'), newPassword: fd.get('newPassword') },
      });
      showAlert(panelAlert, res.message, 'success');
      e.target.reset();
    } catch (err) { showAlert(panelAlert, err.message); }
  });

  document.getElementById('totp-setup-btn')?.addEventListener('click', async () => {
    try {
      const res = await api('/api/user/2fa/setup', { method: 'POST', body: {} });
      const qrImg = document.getElementById('totp-qr-img');
      if (qrImg) qrImg.src = res.qrDataUrl;
      document.getElementById('totp-secret-out').textContent = res.secret;
      document.getElementById('totp-setup-box')?.classList.remove('hidden');
    } catch (err) { showAlert(panelAlert, err.message); }
  });

  document.getElementById('totp-verify-form')?.addEventListener('submit', async (e) => {
    e.preventDefault();
    const fd = new FormData(e.target);
    try {
      await api('/api/user/2fa/verify', { method: 'POST', body: { code: fd.get('code') } });
      location.reload();
    } catch (err) { showAlert(panelAlert, err.message); }
  });

  document.getElementById('totp-disable-form')?.addEventListener('submit', async (e) => {
    e.preventDefault();
    const fd = new FormData(e.target);
    try {
      await api('/api/user/2fa', { method: 'DELETE', body: { currentPassword: fd.get('currentPassword') } });
      location.reload();
    } catch (err) { showAlert(panelAlert, err.message); }
  });

  document.getElementById('delete-account-form')?.addEventListener('submit', async (e) => {
    e.preventDefault();
    if (!confirm('Permanently delete your JoeAuth account? This cannot be undone.')) return;
    const fd = new FormData(e.target);
    try {
      await api('/api/user/account', { method: 'DELETE', body: { currentPassword: fd.get('currentPassword') } });
      location.href = '/';
    } catch (err) { showAlert(panelAlert, err.message); }
  });

  const sessionsListEl = document.getElementById('sessions-list');
  async function loadSessions() {
    if (!sessionsListEl) return;
    try {
      const rows = await api('/api/user/sessions');
      sessionsListEl.innerHTML = rows.length
        ? `<table class="table table-sm table-hover align-middle mb-0"><thead><tr><th>Device / Agent</th><th>IP Hash</th><th>Last Active</th><th></th></tr></thead><tbody>${rows
            .map(
              (s) => `<tr>
                <td>${esc(s.user_agent || 'Unknown')} ${s.is_current ? '<span class="badge text-bg-success">Current</span>' : ''}</td>
                <td><code>${esc(s.ip_hash || '-')}</code></td>
                <td>${new Date(s.last_seen_at * 1000).toLocaleString()}</td>
                <td class="text-end">${s.is_current ? '' : `<button class="btn btn-sm btn-outline-secondary" data-revoke-session="${esc(s.id)}">Revoke</button>`}</td>
              </tr>`
            )
            .join('')}</tbody></table>`
        : '<p class="mb-0">No active sessions.</p>';
      sessionsListEl.querySelectorAll('[data-revoke-session]').forEach((btn) => {
        btn.addEventListener('click', async () => {
          await api(`/api/user/sessions/${btn.dataset.revokeSession}`, { method: 'DELETE', body: {} });
          loadSessions();
        });
      });
    } catch {}
  }
  loadSessions();

  document.getElementById('revoke-other-sessions')?.addEventListener('click', async () => {
    try {
      await api('/api/user/sessions', { method: 'DELETE', body: {} });
      showAlert(panelAlert, 'Other sessions signed out.', 'success');
      loadSessions();
    } catch (err) { showAlert(panelAlert, err.message); }
  });

  const connectedAppsEl = document.getElementById('connected-apps-list');
  async function loadConnectedApps() {
    if (!connectedAppsEl) return;
    try {
      const rows = await api('/api/user/apps');
      connectedAppsEl.innerHTML = rows.length
        ? `<table class="table table-sm table-hover align-middle mb-0"><thead><tr><th>App</th><th>Scopes</th><th>Granted</th><th></th></tr></thead><tbody>${rows
            .map(
              (a) => `<tr>
                <td>
                  <div class="d-flex align-items-center gap-2">
                    ${renderAppLogoHtml(a, 28)}
                    <a href="${esc(safeHttpUrl(a.homepage_url))}" target="_blank" rel="noopener noreferrer">${esc(a.name)}</a>
                  </div>
                </td>
                <td><code>${esc(a.scopes)}</code></td>
                <td>${new Date(a.granted_at * 1000).toLocaleDateString()}</td>
                <td class="text-end"><button class="btn btn-sm btn-outline-secondary" data-revoke-app="${esc(a.app_id)}">Revoke</button></td>
              </tr>`
            )
            .join('')}</tbody></table>`
        : '<p class="mb-0">No connected applications yet.</p>';
      connectedAppsEl.querySelectorAll('[data-revoke-app]').forEach((btn) => {
        btn.addEventListener('click', async () => {
          await api(`/api/user/apps/${btn.dataset.revokeApp}`, { method: 'DELETE', body: {} });
          loadConnectedApps();
        });
      });
    } catch {}
  }
  loadConnectedApps();

  // --- Developer Panel ---
  const devHistoryEl = document.getElementById('dev-status-history');
  if (devHistoryEl) {
    api('/api/dev/status').then((res) => {
      devHistoryEl.innerHTML = res.applications.length
        ? `<table class="table table-sm table-hover align-middle mb-0"><thead><tr><th>Reason</th><th>Status</th><th>Review Note</th></tr></thead><tbody>${res.applications
            .map(
              (a) => `<tr>
                <td>${esc(a.reason)}</td>
                <td><span class="badge ${a.status === 'approved' ? 'text-bg-success' : a.status === 'pending' ? 'text-bg-warning' : 'text-bg-danger'}">${esc(a.status)}</span></td>
                <td>${esc(a.review_note || '-')}</td>
              </tr>`
            )
            .join('')}</tbody></table>`
        : '<p class="mb-0">No applications submitted yet.</p>';
    }).catch(() => {});
  }

  document.getElementById('dev-apply-form')?.addEventListener('submit', async (e) => {
    e.preventDefault();
    const form = e.target;
    const fd = new FormData(form);
    try {
      await api('/api/dev/apply', {
        method: 'POST',
        body: {
          reason: fd.get('reason'),
          turnstileToken: getTurnstileToken(form),
        },
      });
      location.reload();
    } catch (err) {
      resetTurnstile();
      showAlert(panelAlert, err.message);
    }
  });

  const devAppsEl = document.getElementById('dev-apps-list');
  async function loadDevApps() {
    if (!devAppsEl) return;
    try {
      const apps = await api('/api/dev/apps');
      devAppsEl.innerHTML = apps.length
        ? apps
            .map(
              (a) => `<div class="card bg-body-tertiary border mb-2">
                <div class="card-body p-3">
                  <div class="d-flex justify-content-between align-items-start gap-2 mb-2">
                    <div class="d-flex align-items-center gap-2 min-w-0">
                      ${renderAppLogoHtml(a, 40)}
                      <div class="min-w-0">
                        <strong class="d-block text-truncate">${esc(a.name)}</strong>
                        <span class="small text-body-secondary text-break">${esc(a.homepage_url)}</span>
                      </div>
                    </div>
                    <span class="badge ${a.status === 'approved' ? 'text-bg-success' : 'text-bg-danger'}">${esc(a.status)}</span>
                  </div>
                  ${a.description ? `<div class="small mb-1">${esc(a.description)}</div>` : ''}
                  ${a.privilege_description ? `<div class="small text-body-secondary mb-1"><strong>Why access is requested:</strong> ${esc(a.privilege_description)}</div>` : ''}
                  <div class="small">Client ID: <code>${esc(a.client_id)}</code></div>
                  <div class="small text-body-secondary">Secret Prefix: <code>${esc(a.client_secret_prefix)}...</code></div>
                  <div class="small text-body-secondary">Redirects: ${a.redirect_uris.map((u) => `<code>${esc(u)}</code>`).join(', ')}</div>
                  <div class="d-flex flex-wrap gap-2 mt-2">
                    <label class="btn btn-sm btn-outline-primary mb-0">
                      <i class="bi bi-crop me-1"></i>${a.has_custom_logo ? 'Change Logo' : 'Upload Logo'}
                      <input type="file" accept="image/*" class="d-none" data-upload-app-logo="${esc(a.id)}">
                    </label>
                    ${a.has_custom_logo ? `<button class="btn btn-sm btn-outline-secondary" data-remove-app-logo="${esc(a.id)}"><i class="bi bi-x-circle me-1"></i>Reset Logo</button>` : ''}
                    <button class="btn btn-sm btn-outline-secondary" data-toggle-edit-app="${esc(a.id)}"><i class="bi bi-pencil me-1"></i>Edit</button>
                    <button class="btn btn-sm btn-outline-secondary" data-rotate-app="${esc(a.id)}"><i class="bi bi-arrow-repeat me-1"></i>Rotate Secret</button>
                    <button class="btn btn-sm btn-danger" data-delete-app="${esc(a.id)}"><i class="bi bi-trash me-1"></i>Delete</button>
                  </div>
                  <form class="hidden mt-3 pt-3 border-top" data-edit-app-form="${esc(a.id)}">
                    <div class="mb-2">
                      <label class="form-label small mb-1">Application Name</label>
                      <input class="form-control form-control-sm" type="text" name="name" value="${esc(a.name)}" required minlength="2" maxlength="64">
                    </div>
                    <div class="mb-2">
                      <label class="form-label small mb-1">Homepage URL</label>
                      <input class="form-control form-control-sm" type="url" name="homepageUrl" value="${esc(a.homepage_url)}" required>
                    </div>
                    <div class="mb-2">
                      <label class="form-label small mb-1">App Description (optional)</label>
                      <input class="form-control form-control-sm" type="text" name="description" value="${esc(a.description || '')}" maxlength="300">
                    </div>
                    <div class="mb-2">
                      <label class="form-label small mb-1">Privilege Description (optional)</label>
                      <textarea class="form-control form-control-sm" name="privilegeDescription" rows="2" maxlength="400">${esc(a.privilege_description || '')}</textarea>
                    </div>
                    <div class="mb-2">
                      <label class="form-label small mb-1">Redirect URIs (one per line)</label>
                      <textarea class="form-control form-control-sm font-monospace" name="redirectUris" rows="2" required>${esc(a.redirect_uris.join('\n'))}</textarea>
                    </div>
                    <div class="d-flex flex-wrap gap-3 mb-2 small">
                      <label class="form-check-label"><input class="form-check-input me-1" type="checkbox" checked disabled> openid</label>
                      <label class="form-check-label"><input class="form-check-input me-1" type="checkbox" name="scopes" value="profile" ${a.allowed_scopes.includes('profile') ? 'checked' : ''}> profile</label>
                      <label class="form-check-label"><input class="form-check-input me-1" type="checkbox" name="scopes" value="email" ${a.allowed_scopes.includes('email') ? 'checked' : ''}> email</label>
                      <label class="form-check-label"><input class="form-check-input me-1" type="checkbox" name="scopes" value="offline_access" ${a.allowed_scopes.includes('offline_access') ? 'checked' : ''}> offline_access</label>
                    </div>
                    <button type="submit" class="btn btn-sm btn-primary"><i class="bi bi-check2 me-1"></i>Save Changes</button>
                  </form>
                </div>
              </div>`
            )
            .join('')
        : '<p class="mb-0">No OAuth applications created yet.</p>';

      devAppsEl.querySelectorAll('[data-upload-app-logo]').forEach((input) => {
        input.addEventListener('change', () => {
          const file = input.files?.[0];
          const appId = input.dataset.uploadAppLogo;
          input.value = '';
          if (!file || !appId) return;
          openImageCropper(file, {
            title: 'Crop App Logo (256×256 PNG)',
            onConfirm: async (blob) => {
              const fd = new FormData();
              fd.append('file', blob, 'logo.png');
              await api(`/api/dev/apps/${appId}/logo`, { method: 'POST', body: fd });
              showAlert(panelAlert, 'Application logo updated.', 'success');
              loadDevApps();
            },
          });
        });
      });

      devAppsEl.querySelectorAll('[data-remove-app-logo]').forEach((btn) => {
        btn.addEventListener('click', async () => {
          try {
            await api(`/api/dev/apps/${btn.dataset.removeAppLogo}/logo`, { method: 'DELETE', body: {} });
            showAlert(panelAlert, 'Application logo reset to default icon.', 'success');
            loadDevApps();
          } catch (err) { showAlert(panelAlert, err.message); }
        });
      });

      devAppsEl.querySelectorAll('[data-toggle-edit-app]').forEach((btn) => {
        btn.addEventListener('click', () => {
          const form = devAppsEl.querySelector(`[data-edit-app-form="${btn.dataset.toggleEditApp}"]`);
          form?.classList.toggle('hidden');
        });
      });

      devAppsEl.querySelectorAll('[data-edit-app-form]').forEach((form) => {
        form.addEventListener('submit', async (e) => {
          e.preventDefault();
          const appId = form.dataset.editAppForm;
          const fd = new FormData(form);
          const redirectUris = String(fd.get('redirectUris') || '')
            .split(/\r?\n/)
            .map((s) => s.trim())
            .filter(Boolean);
          const allowedScopes = ['openid', ...Array.from(form.querySelectorAll('input[name="scopes"]:checked')).map((i) => i.value)];
          try {
            await api(`/api/dev/apps/${appId}`, {
              method: 'PATCH',
              body: {
                name: fd.get('name'),
                homepageUrl: fd.get('homepageUrl'),
                description: fd.get('description'),
                privilegeDescription: fd.get('privilegeDescription'),
                redirectUris,
                allowedScopes: Array.from(new Set(allowedScopes)),
              },
            });
            showAlert(panelAlert, 'Application details updated.', 'success');
            loadDevApps();
          } catch (err) { showAlert(panelAlert, err.message); }
        });
      });

      devAppsEl.querySelectorAll('[data-rotate-app]').forEach((btn) => {
        btn.addEventListener('click', async () => {
          const pwd = prompt('Confirm your password to rotate the Client Secret:');
          if (!pwd) return;
          try {
            const res = await api(`/api/dev/apps/${btn.dataset.rotateApp}/rotate-secret`, {
              method: 'POST',
              body: { currentPassword: pwd },
            });
            document.getElementById('reveal-client-id').textContent = '(unchanged)';
            document.getElementById('reveal-client-secret').textContent = res.client_secret;
            document.getElementById('secret-reveal-box')?.classList.remove('hidden');
            loadDevApps();
          } catch (err) { showAlert(panelAlert, err.message); }
        });
      });

      devAppsEl.querySelectorAll('[data-delete-app]').forEach((btn) => {
        btn.addEventListener('click', async () => {
          if (!confirm('Delete this application and revoke all tokens?')) return;
          try {
            await api(`/api/dev/apps/${btn.dataset.deleteApp}`, { method: 'DELETE', body: {} });
            loadDevApps();
          } catch (err) { showAlert(panelAlert, err.message); }
        });
      });
    } catch {}
  }
  loadDevApps();

  let pendingCreateAppLogoBlob = null;
  let pendingCreateAppLogoUrl = null;
  const createLogoInput = document.getElementById('create-app-logo-input');
  const clearCreateLogoBtn = document.getElementById('clear-create-app-logo-btn');

  function resetCreateAppLogoPreview() {
    if (pendingCreateAppLogoUrl) {
      URL.revokeObjectURL(pendingCreateAppLogoUrl);
      pendingCreateAppLogoUrl = null;
    }
    pendingCreateAppLogoBlob = null;
    const prev = document.getElementById('create-app-logo-preview');
    if (prev && prev.tagName === 'IMG') {
      const span = document.createElement('span');
      span.id = 'create-app-logo-preview';
      span.className = 'app-icon-badge';
      span.style.width = '48px';
      span.style.height = '48px';
      span.style.fontSize = '24px';
      span.innerHTML = '<i class="bi bi-app-indicator"></i>';
      prev.replaceWith(span);
    }
    clearCreateLogoBtn?.classList.add('hidden');
  }

  createLogoInput?.addEventListener('change', () => {
    const file = createLogoInput.files?.[0];
    createLogoInput.value = '';
    if (!file) return;
    openImageCropper(file, {
      title: 'Crop App Logo (256×256 PNG)',
      onConfirm: async (blob) => {
        if (pendingCreateAppLogoUrl) URL.revokeObjectURL(pendingCreateAppLogoUrl);
        pendingCreateAppLogoBlob = blob;
        pendingCreateAppLogoUrl = URL.createObjectURL(blob);
        const prev = document.getElementById('create-app-logo-preview');
        if (prev) {
          const img = document.createElement('img');
          img.id = 'create-app-logo-preview';
          img.src = pendingCreateAppLogoUrl;
          img.alt = 'Selected app logo';
          img.width = 48;
          img.height = 48;
          img.className = 'rounded border object-fit-cover flex-shrink-0';
          img.style.width = '48px';
          img.style.height = '48px';
          prev.replaceWith(img);
        }
        clearCreateLogoBtn?.classList.remove('hidden');
      },
    });
  });

  clearCreateLogoBtn?.addEventListener('click', resetCreateAppLogoPreview);

  document.getElementById('create-app-form')?.addEventListener('submit', async (e) => {
    e.preventDefault();
    const form = e.target;
    const fd = new FormData(form);
    const redirectUris = String(fd.get('redirectUris') || '')
      .split(/\r?\n/)
      .map((s) => s.trim())
      .filter(Boolean);
    const allowedScopes = ['openid', ...Array.from(form.querySelectorAll('input[name="scopes"]:checked')).map((i) => i.value)];
    try {
      const created = await api('/api/dev/apps', {
        method: 'POST',
        body: {
          name: fd.get('name'),
          homepageUrl: fd.get('homepageUrl'),
          description: fd.get('description'),
          privilegeDescription: fd.get('privilegeDescription'),
          redirectUris,
          allowedScopes: Array.from(new Set(allowedScopes)),
        },
      });
      if (pendingCreateAppLogoBlob) {
        const logoFd = new FormData();
        logoFd.append('file', pendingCreateAppLogoBlob, 'logo.png');
        await api(`/api/dev/apps/${created.id}/logo`, { method: 'POST', body: logoFd });
      }
      document.getElementById('reveal-client-id').textContent = created.client_id;
      document.getElementById('reveal-client-secret').textContent = created.client_secret;
      document.getElementById('secret-reveal-box')?.classList.remove('hidden');
      form.reset();
      resetCreateAppLogoPreview();
      loadDevApps();
    } catch (err) { showAlert(panelAlert, err.message); }
  });

  // --- Admin Panel ---
  const adminRoot = document.getElementById('admin-root');
  if (adminRoot) {
    const isSuperuser = adminRoot.dataset.isSuperuser === '1';
    const currentUserId = adminRoot.dataset.currentUserId || '';

    function openAdminPasswordModal(userEmail, onConfirm) {
      const backdrop = document.createElement('div');
      backdrop.className = 'cropper-backdrop';
      backdrop.innerHTML = `
        <div class="card shadow-lg cropper-dialog">
          <div class="card-body p-3">
            <div class="d-flex justify-content-between align-items-center mb-2">
              <h2 class="h6 fw-semibold mb-0"><i class="bi bi-key me-2 text-primary"></i>Set Password</h2>
              <button type="button" class="btn-close" aria-label="Close" data-pwd-cancel></button>
            </div>
            <p class="text-body-secondary small mb-3">
              Set a new password for <strong>${esc(userEmail)}</strong>. Existing sessions and refresh tokens for this user will be revoked.
            </p>
            <form data-pwd-form>
              <div class="mb-2">
                <label class="form-label small mb-1">New Password (min 8 chars)</label>
                <input type="password" class="form-control" name="newPassword" minlength="8" maxlength="128" required autocomplete="new-password" data-pwd-input>
              </div>
              <div class="form-check mb-3">
                <input class="form-check-input" type="checkbox" id="admin-pwd-show" data-pwd-toggle>
                <label class="form-check-label small" for="admin-pwd-show">Show password</label>
              </div>
              <div class="alert alert-danger py-1 px-2 small hidden" data-pwd-err></div>
              <div class="d-flex gap-2">
                <button type="button" class="btn btn-outline-secondary flex-fill" data-pwd-cancel>Cancel</button>
                <button type="submit" class="btn btn-primary flex-fill"><i class="bi bi-check-lg me-1"></i>Update Password</button>
              </div>
            </form>
          </div>
        </div>
      `;
      document.body.appendChild(backdrop);

      const pwdInput = backdrop.querySelector('[data-pwd-input]');
      const errEl = backdrop.querySelector('[data-pwd-err]');
      pwdInput?.focus();

      backdrop.querySelector('[data-pwd-toggle]')?.addEventListener('change', (ev) => {
        if (pwdInput) pwdInput.type = ev.target.checked ? 'text' : 'password';
      });
      backdrop.querySelectorAll('[data-pwd-cancel]').forEach((b) =>
        b.addEventListener('click', () => backdrop.remove())
      );
      backdrop.querySelector('[data-pwd-form]')?.addEventListener('submit', async (ev) => {
        ev.preventDefault();
        errEl.classList.add('hidden');
        try {
          await onConfirm(pwdInput.value);
          backdrop.remove();
        } catch (err) {
          errEl.textContent = err.message || 'Failed to update password.';
          errEl.classList.remove('hidden');
        }
      });
    }

    async function loadAdminOverview() {
      const data = await api('/api/admin/overview');
      document.getElementById('stat-users').textContent = data.stats.users;
      document.getElementById('stat-pending-devs').textContent = data.stats.pendingDeveloperApplications;
      document.getElementById('stat-apps').textContent = data.stats.apps;
      document.getElementById('stat-rules').textContent = data.stats.activeRules;
      const verifyBox = document.getElementById('setting-require-email-verify');
      if (verifyBox) verifyBox.checked = data.settings.require_email_verification;

      if (data.maintenance) {
        const m = data.maintenance;
        const setTxt = (id, val) => {
          const node = document.getElementById(id);
          if (node) node.textContent = String(val ?? 0);
        };
        setTxt('count-log-failures', m.authFailureLogs);
        setTxt('count-log-user', m.userLogs);
        setTxt('count-log-dev', m.devLogs);
        setTxt('count-log-oauth', m.oauthLogs);
        setTxt('count-log-admin', m.adminLogs);
        setTxt('count-log-total', m.auditLogsTotal);
        setTxt('count-stale-sessions', m.expiredSessions);
        setTxt('count-stale-tokens', m.expiredVerificationTokens);
        setTxt('count-stale-codes', m.staleOAuthCodes);
        setTxt('count-stale-refresh', m.staleRefreshTokens);
      }
    }

    async function loadAuditLogs() {
      const form = document.getElementById('admin-audit-filter-form');
      const category = form?.querySelector('[name="category"]')?.value || 'all';
      const q = form?.querySelector('[name="q"]')?.value || '';
      const logs = await api(`/api/admin/audit-logs?category=${encodeURIComponent(category)}&q=${encodeURIComponent(q)}`);
      const auditEl = document.getElementById('admin-audit-list');
      auditEl.innerHTML = logs.length
        ? `<table class="table table-sm table-hover align-middle mb-0"><thead><tr><th>Time</th><th>Actor</th><th>Action</th><th>Target</th><th>Metadata</th></tr></thead><tbody>${logs
            .map(
              (l) => `<tr>
                <td class="text-nowrap">${new Date(l.created_at * 1000).toLocaleString()}</td>
                <td><code>${esc(l.actor_id || '-')}</code></td>
                <td><code>${esc(l.action)}</code></td>
                <td>${esc(l.target_type || '')} ${esc(l.target_id || '')}</td>
                <td><code>${esc(l.metadata || '')}</code></td>
              </tr>`
            )
            .join('')}</tbody></table>`
        : '<p class="mb-0">No matching audit logs.</p>';
    }

    document.getElementById('admin-audit-filter-form')?.addEventListener('submit', (e) => {
      e.preventDefault();
      loadAuditLogs().catch((err) => showAlert(panelAlert, err.message));
    });
    document.querySelector('#admin-audit-filter-form [name="category"]')?.addEventListener('change', () => {
      loadAuditLogs().catch((err) => showAlert(panelAlert, err.message));
    });

    const auditPurgeLabels = {
      auth_failures: 'failed login audit logs',
      user: 'user activity audit logs',
      dev: 'developer activity audit logs',
      oauth: 'OAuth activity audit logs',
      admin: 'admin/superuser audit logs',
      older_than_30d: 'audit logs older than 30 days',
      all: 'ALL audit logs',
    };
    document.querySelectorAll('[data-purge-audit]').forEach((btn) => {
      btn.addEventListener('click', async () => {
        const category = btn.dataset.purgeAudit;
        const label = auditPurgeLabels[category] || category;
        if (!confirm(`Purge ${label}? This cannot be undone.`)) return;
        try {
          const res = await api('/api/admin/audit-logs/purge', {
            method: 'POST',
            body: { category },
          });
          showAlert(panelAlert, `Purged ${res.deleted} audit log entry(ies).`, 'success');
          loadAdminOverview();
          loadAuditLogs();
        } catch (err) { showAlert(panelAlert, err.message); }
      });
    });

    const maintPurgeLabels = {
      expired_sessions: 'expired sessions',
      expired_tokens: 'expired verification/reset tokens',
      expired_oauth_codes: 'used or expired OAuth codes',
      revoked_refresh_tokens: 'revoked or expired refresh tokens',
      all_stale: 'ALL stale sessions, tokens, and codes',
    };
    document.querySelectorAll('[data-purge-maint]').forEach((btn) => {
      btn.addEventListener('click', async () => {
        const target = btn.dataset.purgeMaint;
        const label = maintPurgeLabels[target] || target;
        if (!confirm(`Purge ${label}?`)) return;
        try {
          const res = await api('/api/admin/maintenance/purge', {
            method: 'POST',
            body: { target },
          });
          showAlert(panelAlert, `Purged ${res.deleted} stale record(s).`, 'success');
          loadAdminOverview();
          loadAuditLogs();
        } catch (err) { showAlert(panelAlert, err.message); }
      });
    });

    document.getElementById('setting-require-email-verify')?.addEventListener('change', async (e) => {
      try {
        await api('/api/admin/settings', {
          method: 'PATCH',
          body: { requireEmailVerification: e.target.checked },
        });
        showAlert(panelAlert, 'System setting updated.', 'success');
      } catch (err) { showAlert(panelAlert, err.message); }
    });

    async function loadRules() {
      const data = await api('/api/admin/rules');
      const el = document.getElementById('admin-rules-list');
      el.innerHTML = data.rules.length
        ? `<table class="table table-sm table-hover align-middle mb-0"><thead><tr><th>Priority</th><th>Type</th><th>Regex Pattern</th><th>Description</th><th>Active</th><th></th></tr></thead><tbody>${data.rules
            .map(
              (r) => `<tr>
                <td>${r.priority}</td>
                <td><span class="badge ${r.rule_type === 'allow' ? 'text-bg-success' : 'text-bg-danger'}">${esc(r.rule_type)}</span></td>
                <td><code>${esc(r.pattern)}</code></td>
                <td>${esc(r.description)}</td>
                <td><button class="btn btn-sm btn-outline-secondary" data-toggle-rule="${esc(r.id)}" data-active="${r.is_active}">${r.is_active ? 'Enabled' : 'Disabled'}</button></td>
                <td class="text-end"><button class="btn btn-sm btn-danger" data-del-rule="${esc(r.id)}">Delete</button></td>
              </tr>`
            )
            .join('')}</tbody></table>`
        : '<div class="alert alert-danger mb-0">No registration rules exist yet — all registrations are currently denied by default.</div>';

      el.querySelectorAll('[data-toggle-rule]').forEach((btn) => {
        btn.addEventListener('click', async () => {
          try {
            await api(`/api/admin/rules/${btn.dataset.toggleRule}`, {
              method: 'PATCH',
              body: { isActive: btn.dataset.active !== '1' },
            });
            loadRules();
            loadAdminOverview();
          } catch (err) { showAlert(panelAlert, err.message); }
        });
      });
      el.querySelectorAll('[data-del-rule]').forEach((btn) => {
        btn.addEventListener('click', async () => {
          try {
            await api(`/api/admin/rules/${btn.dataset.delRule}`, { method: 'DELETE', body: {} });
            loadRules();
            loadAdminOverview();
            loadAuditLogs();
          } catch (err) { showAlert(panelAlert, err.message); }
        });
      });
    }

    document.querySelectorAll('[data-rule-template]').forEach((btn) => {
      btn.addEventListener('click', () => {
        const form = document.getElementById('add-rule-form');
        form.querySelector('[name="ruleType"]').value = btn.dataset.type;
        form.querySelector('[name="pattern"]').value = btn.dataset.pattern;
        form.querySelector('[name="priority"]').value = btn.dataset.priority;
        form.querySelector('[name="description"]').value = btn.dataset.description;
      });
    });

    document.getElementById('add-rule-form')?.addEventListener('submit', async (e) => {
      e.preventDefault();
      const fd = new FormData(e.target);
      try {
        await api('/api/admin/rules', {
          method: 'POST',
          body: {
            ruleType: fd.get('ruleType'),
            priority: Number(fd.get('priority')),
            pattern: fd.get('pattern'),
            description: fd.get('description'),
          },
        });
        e.target.reset();
        loadRules();
        loadAdminOverview();
        loadAuditLogs();
      } catch (err) { showAlert(panelAlert, err.message); }
    });

    document.getElementById('test-rule-form')?.addEventListener('submit', async (e) => {
      e.preventDefault();
      const fd = new FormData(e.target);
      const res = await api('/api/admin/rules/test', { method: 'POST', body: { email: fd.get('email') } });
      const out = document.getElementById('rule-test-result');
      out.textContent = `${res.allowed ? 'ALLOWED' : 'DENIED'} — ${res.reason}`;
      out.className = `small fw-semibold ${res.allowed ? 'text-success' : 'text-danger'}`;
    });

    async function loadDevApplications() {
      const rows = await api('/api/admin/dev-applications');
      const el = document.getElementById('admin-dev-apps-list');
      el.innerHTML = rows.length
        ? `<table class="table table-sm table-hover align-middle mb-0"><thead><tr><th>User</th><th>Reason</th><th>Status</th><th>Actions</th></tr></thead><tbody>${rows
            .map(
              (a) => `<tr>
                <td>${esc(a.user_name)}<br><span class="text-body-secondary">${esc(a.user_email)}</span></td>
                <td>${esc(a.reason)}</td>
                <td><span class="badge ${a.status === 'approved' ? 'text-bg-success' : a.status === 'pending' ? 'text-bg-warning' : 'text-bg-danger'}">${esc(a.status)}</span></td>
                <td>
                  ${a.status === 'pending'
                    ? `<div class="d-flex gap-2">
                        <button class="btn btn-sm btn-primary" data-dev-decision="approved" data-id="${esc(a.id)}"><i class="bi bi-check-lg me-1"></i>Approve</button>
                        <button class="btn btn-sm btn-danger" data-dev-decision="rejected" data-id="${esc(a.id)}"><i class="bi bi-x-lg me-1"></i>Reject</button>
                      </div>`
                    : `<span class="text-body-secondary">${esc(a.reviewed_by || '')}</span>`}
                </td>
              </tr>`
            )
            .join('')}</tbody></table>`
        : '<p class="mb-0">No developer applications.</p>';

      el.querySelectorAll('[data-dev-decision]').forEach((btn) => {
        btn.addEventListener('click', async () => {
          const note = btn.dataset.devDecision === 'rejected' ? (prompt('Rejection note (optional):') || '') : '';
          try {
            await api(`/api/admin/dev-applications/${btn.dataset.id}`, {
              method: 'PATCH',
              body: { decision: btn.dataset.devDecision, reviewNote: note },
            });
            loadDevApplications();
            loadUsers();
            loadAdminOverview();
            loadAuditLogs();
          } catch (err) { showAlert(panelAlert, err.message); }
        });
      });
    }

    function getUserFilterQuery() {
      const form = document.getElementById('admin-user-search-form');
      if (!form) return '';
      const fd = new FormData(form);
      const params = new URLSearchParams();
      for (const k of ['q', 'status', 'role', 'developerStatus']) {
        const v = String(fd.get(k) || '').trim();
        if (v && v !== 'all') params.set(k, v);
      }
      return params.toString();
    }

    async function loadUsers() {
      const qs = getUserFilterQuery();
      const rows = await api(`/api/admin/users${qs ? `?${qs}` : ''}`);
      const el = document.getElementById('admin-users-list');
      el.innerHTML = rows.length
        ? `<table class="table table-sm table-hover align-middle mb-0"><thead><tr><th>User</th><th>Role</th><th>Dev</th><th>Status</th><th>Actions</th></tr></thead><tbody>${rows
            .map((u) => {
              const isSelf = Boolean(currentUserId && u.id === currentUserId);
              const isProtectedAdmin = !isSuperuser && u.role === 'admin' && !isSelf;
              const cannotModifyDestructive = isSelf || isProtectedAdmin;
              const devBadge =
                u.developer_status === 'approved'
                  ? 'text-bg-success'
                  : u.developer_status === 'pending'
                    ? 'text-bg-warning'
                    : u.developer_status === 'revoked'
                      ? 'text-bg-danger'
                      : 'text-bg-secondary';
              const nextDev = u.developer_status === 'approved' ? 'revoked' : 'approved';
              return `<tr>
                <td>
                  <div class="d-flex align-items-center gap-2">
                    <img src="${esc(u.avatar_url)}" alt="${esc(u.name)}" width="32" height="32" class="rounded-circle border object-fit-cover flex-shrink-0">
                    <div>
                      <strong>${esc(u.name)}</strong>
                      ${isSelf ? '<span class="badge text-bg-info ms-1">You</span>' : ''}
                      ${u.totp_enabled ? '<span class="badge text-bg-secondary ms-1" title="2FA enabled">2FA</span>' : ''}
                      <br>
                      <span class="text-body-secondary">${esc(u.email)}</span>
                      ${u.email_verified ? ' <span class="text-success" title="Email verified">✓</span>' : ' <span class="badge text-bg-warning">unverified</span>'}
                    </div>
                  </div>
                </td>
                <td><span class="badge ${u.role === 'admin' ? 'text-bg-success' : 'text-bg-secondary'}">${esc(u.role)}</span></td>
                <td><span class="badge ${devBadge}">${esc(u.developer_status)}</span></td>
                <td><span class="badge ${u.status === 'active' ? 'text-bg-success' : 'text-bg-danger'}">${esc(u.status)}</span></td>
                <td>
                  <div class="d-flex flex-wrap gap-1">
                    <button
                      class="btn btn-sm ${u.status === 'active' ? 'btn-outline-warning' : 'btn-outline-success'}"
                      data-toggle-user="${esc(u.id)}"
                      data-status="${esc(u.status)}"
                      ${u.status === 'active' && cannotModifyDestructive ? `disabled title="${isSelf ? 'You cannot suspend your own active account' : 'Only Superuser can suspend another admin'}"` : ''}
                    >
                      <i class="bi ${u.status === 'active' ? 'bi-pause-circle' : 'bi-play-circle'} me-1"></i>${u.status === 'active' ? 'Suspend' : 'Activate'}
                    </button>
                    <button
                      class="btn btn-sm ${nextDev === 'approved' ? 'btn-outline-primary' : 'btn-outline-secondary'}"
                      data-dev-status="${esc(u.id)}"
                      data-next-dev="${nextDev}"
                    >
                      <i class="bi ${nextDev === 'approved' ? 'bi-code-square' : 'bi-slash-circle'} me-1"></i>${nextDev === 'approved' ? 'Grant Dev' : 'Revoke Dev'}
                    </button>
                    <button
                      class="btn btn-sm btn-outline-secondary"
                      data-set-pwd="${esc(u.id)}"
                      data-email="${esc(u.email)}"
                      ${isProtectedAdmin ? 'disabled title="Only Superuser can set another admin password"' : ''}
                    >
                      <i class="bi bi-key me-1"></i>Set Password
                    </button>
                    <button
                      class="btn btn-sm btn-outline-secondary"
                      data-verify-user="${esc(u.id)}"
                      data-next-verified="${u.email_verified ? '0' : '1'}"
                    >
                      <i class="bi ${u.email_verified ? 'bi-envelope-dash' : 'bi-envelope-check'} me-1"></i>${u.email_verified ? 'Unverify Email' : 'Verify Email'}
                    </button>
                    ${u.totp_enabled ? `<button class="btn btn-sm btn-outline-secondary" data-reset-2fa="${esc(u.id)}" data-email="${esc(u.email)}" ${isProtectedAdmin ? 'disabled' : ''}><i class="bi bi-shield-slash me-1"></i>Reset 2FA</button>` : ''}
                    <button
                      class="btn btn-sm btn-outline-secondary"
                      data-revoke-sessions="${esc(u.id)}"
                      data-email="${esc(u.email)}"
                      ${isProtectedAdmin ? 'disabled title="Only Superuser can revoke sessions for another admin"' : isSelf ? 'title="Revoke other sessions &amp; refresh tokens (keeps current session)"' : ''}
                    >
                      <i class="bi bi-box-arrow-right me-1"></i>Revoke Sessions
                    </button>
                    ${isSuperuser ? `<button class="btn btn-sm btn-outline-secondary" data-role-user="${esc(u.id)}" data-next-role="${u.role === 'admin' ? 'user' : 'admin'}">${u.role === 'admin' ? 'Demote Admin' : 'Make Admin'}</button>` : ''}
                    <button
                      class="btn btn-sm btn-outline-danger"
                      data-delete-user="${esc(u.id)}"
                      data-email="${esc(u.email)}"
                      ${cannotModifyDestructive ? `disabled title="${isSelf ? 'You cannot delete your own active account' : 'Only Superuser can delete an admin account'}"` : ''}
                    >
                      <i class="bi bi-trash me-1"></i>Delete
                    </button>
                  </div>
                </td>
              </tr>`;
            })
            .join('')}</tbody></table>`
        : '<p class="mb-0">No users found.</p>';

      el.querySelectorAll('[data-toggle-user]').forEach((btn) => {
        btn.addEventListener('click', async () => {
          try {
            await api(`/api/admin/users/${btn.dataset.toggleUser}/status`, {
              method: 'PATCH',
              body: { status: btn.dataset.status === 'active' ? 'suspended' : 'active' },
            });
            showAlert(panelAlert, 'User account status updated.', 'success');
            loadUsers();
            loadAuditLogs();
          } catch (err) { showAlert(panelAlert, err.message); }
        });
      });

      el.querySelectorAll('[data-dev-status]').forEach((btn) => {
        btn.addEventListener('click', async () => {
          try {
            await api(`/api/admin/users/${btn.dataset.devStatus}/developer-status`, {
              method: 'PATCH',
              body: { developerStatus: btn.dataset.nextDev },
            });
            showAlert(panelAlert, `Developer privilege ${btn.dataset.nextDev === 'approved' ? 'granted' : 'revoked'}.`, 'success');
            loadUsers();
            loadAuditLogs();
          } catch (err) { showAlert(panelAlert, err.message); }
        });
      });

      el.querySelectorAll('[data-set-pwd]').forEach((btn) => {
        btn.addEventListener('click', () => {
          openAdminPasswordModal(btn.dataset.email, async (newPassword) => {
            await api(`/api/admin/users/${btn.dataset.setPwd}/password`, {
              method: 'POST',
              body: { newPassword },
            });
            showAlert(panelAlert, `Password updated for ${btn.dataset.email}.`, 'success');
            loadAuditLogs();
          });
        });
      });

      el.querySelectorAll('[data-verify-user]').forEach((btn) => {
        btn.addEventListener('click', async () => {
          try {
            await api(`/api/admin/users/${btn.dataset.verifyUser}/status`, {
              method: 'PATCH',
              body: { emailVerified: btn.dataset.nextVerified === '1' },
            });
            showAlert(panelAlert, 'Email verification status updated.', 'success');
            loadUsers();
            loadAuditLogs();
          } catch (err) { showAlert(panelAlert, err.message); }
        });
      });

      el.querySelectorAll('[data-reset-2fa]').forEach((btn) => {
        btn.addEventListener('click', async () => {
          if (!confirm(`Disable two-factor authentication (2FA) for ${btn.dataset.email}?`)) return;
          try {
            await api(`/api/admin/users/${btn.dataset.reset2fa}/2fa`, { method: 'DELETE', body: {} });
            showAlert(panelAlert, `2FA disabled for ${btn.dataset.email}.`, 'success');
            loadUsers();
            loadAuditLogs();
          } catch (err) { showAlert(panelAlert, err.message); }
        });
      });

      el.querySelectorAll('[data-revoke-sessions]').forEach((btn) => {
        btn.addEventListener('click', async () => {
          if (!confirm(`Revoke sessions and refresh tokens for ${btn.dataset.email}?`)) return;
          try {
            await api(`/api/admin/users/${btn.dataset.revokeSessions}/revoke-sessions`, { method: 'POST', body: {} });
            showAlert(panelAlert, `Sessions revoked for ${btn.dataset.email}.`, 'success');
            loadAdminOverview();
            loadAuditLogs();
          } catch (err) { showAlert(panelAlert, err.message); }
        });
      });

      el.querySelectorAll('[data-role-user]').forEach((btn) => {
        btn.addEventListener('click', async () => {
          try {
            await api(`/api/admin/users/${btn.dataset.roleUser}/role`, {
              method: 'PATCH',
              body: { role: btn.dataset.nextRole },
            });
            showAlert(panelAlert, 'User role updated.', 'success');
            loadUsers();
            loadAuditLogs();
          } catch (err) { showAlert(panelAlert, err.message); }
        });
      });

      el.querySelectorAll('[data-delete-user]').forEach((btn) => {
        btn.addEventListener('click', async () => {
          if (!confirm(`Permanently delete account "${btn.dataset.email}" and all of its apps, logos, and tokens? This cannot be undone.`)) return;
          try {
            await api(`/api/admin/users/${btn.dataset.deleteUser}`, { method: 'DELETE', body: {} });
            showAlert(panelAlert, `Account ${btn.dataset.email} deleted.`, 'success');
            loadUsers();
            loadAdminApps();
            loadDevApplications();
            loadAdminOverview();
            loadAuditLogs();
          } catch (err) { showAlert(panelAlert, err.message); }
        });
      });
    }

    document.getElementById('admin-user-search-form')?.addEventListener('submit', (e) => {
      e.preventDefault();
      loadUsers().catch((err) => showAlert(panelAlert, err.message));
    });
    document.querySelectorAll('#admin-user-search-form select').forEach((sel) => {
      sel.addEventListener('change', () => loadUsers().catch((err) => showAlert(panelAlert, err.message)));
    });

    async function loadAdminApps() {
      const rows = await api('/api/admin/apps');
      const el = document.getElementById('admin-apps-list');
      el.innerHTML = rows.length
        ? `<table class="table table-sm table-hover align-middle mb-0"><thead><tr><th>Name</th><th>Client ID</th><th>Owner</th><th>Status</th><th>Actions</th></tr></thead><tbody>${rows
            .map(
              (a) => `<tr>
                <td>
                  <div class="d-flex align-items-center gap-2">
                    ${renderAppLogoHtml(a, 32)}
                    <div><strong>${esc(a.name)}</strong><br><span class="text-body-secondary">${esc(a.homepage_url)}</span></div>
                  </div>
                </td>
                <td><code>${esc(a.client_id)}</code></td>
                <td>${esc(a.owner_email)}</td>
                <td><span class="badge ${a.status === 'approved' ? 'text-bg-success' : 'text-bg-danger'}">${esc(a.status)}</span> ${a.is_first_party ? '<span class="badge text-bg-info">1st-party</span>' : ''}</td>
                <td>
                  <div class="d-flex flex-wrap gap-1">
                    <button class="btn btn-sm btn-outline-secondary" data-app-status="${esc(a.id)}" data-next="${a.status === 'approved' ? 'suspended' : 'approved'}">${a.status === 'approved' ? 'Suspend' : 'Restore'}</button>
                    <button class="btn btn-sm btn-outline-secondary" data-app-fp="${esc(a.id)}" data-fp="${a.is_first_party ? '0' : '1'}">${a.is_first_party ? 'Unmark 1st-party' : 'Mark 1st-party'}</button>
                    <button class="btn btn-sm btn-outline-danger" data-admin-del-app="${esc(a.id)}" data-name="${esc(a.name)}"><i class="bi bi-trash me-1"></i>Delete</button>
                  </div>
                </td>
              </tr>`
            )
            .join('')}</tbody></table>`
        : '<p class="mb-0">No OAuth apps registered.</p>';

      el.querySelectorAll('[data-app-status]').forEach((btn) => {
        btn.addEventListener('click', async () => {
          try {
            await api(`/api/admin/apps/${btn.dataset.appStatus}`, {
              method: 'PATCH',
              body: { status: btn.dataset.next },
            });
            loadAdminApps();
            loadAuditLogs();
          } catch (err) { showAlert(panelAlert, err.message); }
        });
      });
      el.querySelectorAll('[data-app-fp]').forEach((btn) => {
        btn.addEventListener('click', async () => {
          try {
            await api(`/api/admin/apps/${btn.dataset.appFp}`, {
              method: 'PATCH',
              body: { isFirstParty: btn.dataset.fp === '1' },
            });
            loadAdminApps();
            loadAuditLogs();
          } catch (err) { showAlert(panelAlert, err.message); }
        });
      });
      el.querySelectorAll('[data-admin-del-app]').forEach((btn) => {
        btn.addEventListener('click', async () => {
          if (!confirm(`Delete OAuth app "${btn.dataset.name}" and revoke all its tokens?`)) return;
          try {
            await api(`/api/admin/apps/${btn.dataset.adminDelApp}`, { method: 'DELETE', body: {} });
            showAlert(panelAlert, `Deleted OAuth app "${btn.dataset.name}".`, 'success');
            loadAdminApps();
            loadAdminOverview();
            loadAuditLogs();
          } catch (err) { showAlert(panelAlert, err.message); }
        });
      });
    }

    loadAdminOverview();
    loadAuditLogs();
    loadRules();
    loadDevApplications();
    loadUsers();
    loadAdminApps();
  }

  // --- Docs Interactive PKCE URL Builder ---
  const builder = document.getElementById('docs-url-builder');
  if (builder) {
    document.getElementById('doc-generate-btn')?.addEventListener('click', async () => {
      const clientId = document.getElementById('doc-client-id').value.trim();
      const redirectUri = document.getElementById('doc-redirect-uri').value.trim();
      const scope = document.getElementById('doc-scope').value.trim() || 'openid profile email';
      if (!clientId || !redirectUri) return;

      const random = crypto.getRandomValues(new Uint8Array(32));
      const verifier = btoa(String.fromCharCode(...random)).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
      const digest = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(verifier));
      const challenge = btoa(String.fromCharCode(...new Uint8Array(digest))).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');

      const params = new URLSearchParams({
        client_id: clientId,
        redirect_uri: redirectUri,
        response_type: 'code',
        scope,
        state: 'demo_state_' + Math.random().toString(36).slice(2, 10),
        code_challenge: challenge,
        code_challenge_method: 'S256',
      });
      const authUrl = `${builder.dataset.issuer}/oauth/authorize?${params.toString()}`;
      document.getElementById('doc-verifier').textContent = verifier;
      document.getElementById('doc-auth-url').textContent = authUrl;
      document.getElementById('doc-launch-link').href = authUrl;
      document.getElementById('doc-generated-out')?.classList.remove('hidden');
    });
  }
})();
