(function () {
  const csrf = document.querySelector('meta[name="csrf-token"]')?.getAttribute('content') || '';

  async function api(url, opts = {}) {
    const headers = new Headers(opts.headers || {});
    if (csrf) headers.set('X-CSRF-Token', csrf);
    if (opts.body && typeof opts.body === 'object' && !(opts.body instanceof FormData)) {
      headers.set('Content-Type', 'application/json');
      opts.body = JSON.stringify(opts.body);
    }
    const resp = await fetch(url, { credentials: 'same-origin', ...opts, headers });
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
    el.className = `alert ${type === 'success' ? 'alert-success' : 'alert-error'}`;
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
        location.href = btn.dataset.returnTo || '/account';
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
        await api('/api/auth/login', {
          method: 'POST',
          body: {
            email: fd.get('email'),
            password: fd.get('password'),
            totpCode: fd.get('totpCode') || undefined,
            turnstileToken: getTurnstileToken(loginForm),
          },
        });
        location.href = loginForm.dataset.returnTo || '/account';
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
          location.href = registerForm.dataset.returnTo || '/account';
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
        location.href = '/admin';
      } catch (err) {
        resetTurnstile();
        showAlert(alertEl, err.message);
      }
    });
  }

  // --- User Panel ---
  const panelAlert = document.getElementById('panel-alert');
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
        ? `<table><thead><tr><th>Device / Agent</th><th>IP Hash</th><th>Last Active</th><th></th></tr></thead><tbody>${rows
            .map(
              (s) => `<tr>
                <td>${esc(s.user_agent || 'Unknown')} ${s.is_current ? '<span class="badge badge-ok">Current</span>' : ''}</td>
                <td><code>${esc(s.ip_hash || '-')}</code></td>
                <td>${new Date(s.last_seen_at * 1000).toLocaleString()}</td>
                <td>${s.is_current ? '' : `<button class="btn btn-sm btn-ghost" data-revoke-session="${esc(s.id)}">Revoke</button>`}</td>
              </tr>`
            )
            .join('')}</tbody></table>`
        : '<p>No active sessions.</p>';
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
        ? `<table><thead><tr><th>App</th><th>Scopes</th><th>Granted</th><th></th></tr></thead><tbody>${rows
            .map(
              (a) => `<tr>
                <td><a href="${esc(a.homepage_url)}" target="_blank" rel="noopener">${esc(a.name)}</a></td>
                <td><code>${esc(a.scopes)}</code></td>
                <td>${new Date(a.granted_at * 1000).toLocaleDateString()}</td>
                <td><button class="btn btn-sm btn-ghost" data-revoke-app="${esc(a.app_id)}">Revoke</button></td>
              </tr>`
            )
            .join('')}</tbody></table>`
        : '<p>No connected applications yet.</p>';
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
        ? `<table><thead><tr><th>Reason</th><th>Status</th><th>Review Note</th></tr></thead><tbody>${res.applications
            .map(
              (a) => `<tr>
                <td>${esc(a.reason)}</td>
                <td><span class="badge ${a.status === 'approved' ? 'badge-ok' : a.status === 'pending' ? 'badge-warn' : 'badge-bad'}">${esc(a.status)}</span></td>
                <td>${esc(a.review_note || '-')}</td>
              </tr>`
            )
            .join('')}</tbody></table>`
        : '<p>No applications submitted yet.</p>';
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
              (a) => `<div class="card mt-1">
                <div class="section-head">
                  <strong>${esc(a.name)}</strong>
                  <span class="badge ${a.status === 'approved' ? 'badge-ok' : 'badge-bad'}">${esc(a.status)}</span>
                </div>
                <div class="small">Client ID: <code>${esc(a.client_id)}</code></div>
                <div class="small muted">Secret Prefix: <code>${esc(a.client_secret_prefix)}...</code></div>
                <div class="small muted">Redirects: ${a.redirect_uris.map((u) => `<code>${esc(u)}</code>`).join(', ')}</div>
                <div class="btn-row mt-1">
                  <button class="btn btn-sm btn-ghost" data-rotate-app="${esc(a.id)}">Rotate Secret</button>
                  <button class="btn btn-sm btn-danger" data-delete-app="${esc(a.id)}">Delete</button>
                </div>
              </div>`
            )
            .join('')
        : '<p>No OAuth applications created yet.</p>';

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
          redirectUris,
          allowedScopes: Array.from(new Set(allowedScopes)),
        },
      });
      document.getElementById('reveal-client-id').textContent = created.client_id;
      document.getElementById('reveal-client-secret').textContent = created.client_secret;
      document.getElementById('secret-reveal-box')?.classList.remove('hidden');
      form.reset();
      loadDevApps();
    } catch (err) { showAlert(panelAlert, err.message); }
  });

  // --- Admin Panel ---
  const adminRoot = document.getElementById('admin-root');
  if (adminRoot) {
    const isSuperuser = adminRoot.dataset.isSuperuser === '1';

    async function loadAdminOverview() {
      const data = await api('/api/admin/overview');
      document.getElementById('stat-users').textContent = data.stats.users;
      document.getElementById('stat-pending-devs').textContent = data.stats.pendingDeveloperApplications;
      document.getElementById('stat-apps').textContent = data.stats.apps;
      document.getElementById('stat-rules').textContent = data.stats.activeRules;
      const verifyBox = document.getElementById('setting-require-email-verify');
      if (verifyBox) verifyBox.checked = data.settings.require_email_verification;

      const auditEl = document.getElementById('admin-audit-list');
      auditEl.innerHTML = data.recentAuditLogs.length
        ? `<table><thead><tr><th>Time</th><th>Actor</th><th>Action</th><th>Target</th><th>Metadata</th></tr></thead><tbody>${data.recentAuditLogs
            .map(
              (l) => `<tr>
                <td>${new Date(l.created_at * 1000).toLocaleString()}</td>
                <td><code>${esc(l.actor_id || '-')}</code></td>
                <td><code>${esc(l.action)}</code></td>
                <td>${esc(l.target_type || '')} ${esc(l.target_id || '')}</td>
                <td><code>${esc(l.metadata || '')}</code></td>
              </tr>`
            )
            .join('')}</tbody></table>`
        : '<p>No audit logs yet.</p>';
    }

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
        ? `<table><thead><tr><th>Priority</th><th>Type</th><th>Regex Pattern</th><th>Description</th><th>Active</th><th></th></tr></thead><tbody>${data.rules
            .map(
              (r) => `<tr>
                <td>${r.priority}</td>
                <td><span class="badge ${r.rule_type === 'allow' ? 'badge-ok' : 'badge-bad'}">${esc(r.rule_type)}</span></td>
                <td><code>${esc(r.pattern)}</code></td>
                <td>${esc(r.description)}</td>
                <td><button class="btn btn-sm btn-ghost" data-toggle-rule="${esc(r.id)}" data-active="${r.is_active}">${r.is_active ? 'Enabled' : 'Disabled'}</button></td>
                <td><button class="btn btn-sm btn-danger" data-del-rule="${esc(r.id)}">Delete</button></td>
              </tr>`
            )
            .join('')}</tbody></table>`
        : '<p class="alert alert-error">No registration rules exist yet — all registrations are currently denied by default.</p>';

      el.querySelectorAll('[data-toggle-rule]').forEach((btn) => {
        btn.addEventListener('click', async () => {
          await api(`/api/admin/rules/${btn.dataset.toggleRule}`, {
            method: 'PATCH',
            body: { isActive: btn.dataset.active !== '1' },
          });
          loadRules();
          loadAdminOverview();
        });
      });
      el.querySelectorAll('[data-del-rule]').forEach((btn) => {
        btn.addEventListener('click', async () => {
          await api(`/api/admin/rules/${btn.dataset.delRule}`, { method: 'DELETE', body: {} });
          loadRules();
          loadAdminOverview();
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
      } catch (err) { showAlert(panelAlert, err.message); }
    });

    document.getElementById('test-rule-form')?.addEventListener('submit', async (e) => {
      e.preventDefault();
      const fd = new FormData(e.target);
      const res = await api('/api/admin/rules/test', { method: 'POST', body: { email: fd.get('email') } });
      const out = document.getElementById('rule-test-result');
      out.textContent = `${res.allowed ? 'ALLOWED' : 'DENIED'} — ${res.reason}`;
      out.className = `small ${res.allowed ? 'text-ok' : ''}`;
    });

    async function loadDevApplications() {
      const rows = await api('/api/admin/dev-applications');
      const el = document.getElementById('admin-dev-apps-list');
      el.innerHTML = rows.length
        ? `<table><thead><tr><th>User</th><th>Reason</th><th>Status</th><th>Actions</th></tr></thead><tbody>${rows
            .map(
              (a) => `<tr>
                <td>${esc(a.user_name)}<br><span class="muted">${esc(a.user_email)}</span></td>
                <td>${esc(a.reason)}</td>
                <td><span class="badge ${a.status === 'approved' ? 'badge-ok' : a.status === 'pending' ? 'badge-warn' : 'badge-bad'}">${esc(a.status)}</span></td>
                <td>
                  ${a.status === 'pending'
                    ? `<div class="btn-row">
                        <button class="btn btn-sm btn-primary" data-dev-decision="approved" data-id="${esc(a.id)}">Approve</button>
                        <button class="btn btn-sm btn-danger" data-dev-decision="rejected" data-id="${esc(a.id)}">Reject</button>
                      </div>`
                    : `<span class="muted">${esc(a.reviewed_by || '')}</span>`}
                </td>
              </tr>`
            )
            .join('')}</tbody></table>`
        : '<p>No developer applications.</p>';

      el.querySelectorAll('[data-dev-decision]').forEach((btn) => {
        btn.addEventListener('click', async () => {
          const note = btn.dataset.devDecision === 'rejected' ? (prompt('Rejection note (optional):') || '') : '';
          await api(`/api/admin/dev-applications/${btn.dataset.id}`, {
            method: 'PATCH',
            body: { decision: btn.dataset.devDecision, reviewNote: note },
          });
          loadDevApplications();
          loadUsers();
          loadAdminOverview();
        });
      });
    }

    async function loadUsers(q = '') {
      const rows = await api(`/api/admin/users?q=${encodeURIComponent(q)}`);
      const el = document.getElementById('admin-users-list');
      el.innerHTML = rows.length
        ? `<table><thead><tr><th>User</th><th>Role</th><th>Dev</th><th>Status</th><th>Actions</th></tr></thead><tbody>${rows
            .map(
              (u) => `<tr>
                <td><strong>${esc(u.name)}</strong><br><span class="muted">${esc(u.email)}</span> ${u.email_verified ? '✓' : '<span class="badge badge-warn">unverified</span>'}</td>
                <td><span class="badge ${u.role === 'admin' ? 'badge-ok' : ''}">${esc(u.role)}</span></td>
                <td><span class="badge">${esc(u.developer_status)}</span></td>
                <td><span class="badge ${u.status === 'active' ? 'badge-ok' : 'badge-bad'}">${esc(u.status)}</span></td>
                <td>
                  <div class="btn-row">
                    <button class="btn btn-sm btn-ghost" data-toggle-user="${esc(u.id)}" data-status="${u.status}">${u.status === 'active' ? 'Suspend' : 'Activate'}</button>
                    ${!u.email_verified ? `<button class="btn btn-sm btn-ghost" data-verify-user="${esc(u.id)}">Verify Email</button>` : ''}
                    ${isSuperuser ? `<button class="btn btn-sm btn-ghost" data-role-user="${esc(u.id)}" data-next-role="${u.role === 'admin' ? 'user' : 'admin'}">${u.role === 'admin' ? 'Demote Admin' : 'Make Admin'}</button>` : ''}
                  </div>
                </td>
              </tr>`
            )
            .join('')}</tbody></table>`
        : '<p>No users found.</p>';

      el.querySelectorAll('[data-toggle-user]').forEach((btn) => {
        btn.addEventListener('click', async () => {
          await api(`/api/admin/users/${btn.dataset.toggleUser}/status`, {
            method: 'PATCH',
            body: { status: btn.dataset.status === 'active' ? 'suspended' : 'active' },
          });
          loadUsers(q);
        });
      });
      el.querySelectorAll('[data-verify-user]').forEach((btn) => {
        btn.addEventListener('click', async () => {
          await api(`/api/admin/users/${btn.dataset.verifyUser}/status`, {
            method: 'PATCH',
            body: { emailVerified: true },
          });
          loadUsers(q);
        });
      });
      el.querySelectorAll('[data-role-user]').forEach((btn) => {
        btn.addEventListener('click', async () => {
          await api(`/api/admin/users/${btn.dataset.roleUser}/role`, {
            method: 'PATCH',
            body: { role: btn.dataset.nextRole },
          });
          loadUsers(q);
        });
      });
    }

    document.getElementById('admin-user-search-form')?.addEventListener('submit', (e) => {
      e.preventDefault();
      loadUsers(new FormData(e.target).get('q') || '');
    });

    async function loadAdminApps() {
      const rows = await api('/api/admin/apps');
      const el = document.getElementById('admin-apps-list');
      el.innerHTML = rows.length
        ? `<table><thead><tr><th>Name</th><th>Client ID</th><th>Owner</th><th>Status</th><th>Actions</th></tr></thead><tbody>${rows
            .map(
              (a) => `<tr>
                <td><strong>${esc(a.name)}</strong><br><span class="muted">${esc(a.homepage_url)}</span></td>
                <td><code>${esc(a.client_id)}</code></td>
                <td>${esc(a.owner_email)}</td>
                <td><span class="badge ${a.status === 'approved' ? 'badge-ok' : 'badge-bad'}">${esc(a.status)}</span> ${a.is_first_party ? '<span class="badge badge-ok">1st-party</span>' : ''}</td>
                <td>
                  <div class="btn-row">
                    <button class="btn btn-sm btn-ghost" data-app-status="${esc(a.id)}" data-next="${a.status === 'approved' ? 'suspended' : 'approved'}">${a.status === 'approved' ? 'Suspend' : 'Restore'}</button>
                    <button class="btn btn-sm btn-ghost" data-app-fp="${esc(a.id)}" data-fp="${a.is_first_party ? '0' : '1'}">${a.is_first_party ? 'Unmark 1st-party' : 'Mark 1st-party'}</button>
                  </div>
                </td>
              </tr>`
            )
            .join('')}</tbody></table>`
        : '<p>No OAuth apps registered.</p>';

      el.querySelectorAll('[data-app-status]').forEach((btn) => {
        btn.addEventListener('click', async () => {
          await api(`/api/admin/apps/${btn.dataset.appStatus}`, {
            method: 'PATCH',
            body: { status: btn.dataset.next },
          });
          loadAdminApps();
        });
      });
      el.querySelectorAll('[data-app-fp]').forEach((btn) => {
        btn.addEventListener('click', async () => {
          await api(`/api/admin/apps/${btn.dataset.appFp}`, {
            method: 'PATCH',
            body: { isFirstParty: btn.dataset.fp === '1' },
          });
          loadAdminApps();
        });
      });
    }

    loadAdminOverview();
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
