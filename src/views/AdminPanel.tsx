import type { FC } from 'hono/jsx';
import type { AuthContext } from '../types';
import { REGISTRATION_RULE_TEMPLATES } from '../lib/rules';
import { Layout } from './Layout';

export const AdminPanel: FC<{
  appName: string;
  auth: AuthContext;
  csrfToken: string;
}> = ({ auth, csrfToken }) => {
  const isSuperuser = auth.isSuperuser;

  return (
    <Layout title="Admin" auth={auth} csrfToken={csrfToken} showNav>
      <div class="page-header" id="admin-root" data-is-superuser={isSuperuser ? '1' : '0'}>
        <div>
          <h1>Admin</h1>
          <p class="muted">
            Signed in as{' '}
            <span class={`badge ${isSuperuser ? 'badge-ok' : ''}`}>
              {isSuperuser ? 'Superuser' : `Admin (${auth.user?.email})`}
            </span>
          </p>
        </div>
        {isSuperuser && (
          <div class="card compact-card">
            <label class="inline-check">
              <input type="checkbox" id="setting-require-email-verify" />
              <span>Require Email Verification (Resend)</span>
            </label>
          </div>
        )}
      </div>

      <div id="panel-alert" class="alert hidden"></div>

      <div class="grid-4" id="admin-stats">
        <div class="card stat-card"><div class="muted small">Users</div><strong id="stat-users">-</strong></div>
        <div class="card stat-card"><div class="muted small">Pending Dev Apps</div><strong id="stat-pending-devs">-</strong></div>
        <div class="card stat-card"><div class="muted small">OAuth Apps</div><strong id="stat-apps">-</strong></div>
        <div class="card stat-card"><div class="muted small">Active Reg Rules</div><strong id="stat-rules">-</strong></div>
      </div>

      <section class="card mt-1">
        <h2>Registration Email Regex Rules</h2>
        <p class="muted small">
          <strong>Default Policy: Approve Nothing.</strong> Rules run in ascending <code>priority</code> order; the first
          matching rule decides (<code>allow</code> or <code>deny</code>). If no rule matches, registration is denied.
        </p>

        <div class="template-bar">
          <span class="small muted">Templates:</span>
          {REGISTRATION_RULE_TEMPLATES.map((tpl) => (
            <button
              key={tpl.id}
              type="button"
              class="btn btn-sm btn-ghost"
              data-rule-template
              data-type={tpl.ruleType}
              data-pattern={tpl.pattern}
              data-priority={String(tpl.priority)}
              data-description={tpl.description}
            >
              {tpl.label}
            </button>
          ))}
        </div>

        <form id="add-rule-form" class="grid-form mt-1">
          <select name="ruleType" required>
            <option value="allow">Allow</option>
            <option value="deny">Deny</option>
          </select>
          <input type="number" name="priority" value="100" required title="Priority (lower runs first)" />
          <input type="text" name="pattern" required placeholder="^[^@]+@joeuniverse\.com$" />
          <input type="text" name="description" placeholder="Rule description" />
          <button type="submit" class="btn btn-primary">Add Rule</button>
        </form>

        <form id="test-rule-form" class="inline-form mt-1">
          <input type="email" name="email" required placeholder="Test an email address (e.g. joe@joeuniverse.com)" />
          <button type="submit" class="btn btn-ghost">Test Email</button>
          <span id="rule-test-result" class="small"></span>
        </form>

        <div id="admin-rules-list" class="table-wrap mt-1 muted small">Loading rules...</div>
      </section>

      <section class="card mt-1">
        <h2>Developer Access Applications</h2>
        <p class="muted small">Approve or reject users applying for access to the Developer Panel.</p>
        <div id="admin-dev-apps-list" class="table-wrap muted small">Loading developer applications...</div>
      </section>

      <section class="card mt-1">
        <div class="section-head">
          <h2>Users &amp; Roles</h2>
          <form id="admin-user-search-form" class="inline-form">
            <input type="search" name="q" placeholder="Search email or name..." />
            <button type="submit" class="btn btn-sm btn-ghost">Search</button>
          </form>
        </div>
        {!isSuperuser && (
          <p class="muted small">Note: Only the Superuser can promote or demote Admin roles.</p>
        )}
        <div id="admin-users-list" class="table-wrap muted small">Loading users...</div>
      </section>

      <section class="card mt-1">
        <h2>Registered OAuth Applications</h2>
        <div id="admin-apps-list" class="table-wrap muted small">Loading OAuth apps...</div>
      </section>

      <section class="card mt-1">
        <h2>Recent Security Audit Logs</h2>
        <div id="admin-audit-list" class="table-wrap muted small">Loading audit logs...</div>
      </section>
    </Layout>
  );
};
