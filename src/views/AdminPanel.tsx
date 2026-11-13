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
      <div
        class="d-flex justify-content-between align-items-start flex-wrap gap-3 mb-4"
        id="admin-root"
        data-is-superuser={isSuperuser ? '1' : '0'}
      >
        <div>
          <h1 class="h3 fw-semibold mb-1">
            <i class="bi bi-shield-lock me-2 text-primary"></i>Admin
          </h1>
          <p class="text-body-secondary mb-0">
            Signed in as{' '}
            <span class={`badge ${isSuperuser ? 'text-bg-success' : 'text-bg-secondary'}`}>
              {isSuperuser ? 'Superuser' : `Admin (${auth.user?.email})`}
            </span>
          </p>
        </div>
        {isSuperuser && (
          <div class="card shadow-sm">
            <div class="card-body py-2 px-3">
              <div class="form-check form-switch mb-0">
                <input class="form-check-input" type="checkbox" role="switch" id="setting-require-email-verify" />
                <label class="form-check-label small fw-medium" for="setting-require-email-verify">
                  Require Email Verification (Resend)
                </label>
              </div>
            </div>
          </div>
        )}
      </div>

      <div id="panel-alert" class="alert hidden"></div>

      <div class="row g-3 mb-4" id="admin-stats">
        <div class="col-6 col-md-3">
          <div class="card shadow-sm h-100">
            <div class="card-body">
              <div class="text-body-secondary small">
                <i class="bi bi-people me-1"></i>Users
              </div>
              <div class="fs-3 fw-bold" id="stat-users">-</div>
            </div>
          </div>
        </div>
        <div class="col-6 col-md-3">
          <div class="card shadow-sm h-100">
            <div class="card-body">
              <div class="text-body-secondary small">
                <i class="bi bi-hourglass-split me-1"></i>Pending Dev Apps
              </div>
              <div class="fs-3 fw-bold" id="stat-pending-devs">-</div>
            </div>
          </div>
        </div>
        <div class="col-6 col-md-3">
          <div class="card shadow-sm h-100">
            <div class="card-body">
              <div class="text-body-secondary small">
                <i class="bi bi-app-indicator me-1"></i>OAuth Apps
              </div>
              <div class="fs-3 fw-bold" id="stat-apps">-</div>
            </div>
          </div>
        </div>
        <div class="col-6 col-md-3">
          <div class="card shadow-sm h-100">
            <div class="card-body">
              <div class="text-body-secondary small">
                <i class="bi bi-funnel me-1"></i>Active Reg Rules
              </div>
              <div class="fs-3 fw-bold" id="stat-rules">-</div>
            </div>
          </div>
        </div>
      </div>

      <section class="card shadow-sm mb-4">
        <div class="card-body">
          <h2 class="h5 fw-semibold mb-1">
            <i class="bi bi-funnel me-2 text-primary"></i>Registration Email Regex Rules
          </h2>
          <p class="text-body-secondary small mb-3">
            <strong>Default Policy: Approve Nothing.</strong> Rules run in ascending <code>priority</code> order; the first
            matching rule decides (<code>allow</code> or <code>deny</code>). If no rule matches, registration is denied.
          </p>

          <div class="d-flex flex-wrap align-items-center gap-2 mb-3">
            <span class="small text-body-secondary">Templates:</span>
            {REGISTRATION_RULE_TEMPLATES.map((tpl) => (
              <button
                key={tpl.id}
                type="button"
                class="btn btn-sm btn-outline-secondary"
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

          <form id="add-rule-form" class="row g-2 align-items-center mb-3">
            <div class="col-md-2">
              <select class="form-select" name="ruleType" required>
                <option value="allow">Allow</option>
                <option value="deny">Deny</option>
              </select>
            </div>
            <div class="col-md-2">
              <input class="form-control" type="number" name="priority" value="100" required title="Priority (lower runs first)" />
            </div>
            <div class="col-md-4">
              <input class="form-control font-monospace" type="text" name="pattern" required placeholder="^[^@]+@joeuniverse\.com$" />
            </div>
            <div class="col-md-3">
              <input class="form-control" type="text" name="description" placeholder="Rule description" />
            </div>
            <div class="col-md-1 d-grid">
              <button type="submit" class="btn btn-primary" title="Add Rule">
                <i class="bi bi-plus-lg"></i> Add
              </button>
            </div>
          </form>

          <form id="test-rule-form" class="row g-2 align-items-center mb-3">
            <div class="col-sm-6 col-md-5">
              <input class="form-control" type="email" name="email" required placeholder="Test an email address (e.g. joe@joeuniverse.com)" />
            </div>
            <div class="col-auto">
              <button type="submit" class="btn btn-outline-secondary">
                <i class="bi bi-check2-circle me-1"></i>Test Email
              </button>
            </div>
            <div class="col-auto">
              <span id="rule-test-result" class="small"></span>
            </div>
          </form>

          <div id="admin-rules-list" class="table-responsive text-body-secondary small">Loading rules...</div>
        </div>
      </section>

      <section class="card shadow-sm mb-4">
        <div class="card-body">
          <h2 class="h5 fw-semibold mb-1">
            <i class="bi bi-person-badge me-2 text-primary"></i>Developer Access Applications
          </h2>
          <p class="text-body-secondary small mb-3">Approve or reject users applying for access to the Developer Panel.</p>
          <div id="admin-dev-apps-list" class="table-responsive text-body-secondary small">Loading developer applications...</div>
        </div>
      </section>

      <section class="card shadow-sm mb-4">
        <div class="card-body">
          <div class="d-flex justify-content-between align-items-center flex-wrap gap-2 mb-2">
            <h2 class="h5 fw-semibold mb-0">
              <i class="bi bi-people me-2 text-primary"></i>Users &amp; Roles
            </h2>
            <form id="admin-user-search-form" class="d-flex gap-2">
              <input class="form-control form-control-sm" type="search" name="q" placeholder="Search email or name..." />
              <button type="submit" class="btn btn-sm btn-outline-secondary">
                <i class="bi bi-search me-1"></i>Search
              </button>
            </form>
          </div>
          {!isSuperuser && (
            <p class="text-body-secondary small mb-3">Note: Only the Superuser can promote or demote Admin roles.</p>
          )}
          <div id="admin-users-list" class="table-responsive text-body-secondary small">Loading users...</div>
        </div>
      </section>

      <section class="card shadow-sm mb-4">
        <div class="card-body">
          <h2 class="h5 fw-semibold mb-3">
            <i class="bi bi-grid-3x3-gap me-2 text-primary"></i>Registered OAuth Applications
          </h2>
          <div id="admin-apps-list" class="table-responsive text-body-secondary small">Loading OAuth apps...</div>
        </div>
      </section>

      <section class="card shadow-sm">
        <div class="card-body">
          <h2 class="h5 fw-semibold mb-3">
            <i class="bi bi-journal-text me-2 text-primary"></i>Recent Security Audit Logs
          </h2>
          <div id="admin-audit-list" class="table-responsive text-body-secondary small">Loading audit logs...</div>
        </div>
      </section>
    </Layout>
  );
};
