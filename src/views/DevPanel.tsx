import type { FC } from 'hono/jsx';
import type { AuthContext } from '../types';
import { Layout } from './Layout';

export const DevPanel: FC<{
  appName: string;
  auth: AuthContext;
  csrfToken: string;
  siteKey: string;
}> = ({ auth, csrfToken, siteKey }) => {
  const user = auth.user!;
  const isApproved = user.developer_status === 'approved';

  return (
    <Layout title="Developer" auth={auth} csrfToken={csrfToken} turnstile={!isApproved} showNav>
      <div class="mb-4">
        <h1 class="h3 fw-semibold mb-1">
          <i class="bi bi-code-square me-2 text-primary"></i>Applications
        </h1>
        <p class="text-body-secondary mb-0">
          Developer Status:{' '}
          <span
            class={`badge ${
              isApproved ? 'text-bg-success' : user.developer_status === 'pending' ? 'text-bg-warning' : 'text-bg-secondary'
            }`}
          >
            {user.developer_status}
          </span>
        </p>
      </div>

      <div id="panel-alert" class="alert hidden"></div>

      {!isApproved ? (
        <div class="card shadow-sm">
          <div class="card-body">
            {user.developer_status === 'pending' ? (
              <>
                <h2 class="h5 fw-semibold">
                  <i class="bi bi-hourglass-split me-2 text-warning"></i>Developer Application Pending
                </h2>
                <p class="text-body-secondary mb-0">
                  Your application to become a JoeAuth developer is awaiting Admin or Superuser approval. Once approved,
                  any OAuth application tokens you create here will be activated immediately.
                </p>
              </>
            ) : (
              <>
                <h2 class="h5 fw-semibold">
                  <i class="bi bi-person-badge me-2 text-primary"></i>Apply for Developer Access
                </h2>
                <p class="text-body-secondary">
                  Developer access requires one-time Admin approval. Once approved, you can create and manage JoeAuth
                  application tokens immediately.
                </p>
                <form id="dev-apply-form">
                  <div class="mb-3">
                    <label class="form-label" for="dev-reason">
                      Why do you need JoeAuth developer access?
                    </label>
                    <textarea
                      id="dev-reason"
                      class="form-control"
                      name="reason"
                      required
                      minlength={10}
                      maxlength={500}
                      rows={4}
                    ></textarea>
                  </div>
                  <div class="cf-turnstile mb-3" data-sitekey={siteKey}></div>
                  <button type="submit" class="btn btn-primary">
                    <i class="bi bi-send me-1"></i>Submit Developer Application
                  </button>
                </form>
              </>
            )}
            <hr class="my-4" />
            <h3 class="h6 fw-semibold mb-3">
              <i class="bi bi-clock-history me-2"></i>Your Application History
            </h3>
            <div id="dev-status-history" class="table-responsive text-body-secondary small">Loading...</div>
          </div>
        </div>
      ) : (
        <>
          <div id="secret-reveal-box" class="alert alert-success hidden">
            <strong><i class="bi bi-key-fill me-1"></i>Copy your Client Secret now!</strong> It will not be shown again.
            <div class="mt-2 small font-monospace">
              <div>Client ID: <code id="reveal-client-id"></code></div>
              <div>Client Secret: <code id="reveal-client-secret"></code></div>
            </div>
          </div>

          <div class="row g-4">
            <div class="col-lg-5">
              <section class="card shadow-sm h-100">
                <div class="card-body">
                  <h2 class="h5 fw-semibold mb-1">
                    <i class="bi bi-plus-circle me-2 text-primary"></i>Create Application Token
                  </h2>
                  <p class="text-body-secondary small mb-3">
                    New applications are approved immediately for verified Joe Universe developers.
                  </p>
                  <form id="create-app-form">
                    <div class="mb-3">
                      <label class="form-label" for="app-name">Application Name</label>
                      <input id="app-name" class="form-control" type="text" name="name" required minlength={2} maxlength={64} placeholder="JoeNotes Web" />
                    </div>
                    <div class="mb-3">
                      <label class="form-label" for="app-url">Homepage URL</label>
                      <input id="app-url" class="form-control" type="url" name="homepageUrl" required placeholder="https://notes.joeuniverse.com" />
                    </div>
                    <div class="mb-3">
                      <label class="form-label" for="app-desc">Description</label>
                      <input id="app-desc" class="form-control" type="text" name="description" maxlength={300} placeholder="Cloud notes for Joe Universe" />
                    </div>
                    <div class="mb-3">
                      <label class="form-label" for="app-redirects">Allowed Redirect URIs (one per line)</label>
                      <textarea
                        id="app-redirects"
                        class="form-control font-monospace small"
                        name="redirectUris"
                        required
                        rows={3}
                        placeholder="https://notes.joeuniverse.com/callback&#10;http://127.0.0.1:8788/callback"
                      ></textarea>
                    </div>
                    <div class="mb-3">
                      <div class="form-label mb-1">Allowed Scopes</div>
                      <div class="d-flex flex-wrap gap-3">
                        <label class="form-check-label">
                          <input class="form-check-input me-1" type="checkbox" name="scopes" value="openid" checked disabled /> openid
                        </label>
                        <label class="form-check-label">
                          <input class="form-check-input me-1" type="checkbox" name="scopes" value="profile" checked /> profile
                        </label>
                        <label class="form-check-label">
                          <input class="form-check-input me-1" type="checkbox" name="scopes" value="email" checked /> email
                        </label>
                        <label class="form-check-label">
                          <input class="form-check-input me-1" type="checkbox" name="scopes" value="offline_access" checked /> offline_access
                        </label>
                      </div>
                    </div>
                    <button type="submit" class="btn btn-primary w-100">
                      <i class="bi bi-plus-lg me-1"></i>Create Application
                    </button>
                  </form>
                </div>
              </section>
            </div>

            <div class="col-lg-7">
              <section class="card shadow-sm h-100">
                <div class="card-body">
                  <h2 class="h5 fw-semibold mb-3">
                    <i class="bi bi-app-indicator me-2 text-primary"></i>Your Registered Applications
                  </h2>
                  <div id="dev-apps-list" class="text-body-secondary small">Loading applications...</div>
                </div>
              </section>
            </div>
          </div>
        </>
      )}
    </Layout>
  );
};
