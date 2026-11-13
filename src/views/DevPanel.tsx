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
      <div class="page-header">
        <div>
          <h1>Applications</h1>
          <p class="muted">
            Developer Status:{' '}
            <span class={`badge ${isApproved ? 'badge-ok' : user.developer_status === 'pending' ? 'badge-warn' : ''}`}>
              {user.developer_status}
            </span>
          </p>
        </div>
      </div>

      <div id="panel-alert" class="alert hidden"></div>

      {!isApproved ? (
        <div class="card">
          {user.developer_status === 'pending' ? (
            <>
              <h2>Developer Application Pending</h2>
              <p class="muted">
                Your application to become a JoeAuth developer is awaiting Admin or Superuser approval. Once approved,
                any OAuth application tokens you create here will be activated immediately.
              </p>
            </>
          ) : (
            <>
              <h2>Apply for Developer Access</h2>
              <p class="muted">
                Developer access requires one-time Admin approval. Once approved, you can create and manage JoeAuth
                application tokens immediately.
              </p>
              <form id="dev-apply-form">
                <label>
                  Why do you need JoeAuth developer access?
                  <textarea name="reason" required minlength={10} maxlength={500} rows={4}></textarea>
                </label>
                <div class="cf-turnstile" data-sitekey={siteKey}></div>
                <button type="submit" class="btn btn-primary">Submit Developer Application</button>
              </form>
            </>
          )}
          <hr />
          <h3>Your Application History</h3>
          <div id="dev-status-history" class="muted small">Loading...</div>
        </div>
      ) : (
        <>
          <div id="secret-reveal-box" class="alert alert-success hidden">
            <strong>Copy your Client Secret now!</strong> It will not be shown again.
            <div class="code-inline mt-1">
              <span>Client ID: <code id="reveal-client-id"></code></span><br />
              <span>Client Secret: <code id="reveal-client-secret"></code></span>
            </div>
          </div>

          <div class="grid-2">
            <section class="card">
              <h2>Create Application Token</h2>
              <p class="muted small">New applications are approved immediately for verified Joe Universe developers.</p>
              <form id="create-app-form">
                <label>
                  Application Name
                  <input type="text" name="name" required minlength={2} maxlength={64} placeholder="JoeNotes Web" />
                </label>
                <label>
                  Homepage URL
                  <input type="url" name="homepageUrl" required placeholder="https://notes.joeuniverse.com" />
                </label>
                <label>
                  Description
                  <input type="text" name="description" maxlength={300} placeholder="Cloud notes for Joe Universe" />
                </label>
                <label>
                  Allowed Redirect URIs (one per line)
                  <textarea
                    name="redirectUris"
                    required
                    rows={3}
                    placeholder="https://notes.joeuniverse.com/callback&#10;http://localhost:3000/callback"
                  ></textarea>
                </label>
                <div class="checkbox-row">
                  <span>Allowed Scopes:</span>
                  <label class="inline-check"><input type="checkbox" name="scopes" value="openid" checked disabled /> openid</label>
                  <label class="inline-check"><input type="checkbox" name="scopes" value="profile" checked /> profile</label>
                  <label class="inline-check"><input type="checkbox" name="scopes" value="email" checked /> email</label>
                  <label class="inline-check"><input type="checkbox" name="scopes" value="offline_access" checked /> offline_access</label>
                </div>
                <button type="submit" class="btn btn-primary">Create Application</button>
              </form>
            </section>

            <section class="card">
              <h2>Your Registered Applications</h2>
              <div id="dev-apps-list" class="muted small">Loading applications...</div>
            </section>
          </div>
        </>
      )}
    </Layout>
  );
};
