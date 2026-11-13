import type { FC } from 'hono/jsx';
import type { AuthContext } from '../types';
import { Layout } from './Layout';

export const UserPanel: FC<{
  appName: string;
  auth: AuthContext;
  csrfToken: string;
}> = ({ auth, csrfToken }) => {
  const user = auth.user!;
  return (
    <Layout title="Account" auth={auth} csrfToken={csrfToken} showNav>
      <div class="page-header">
        <div>
          <h1>{user.name}</h1>
          <p class="muted">
            {user.email}{' '}
            <span class={`badge ${user.email_verified ? 'badge-ok' : 'badge-warn'}`}>
              {user.email_verified ? 'Verified' : 'Unverified'}
            </span>
          </p>
        </div>
      </div>

      <div id="panel-alert" class="alert hidden"></div>

      <div class="grid-2">
        <section class="card">
          <h2>Profile</h2>
          <form id="profile-form">
            <label>
              Display Name
              <input type="text" name="name" value={user.name} required maxlength={80} />
            </label>
            <button type="submit" class="btn btn-primary">Save Name</button>
          </form>

          <hr />
          <h3>Change Email</h3>
          <form id="email-form">
            <label>
              New Email Address
              <input type="email" name="newEmail" required placeholder="new@joeuniverse.com" />
            </label>
            <label>
              Current Password
              <input type="password" name="currentPassword" required />
            </label>
            <button type="submit" class="btn btn-ghost">Update Email</button>
          </form>
        </section>

        <section class="card">
          <h2>Security</h2>
          <form id="password-form">
            <label>
              Current Password
              <input type="password" name="currentPassword" required />
            </label>
            <label>
              New Password (min 8 chars)
              <input type="password" name="newPassword" required minlength={8} maxlength={128} />
            </label>
            <button type="submit" class="btn btn-primary">Change Password</button>
          </form>

          <hr />
          <h3>Two-Factor Authentication (TOTP)</h3>
          {user.totp_enabled === 1 ? (
            <form id="totp-disable-form">
              <p class="muted small">2FA is currently <strong class="text-ok">Enabled</strong>.</p>
              <label>
                Confirm Password to Disable 2FA
                <input type="password" name="currentPassword" required />
              </label>
              <button type="submit" class="btn btn-danger">Disable 2FA</button>
            </form>
          ) : (
            <div>
              <p class="muted small">Protect your account with an authenticator app.</p>
              <button type="button" id="totp-setup-btn" class="btn btn-ghost">Set up 2FA</button>
              <div id="totp-setup-box" class="hidden mt-1">
                <p class="small">Scan this QR code with your authenticator app (or enter the key manually), then enter the 6-digit code:</p>
                <div class="qr-wrap">
                  <img id="totp-qr-img" class="qr-img" alt="Authenticator QR Code" />
                </div>
                <div class="small muted mt-1">Manual setup key: <code id="totp-secret-out"></code></div>
                <form id="totp-verify-form" class="mt-1">
                  <label>
                    6-Digit Code
                    <input type="text" name="code" required pattern="[0-9]{6}" placeholder="123456" />
                  </label>
                  <button type="submit" class="btn btn-primary">Verify &amp; Enable 2FA</button>
                </form>
              </div>
            </div>
          )}
        </section>
      </div>

      <section class="card mt-1">
        <div class="section-head">
          <h2>Active Sessions</h2>
          <button type="button" id="revoke-other-sessions" class="btn btn-sm btn-ghost">Sign out other devices</button>
        </div>
        <div id="sessions-list" class="table-wrap muted small">Loading sessions...</div>
      </section>

      <section class="card mt-1">
        <h2>Connected Joe Universe Apps</h2>
        <div id="connected-apps-list" class="table-wrap muted small">Loading connected apps...</div>
      </section>

      <section class="card danger-zone mt-1">
        <h2>Delete Account</h2>
        <p class="muted small">
          Permanently deletes your JoeAuth account, owned applications, active sessions, and connected app grants.
        </p>
        <form id="delete-account-form" class="inline-form">
          <input type="password" name="currentPassword" required placeholder="Confirm your password" />
          <button type="submit" class="btn btn-danger">Delete My Account</button>
        </form>
      </section>
    </Layout>
  );
};
