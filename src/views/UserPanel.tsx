import type { FC } from 'hono/jsx';
import type { AuthContext } from '../types';
import { Layout } from './Layout';
import { UserAvatar } from './components/Media';

export const UserPanel: FC<{
  appName: string;
  auth: AuthContext;
  csrfToken: string;
}> = ({ auth, csrfToken }) => {
  const user = auth.user!;
  return (
    <Layout title="Account" auth={auth} csrfToken={csrfToken} showNav>
      <div class="d-flex align-items-center gap-3 mb-4">
        <UserAvatar user={user} size={52} id="account-header-avatar" />
        <div>
          <h1 class="h3 fw-semibold mb-1">{user.name}</h1>
          <p class="text-body-secondary mb-0">
            {user.email}{' '}
            <span class={`badge ${user.email_verified ? 'text-bg-success' : 'text-bg-warning'}`}>
              <i class={`bi ${user.email_verified ? 'bi-patch-check' : 'bi-exclamation-circle'} me-1`}></i>
              {user.email_verified ? 'Verified' : 'Unverified'}
            </span>
          </p>
        </div>
      </div>

      <div id="panel-alert" class="alert hidden"></div>

      <div class="row g-4">
        <div class="col-lg-6">
          <section class="card shadow-sm h-100">
            <div class="card-body">
              <h2 class="h5 fw-semibold mb-3">
                <i class="bi bi-person-vcard me-2 text-primary"></i>Profile
              </h2>
              <div class="d-flex align-items-center gap-3 p-3 rounded bg-body-tertiary border mb-3">
                <UserAvatar user={user} size={64} id="avatar-preview" />
                <div class="flex-grow-1 min-w-0">
                  <div class="fw-semibold small mb-1">Profile Picture</div>
                  <div class="text-body-secondary small mb-2">
                    Optional 256×256 PNG (max 128 KiB). Cropped in your browser and shared via <code>profile</code> scope.
                  </div>
                  <div class="d-flex flex-wrap gap-2">
                    <label class="btn btn-sm btn-outline-primary mb-0" for="avatar-file-input">
                      <i class="bi bi-crop me-1"></i>Choose &amp; Crop Picture
                    </label>
                    <input id="avatar-file-input" type="file" accept="image/*" class="d-none" />
                    <button
                      type="button"
                      id="remove-avatar-btn"
                      class={`btn btn-sm btn-outline-secondary ${user.avatar_key ? '' : 'hidden'}`}
                    >
                      <i class="bi bi-trash me-1"></i>Remove
                    </button>
                  </div>
                </div>
              </div>
              <form id="profile-form">
                <div class="mb-3">
                  <label class="form-label" for="profile-name">Display Name</label>
                  <input id="profile-name" class="form-control" type="text" name="name" value={user.name} required maxlength={80} />
                </div>
                <button type="submit" class="btn btn-primary">
                  <i class="bi bi-check2 me-1"></i>Save Name
                </button>
              </form>

              <hr class="my-4" />
              <h3 class="h6 fw-semibold mb-3">
                <i class="bi bi-envelope me-2"></i>Change Email
              </h3>
              <form id="email-form">
                <div class="mb-3">
                  <label class="form-label" for="new-email">New Email Address</label>
                  <input id="new-email" class="form-control" type="email" name="newEmail" required placeholder="joe@example.com" />
                </div>
                <div class="mb-3">
                  <label class="form-label" for="email-cur-pwd">Current Password</label>
                  <input id="email-cur-pwd" class="form-control" type="password" name="currentPassword" required />
                </div>
                <button type="submit" class="btn btn-outline-secondary">
                  <i class="bi bi-envelope-check me-1"></i>Update Email
                </button>
              </form>
            </div>
          </section>
        </div>

        <div class="col-lg-6">
          <section class="card shadow-sm h-100">
            <div class="card-body">
              <h2 class="h5 fw-semibold mb-3">
                <i class="bi bi-shield-lock me-2 text-primary"></i>Security
              </h2>
              <form id="password-form">
                <div class="mb-3">
                  <label class="form-label" for="pwd-cur">Current Password</label>
                  <input id="pwd-cur" class="form-control" type="password" name="currentPassword" required />
                </div>
                <div class="mb-3">
                  <label class="form-label" for="pwd-new">New Password (min 8 chars)</label>
                  <input id="pwd-new" class="form-control" type="password" name="newPassword" required minlength={8} maxlength={128} />
                </div>
                <button type="submit" class="btn btn-primary">
                  <i class="bi bi-key me-1"></i>Change Password
                </button>
              </form>

              <hr class="my-4" />
              <h3 class="h6 fw-semibold mb-2">
                <i class="bi bi-qr-code-scan me-2"></i>Two-Factor Authentication (TOTP)
              </h3>
              {user.totp_enabled === 1 ? (
                <form id="totp-disable-form">
                  <p class="text-body-secondary small">
                    2FA is currently <strong class="text-success">Enabled</strong>.
                  </p>
                  <div class="mb-3">
                    <label class="form-label" for="totp-disable-pwd">Confirm Password to Disable 2FA</label>
                    <input id="totp-disable-pwd" class="form-control" type="password" name="currentPassword" required />
                  </div>
                  <button type="submit" class="btn btn-danger">
                    <i class="bi bi-shield-x me-1"></i>Disable 2FA
                  </button>
                </form>
              ) : (
                <div>
                  <p class="text-body-secondary small">Protect your account with an authenticator app.</p>
                  <button type="button" id="totp-setup-btn" class="btn btn-outline-secondary">
                    <i class="bi bi-qr-code me-1"></i>Set up 2FA
                  </button>
                  <div id="totp-setup-box" class="hidden mt-3">
                    <p class="small mb-2">
                      Scan this QR code with your authenticator app (or enter the key manually), then enter the 6-digit code:
                    </p>
                    <div class="qr-wrap mb-2">
                      <img id="totp-qr-img" class="qr-img" alt="Authenticator QR Code" />
                    </div>
                    <div class="small text-body-secondary mb-3">
                      Manual setup key: <code id="totp-secret-out"></code>
                    </div>
                    <form id="totp-verify-form">
                      <div class="mb-3">
                        <label class="form-label" for="totp-verify-code">6-Digit Code</label>
                        <input id="totp-verify-code" class="form-control" type="text" name="code" required pattern="[0-9]{6}" placeholder="123456" />
                      </div>
                      <button type="submit" class="btn btn-primary">
                        <i class="bi bi-shield-check me-1"></i>Verify &amp; Enable 2FA
                      </button>
                    </form>
                  </div>
                </div>
              )}
            </div>
          </section>
        </div>
      </div>

      <section class="card shadow-sm mt-4">
        <div class="card-body">
          <div class="d-flex justify-content-between align-items-center flex-wrap gap-2 mb-3">
            <h2 class="h5 fw-semibold mb-0">
              <i class="bi bi-laptop me-2 text-primary"></i>Active Sessions
            </h2>
            <button type="button" id="revoke-other-sessions" class="btn btn-sm btn-outline-secondary">
              <i class="bi bi-box-arrow-right me-1"></i>Sign out other devices
            </button>
          </div>
          <div id="sessions-list" class="table-responsive text-body-secondary small">Loading sessions...</div>
        </div>
      </section>

      <section class="card shadow-sm mt-4">
        <div class="card-body">
          <h2 class="h5 fw-semibold mb-3">
            <i class="bi bi-grid me-2 text-primary"></i>Connected Apps
          </h2>
          <div id="connected-apps-list" class="table-responsive text-body-secondary small">Loading connected apps...</div>
        </div>
      </section>

      <section class="card shadow-sm border-danger-subtle mt-4">
        <div class="card-body">
          <h2 class="h5 fw-semibold text-danger mb-2">
            <i class="bi bi-exclamation-triangle me-2"></i>Delete Account
          </h2>
          <p class="text-body-secondary small mb-3">
            Permanently deletes your JoeAuth account, owned applications, active sessions, and connected app grants.
          </p>
          <form id="delete-account-form" class="row g-2 align-items-center">
            <div class="col-sm-6 col-md-4">
              <input class="form-control" type="password" name="currentPassword" required placeholder="Confirm your password" />
            </div>
            <div class="col-auto">
              <button type="submit" class="btn btn-danger">
                <i class="bi bi-trash me-1"></i>Delete My Account
              </button>
            </div>
          </form>
        </div>
      </section>
    </Layout>
  );
};
