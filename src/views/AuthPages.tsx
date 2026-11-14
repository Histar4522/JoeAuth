import type { FC } from 'hono/jsx';
import type { ResolvedAccountSession } from '../types';
import { Layout } from './Layout';
import { AppLogo, UserAvatar } from './components/Media';

export const AccountChooserPage: FC<{
  csrfToken: string;
  accounts: ResolvedAccountSession[];
  returnTo?: string;
  oauthParams?: {
    appName: string;
    appLogoUrl?: string | null;
    client_id: string;
    redirect_uri: string;
    response_type: string;
    scope: string;
    state: string;
    code_challenge: string;
    code_challenge_method: string;
    nonce: string;
    prompt?: string;
    login_hint?: string;
    max_age?: string;
  };
}> = ({ csrfToken, accounts, returnTo = '/account', oauthParams }) => {
  const userAccounts = accounts.filter((a) => !a.isSuperuser && a.user);
  const hasSuperuser = !oauthParams && accounts.some((a) => a.isSuperuser);
  const effectiveReturnTo = oauthParams
    ? `/oauth/authorize?${new URLSearchParams({
        client_id: oauthParams.client_id,
        redirect_uri: oauthParams.redirect_uri,
        response_type: oauthParams.response_type,
        scope: oauthParams.scope,
        state: oauthParams.state,
        code_challenge: oauthParams.code_challenge,
        code_challenge_method: oauthParams.code_challenge_method,
        nonce: oauthParams.nonce,
        prompt: oauthParams.prompt || '',
        login_hint: oauthParams.login_hint || '',
        max_age: oauthParams.max_age || '',
        selected: '1',
      }).toString()}`
    : returnTo;

  const loginQuery = new URLSearchParams({ mode: 'add', return_to: effectiveReturnTo });
  if (oauthParams?.login_hint) loginQuery.set('login_hint', oauthParams.login_hint);
  const addAccountHref = `/login?${loginQuery.toString()}`;
  const registerHref = `/register?return_to=${encodeURIComponent(effectiveReturnTo)}`;

  return (
    <Layout title={oauthParams ? `Continue to ${oauthParams.appName}` : 'Choose an account'} csrfToken={csrfToken}>
      <div class="card shadow-sm auth-card">
        <div class="card-body p-4">
          <h1 class="h4 fw-semibold mb-3 d-flex align-items-center gap-2">
            {oauthParams ? (
              <>
                <AppLogo appName={oauthParams.appName} logoUrl={oauthParams.appLogoUrl} size={36} />
                <span>Continue to {oauthParams.appName}</span>
              </>
            ) : (
              <>
                <i class="bi bi-people text-primary"></i>
                <span>Choose an account</span>
              </>
            )}
          </h1>
          <div id="form-alert" class="alert hidden"></div>

          <div class="d-grid gap-2">
            {userAccounts.map((acc) => {
              const u = acc.user!;
              return (
                <div class="d-flex align-items-stretch gap-2" key={acc.sessionId}>
                  {oauthParams ? (
                    <form method="post" action="/oauth/select-account" class="flex-grow-1 m-0">
                      <input type="hidden" name="_csrf" value={csrfToken} />
                      <input type="hidden" name="sessionId" value={acc.sessionId} />
                      <input type="hidden" name="client_id" value={oauthParams.client_id} />
                      <input type="hidden" name="redirect_uri" value={oauthParams.redirect_uri} />
                      <input type="hidden" name="response_type" value={oauthParams.response_type} />
                      <input type="hidden" name="scope" value={oauthParams.scope} />
                      <input type="hidden" name="state" value={oauthParams.state} />
                      <input type="hidden" name="code_challenge" value={oauthParams.code_challenge} />
                      <input type="hidden" name="code_challenge_method" value={oauthParams.code_challenge_method} />
                      <input type="hidden" name="nonce" value={oauthParams.nonce} />
                      <input type="hidden" name="prompt" value={oauthParams.prompt || ''} />
                      <input type="hidden" name="login_hint" value={oauthParams.login_hint || ''} />
                      <input type="hidden" name="max_age" value={oauthParams.max_age || ''} />
                      <button type="submit" class="account-btn">
                        <UserAvatar user={u} size={38} />
                        <span class="account-meta">
                          <strong>{u.name}</strong>
                          <span class="text-body-secondary small">{u.email}</span>
                        </span>
                      </button>
                    </form>
                  ) : (
                    <button
                      type="button"
                      class="account-btn flex-grow-1"
                      data-switch-session={acc.sessionId}
                      data-target-slot={acc.slot}
                      data-multi-user={userAccounts.length > 1 ? '1' : '0'}
                      data-return-to={effectiveReturnTo}
                    >
                      <UserAvatar user={u} size={38} />
                      <span class="account-meta">
                        <strong>{u.name}</strong>
                        <span class="text-body-secondary small">{u.email}</span>
                      </span>
                    </button>
                  )}
                  <button
                    type="button"
                    class="btn btn-outline-secondary d-flex align-items-center px-3"
                    title="Sign out of this account"
                    data-remove-session={acc.sessionId}
                  >
                    <i class="bi bi-x-lg"></i>
                  </button>
                </div>
              );
            })}
          </div>

          <div class="d-grid gap-2 mt-3 pt-3 border-top">
            {hasSuperuser && (
              <a class="btn btn-outline-success" href="/u/superuser/admin">
                <i class="bi bi-shield-lock me-1"></i>Superuser Admin Console
              </a>
            )}
            <a class="btn btn-outline-secondary" href={addAccountHref}>
              <i class="bi bi-person-plus me-1"></i>Use another account
            </a>
            <a class="btn btn-outline-secondary" href={registerHref}>
              <i class="bi bi-plus-circle me-1"></i>Create account
            </a>
            {userAccounts.length > 1 && (
              <button type="button" class="btn btn-sm btn-link text-body-secondary mt-1" data-logout-all-btn>
                <i class="bi bi-box-arrow-right me-1"></i>Sign out of all accounts
              </button>
            )}
          </div>
        </div>
      </div>
    </Layout>
  );
};

export const LoginPage: FC<{
  csrfToken: string;
  siteKey: string;
  returnTo?: string;
  verified?: boolean;
  hasSavedAccounts?: boolean;
  loginHint?: string;
}> = ({ csrfToken, siteKey, returnTo = '/account', verified = false, hasSavedAccounts = false, loginHint = '' }) => (
  <Layout title="Sign in" csrfToken={csrfToken} turnstile>
    <div class="card shadow-sm auth-card">
      <div class="card-body p-4">
        <h1 class="h4 fw-semibold mb-3">
          <i class="bi bi-box-arrow-in-right me-2 text-primary"></i>Sign in
        </h1>
        {verified && (
          <div class="alert alert-success">
            <i class="bi bi-check-circle-fill me-2"></i>Email verified. You can sign in now.
          </div>
        )}
        <div id="form-alert" class="alert hidden"></div>
        <form id="login-form" data-return-to={returnTo}>
          <div class="mb-3">
            <label class="form-label" for="login-email">Email</label>
            <input
              id="login-email"
              class="form-control"
              type="email"
              name="email"
              required
              autocomplete="email"
              value={loginHint}
              placeholder="joe@example.com"
            />
          </div>
          <div class="mb-3">
            <label class="form-label" for="login-password">Password</label>
            <input
              id="login-password"
              class="form-control"
              type="password"
              name="password"
              required
              autocomplete="current-password"
            />
          </div>
          <div id="totp-group" class="mb-3 hidden">
            <div class="d-flex justify-content-between align-items-center mb-1">
              <label class="form-label mb-0" for="login-totp" id="login-2fa-label">
                <i class="bi bi-shield-lock me-1"></i>Authenticator Code
              </label>
              <button type="button" class="btn btn-link btn-sm p-0 text-decoration-none" id="toggle-recovery-mode">
                Use recovery code
              </button>
            </div>
            <input
              id="login-totp"
              class="form-control"
              type="text"
              name="totpCode"
              inputmode="numeric"
              pattern="[0-9]{6}"
              placeholder="123456"
            />
            <input
              id="login-recovery-code"
              class="form-control hidden"
              type="text"
              name="recoveryCode"
              placeholder="ABCD-EFGH"
              autocomplete="one-time-code"
            />
          </div>
          <div class="cf-turnstile mb-3" data-sitekey={siteKey}></div>
          <button type="submit" class="btn btn-primary w-100">
            <i class="bi bi-box-arrow-in-right me-1"></i>Sign in
          </button>
        </form>
        <div class="d-grid mt-2">
          <button type="button" id="passkey-login-btn" class="btn btn-outline-secondary w-100" data-return-to={returnTo}>
            <i class="bi bi-key me-1"></i>Sign in with Passkey
          </button>
        </div>
        <div class="d-flex justify-content-between mt-3 small">
          <a href="/forgot-password">Forgot password?</a>
          <a href={`/register?return_to=${encodeURIComponent(returnTo)}`}>Create account</a>
        </div>
        {hasSavedAccounts && (
          <div class="mt-2 small">
            <a href={`/login?return_to=${encodeURIComponent(returnTo)}`}>
              <i class="bi bi-arrow-left me-1"></i>Back to saved accounts
            </a>
          </div>
        )}
      </div>
    </div>
  </Layout>
);

export const RegisterPage: FC<{
  csrfToken: string;
  siteKey: string;
  returnTo?: string;
}> = ({ csrfToken, siteKey, returnTo = '/account' }) => (
  <Layout title="Create account" csrfToken={csrfToken} turnstile>
    <div class="card shadow-sm auth-card">
      <div class="card-body p-4">
        <h1 class="h4 fw-semibold mb-3">
          <i class="bi bi-person-plus me-2 text-primary"></i>Create account
        </h1>
        <div id="form-alert" class="alert hidden"></div>
        <form id="register-form" data-return-to={returnTo}>
          <div class="mb-3">
            <label class="form-label" for="reg-name">Name</label>
            <input id="reg-name" class="form-control" type="text" name="name" required maxlength={80} autocomplete="name" />
          </div>
          <div class="mb-3">
            <label class="form-label" for="reg-email">Email</label>
            <input
              id="reg-email"
              class="form-control"
              type="email"
              name="email"
              required
              autocomplete="email"
              placeholder="joe@example.com"
            />
          </div>
          <div class="mb-3">
            <label class="form-label" for="reg-password">Password (min 8 characters)</label>
            <input
              id="reg-password"
              class="form-control"
              type="password"
              name="password"
              required
              minlength={8}
              maxlength={128}
              autocomplete="new-password"
            />
          </div>
          <div class="cf-turnstile mb-3" data-sitekey={siteKey}></div>
          <button type="submit" class="btn btn-primary w-100">
            <i class="bi bi-person-plus me-1"></i>Create account
          </button>
        </form>
        <div class="mt-3 small">
          <a href={`/login?return_to=${encodeURIComponent(returnTo)}`}>Sign in instead</a>
        </div>
      </div>
    </div>
  </Layout>
);

export const ForgotPasswordPage: FC<{ csrfToken: string; siteKey: string }> = ({
  csrfToken,
  siteKey,
}) => (
  <Layout title="Reset password" csrfToken={csrfToken} turnstile>
    <div class="card shadow-sm auth-card">
      <div class="card-body p-4">
        <h1 class="h4 fw-semibold mb-3">
          <i class="bi bi-envelope-paper me-2 text-primary"></i>Reset password
        </h1>
        <div id="form-alert" class="alert hidden"></div>
        <form id="forgot-form">
          <div class="mb-3">
            <label class="form-label" for="forgot-email">Email</label>
            <input id="forgot-email" class="form-control" type="email" name="email" required autocomplete="email" />
          </div>
          <div class="cf-turnstile mb-3" data-sitekey={siteKey}></div>
          <button type="submit" class="btn btn-primary w-100">
            <i class="bi bi-send me-1"></i>Send reset link
          </button>
        </form>
        <div class="mt-3 small">
          <a href="/login"><i class="bi bi-arrow-left me-1"></i>Back to sign in</a>
        </div>
      </div>
    </div>
  </Layout>
);

export const ResetPasswordPage: FC<{ csrfToken: string; token: string }> = ({
  csrfToken,
  token,
}) => (
  <Layout title="Set new password" csrfToken={csrfToken}>
    <div class="card shadow-sm auth-card">
      <div class="card-body p-4">
        <h1 class="h4 fw-semibold mb-3">
          <i class="bi bi-key me-2 text-primary"></i>New password
        </h1>
        <div id="form-alert" class="alert hidden"></div>
        <form id="reset-form">
          <input type="hidden" name="token" value={token} />
          <div class="mb-3">
            <label class="form-label" for="reset-password">New Password (min 8 characters)</label>
            <input
              id="reset-password"
              class="form-control"
              type="password"
              name="newPassword"
              required
              minlength={8}
              maxlength={128}
              autocomplete="new-password"
            />
          </div>
          <button type="submit" class="btn btn-primary w-100">
            <i class="bi bi-check2 me-1"></i>Update password
          </button>
        </form>
      </div>
    </div>
  </Layout>
);

export const AdminLoginPage: FC<{ csrfToken: string; siteKey: string }> = ({
  csrfToken,
  siteKey,
}) => (
  <Layout title="Superuser sign in" csrfToken={csrfToken} turnstile>
    <div class="card shadow-sm auth-card">
      <div class="card-body p-4">
        <h1 class="h4 fw-semibold mb-2">
          <i class="bi bi-shield-lock me-2 text-primary"></i>Superuser sign in
        </h1>
        <p class="text-body-secondary small mb-3">
          Assigned admins sign in at <a href="/login">/login</a>.
        </p>
        <div id="form-alert" class="alert hidden"></div>
        <form id="superuser-login-form">
          <div class="mb-3">
            <label class="form-label" for="su-password">Password</label>
            <input
              id="su-password"
              class="form-control"
              type="password"
              name="password"
              required
              autocomplete="current-password"
            />
          </div>
          <div class="cf-turnstile mb-3" data-sitekey={siteKey}></div>
          <button type="submit" class="btn btn-primary w-100">
            <i class="bi bi-shield-check me-1"></i>Sign in
          </button>
        </form>
      </div>
    </div>
  </Layout>
);

export const DevicePage: FC<{
  csrfToken: string;
  userCode?: string;
  userEmail: string;
}> = ({ csrfToken, userCode = '', userEmail }) => (
  <Layout title="Device Verification" csrfToken={csrfToken}>
    <div class="card shadow-sm auth-card">
      <div class="card-body p-4">
        <h1 class="h4 fw-semibold mb-2">
          <i class="bi bi-tv me-2 text-primary"></i>Authorize Device
        </h1>
        <p class="text-body-secondary small mb-3">
          Signed in as <strong>{userEmail}</strong>. Enter the code displayed on your device.
        </p>
        <div id="form-alert" class="alert hidden"></div>
        <form id="device-approve-form">
          <div class="mb-3">
            <label class="form-label" for="device-user-code">Device Code</label>
            <input
              id="device-user-code"
              class="form-control form-control-lg text-center font-monospace text-uppercase"
              type="text"
              name="userCode"
              required
              value={userCode}
              placeholder="XXXX-XXXX"
            />
          </div>
          <div class="d-flex gap-2">
            <button type="button" class="btn btn-outline-secondary flex-fill" id="device-deny-btn">
              Deny
            </button>
            <button type="submit" class="btn btn-primary flex-fill">
              <i class="bi bi-check2-circle me-1"></i>Approve Device
            </button>
          </div>
        </form>
      </div>
    </div>
  </Layout>
);

export const LogoutConfirmPage: FC<{
  appName: string;
  csrfToken: string;
  userEmail: string;
  clientName: string | null;
  postLogoutRedirectUri: string;
  clientId: string;
  state: string;
}> = ({ appName, csrfToken, userEmail, clientName, postLogoutRedirectUri, clientId, state }) => (
  <Layout title="Sign out" csrfToken={csrfToken}>
    <div class="card shadow-sm auth-card">
      <div class="card-body p-4">
        <h1 class="h4 fw-semibold mb-2">
          <i class="bi bi-box-arrow-right me-2 text-primary"></i>Sign out of {appName}
        </h1>
        <p class="text-body-secondary small mb-3">
          {clientName ? (
            <>
              <strong>{clientName}</strong> requested to sign you out of <strong>{userEmail}</strong>.
            </>
          ) : (
            <>
              Confirm signing out of <strong>{userEmail}</strong>.
            </>
          )}
        </p>
        <form method="post" action="/oauth/logout" class="d-flex gap-2">
          <input type="hidden" name="_csrf" value={csrfToken} />
          <input type="hidden" name="post_logout_redirect_uri" value={postLogoutRedirectUri} />
          <input type="hidden" name="client_id" value={clientId} />
          <input type="hidden" name="state" value={state} />
          <button type="submit" name="decision" value="cancel" class="btn btn-outline-secondary flex-fill">
            Stay signed in
          </button>
          <button type="submit" name="decision" value="confirm" class="btn btn-danger flex-fill">
            <i class="bi bi-box-arrow-right me-1"></i>Sign out
          </button>
        </form>
      </div>
    </div>
  </Layout>
);
