import type { FC } from 'hono/jsx';
import type { ResolvedAccountSession } from '../types';
import { Layout } from './Layout';

export const AccountChooserPage: FC<{
  csrfToken: string;
  accounts: ResolvedAccountSession[];
  returnTo?: string;
  oauthParams?: {
    appName: string;
    client_id: string;
    redirect_uri: string;
    response_type: string;
    scope: string;
    state: string;
    code_challenge: string;
    code_challenge_method: string;
    nonce: string;
  };
}> = ({ csrfToken, accounts, returnTo = '/account', oauthParams }) => {
  const userAccounts = accounts.filter((a) => !a.isSuperuser && a.user);
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
        selected: '1',
      }).toString()}`
    : returnTo;

  const addAccountHref = `/login?mode=add&return_to=${encodeURIComponent(effectiveReturnTo)}`;
  const registerHref = `/register?return_to=${encodeURIComponent(effectiveReturnTo)}`;

  return (
    <Layout title={oauthParams ? `Continue to ${oauthParams.appName}` : 'Choose an account'} csrfToken={csrfToken}>
      <div class="auth-card">
        <h1>{oauthParams ? `Continue to ${oauthParams.appName}` : 'Choose an account'}</h1>
        <div id="form-alert" class="alert hidden"></div>

        <div class="account-list">
          {userAccounts.map((acc) => {
            const u = acc.user!;
            const initial = (u.name || u.email || '?').trim().charAt(0).toUpperCase();
            return (
              <div class="account-row" key={acc.sessionId}>
                {oauthParams ? (
                  <form method="post" action="/oauth/select-account" class="account-form">
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
                    <button type="submit" class="account-btn">
                      <span class="avatar-circle">{initial}</span>
                      <span class="account-meta">
                        <strong>{u.name}</strong>
                        <span class="muted small">{u.email}</span>
                      </span>
                    </button>
                  </form>
                ) : (
                  <button
                    type="button"
                    class="account-btn"
                    data-switch-session={acc.sessionId}
                    data-return-to={effectiveReturnTo}
                  >
                    <span class="avatar-circle">{initial}</span>
                    <span class="account-meta">
                      <strong>{u.name}</strong>
                      <span class="muted small">{u.email}</span>
                    </span>
                  </button>
                )}
                <button
                  type="button"
                  class="btn btn-sm btn-ghost account-remove-btn"
                  title="Sign out of this account"
                  data-remove-session={acc.sessionId}
                >
                  ×
                </button>
              </div>
            );
          })}
        </div>

        <div class="chooser-actions">
          <a class="btn btn-ghost btn-full" href={addAccountHref}>Use another account</a>
          <a class="btn btn-ghost btn-full" href={registerHref}>Create account</a>
          {userAccounts.length > 1 && (
            <button type="button" class="btn btn-sm btn-ghost mt-1" data-logout-all-btn>
              Sign out of all accounts
            </button>
          )}
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
}> = ({ csrfToken, siteKey, returnTo = '/account', verified = false, hasSavedAccounts = false }) => (
  <Layout title="Sign in" csrfToken={csrfToken} turnstile>
    <div class="auth-card">
      <h1>Sign in</h1>
      {verified && <div class="alert alert-success">Email verified. You can sign in now.</div>}
      <div id="form-alert" class="alert hidden"></div>
      <form id="login-form" data-return-to={returnTo}>
        <label>
          Email
          <input type="email" name="email" required autocomplete="email" placeholder="you@example.com" />
        </label>
        <label>
          Password
          <input type="password" name="password" required autocomplete="current-password" />
        </label>
        <label id="totp-group" class="hidden">
          Authenticator Code
          <input type="text" name="totpCode" inputmode="numeric" pattern="[0-9]{6}" placeholder="123456" />
        </label>
        <div class="cf-turnstile" data-sitekey={siteKey}></div>
        <button type="submit" class="btn btn-primary btn-full">Sign in</button>
      </form>
      <div class="auth-links">
        <a href="/forgot-password">Forgot password?</a>
        <a href={`/register?return_to=${encodeURIComponent(returnTo)}`}>Create account</a>
      </div>
      {hasSavedAccounts && (
        <div class="mt-1 small">
          <a href={`/login?return_to=${encodeURIComponent(returnTo)}`}>← Back to saved accounts</a>
        </div>
      )}
    </div>
  </Layout>
);

export const RegisterPage: FC<{
  csrfToken: string;
  siteKey: string;
  returnTo?: string;
}> = ({ csrfToken, siteKey, returnTo = '/account' }) => (
  <Layout title="Create account" csrfToken={csrfToken} turnstile>
    <div class="auth-card">
      <h1>Create account</h1>
      <div id="form-alert" class="alert hidden"></div>
      <form id="register-form" data-return-to={returnTo}>
        <label>
          Name
          <input type="text" name="name" required maxlength={80} autocomplete="name" />
        </label>
        <label>
          Email
          <input type="email" name="email" required autocomplete="email" placeholder="you@example.com" />
        </label>
        <label>
          Password (min 8 characters)
          <input type="password" name="password" required minlength={8} maxlength={128} autocomplete="new-password" />
        </label>
        <div class="cf-turnstile" data-sitekey={siteKey}></div>
        <button type="submit" class="btn btn-primary btn-full">Create account</button>
      </form>
      <div class="auth-links">
        <a href={`/login?return_to=${encodeURIComponent(returnTo)}`}>Sign in instead</a>
      </div>
    </div>
  </Layout>
);

export const ForgotPasswordPage: FC<{ csrfToken: string; siteKey: string }> = ({
  csrfToken,
  siteKey,
}) => (
  <Layout title="Reset password" csrfToken={csrfToken} turnstile>
    <div class="auth-card">
      <h1>Reset password</h1>
      <div id="form-alert" class="alert hidden"></div>
      <form id="forgot-form">
        <label>
          Email
          <input type="email" name="email" required autocomplete="email" />
        </label>
        <div class="cf-turnstile" data-sitekey={siteKey}></div>
        <button type="submit" class="btn btn-primary btn-full">Send reset link</button>
      </form>
      <div class="auth-links">
        <a href="/login">Back to sign in</a>
      </div>
    </div>
  </Layout>
);

export const ResetPasswordPage: FC<{ csrfToken: string; token: string }> = ({
  csrfToken,
  token,
}) => (
  <Layout title="Set new password" csrfToken={csrfToken}>
    <div class="auth-card">
      <h1>New password</h1>
      <div id="form-alert" class="alert hidden"></div>
      <form id="reset-form">
        <input type="hidden" name="token" value={token} />
        <label>
          New Password (min 8 characters)
          <input type="password" name="newPassword" required minlength={8} maxlength={128} autocomplete="new-password" />
        </label>
        <button type="submit" class="btn btn-primary btn-full">Update password</button>
      </form>
    </div>
  </Layout>
);

export const AdminLoginPage: FC<{ csrfToken: string; siteKey: string }> = ({
  csrfToken,
  siteKey,
}) => (
  <Layout title="Superuser sign in" csrfToken={csrfToken} turnstile>
    <div class="auth-card">
      <h1>Superuser sign in</h1>
      <p class="muted small">
        Assigned admins sign in at <a href="/login">/login</a>.
      </p>
      <div id="form-alert" class="alert hidden"></div>
      <form id="superuser-login-form">
        <label>
          Password
          <input type="password" name="password" required autocomplete="current-password" />
        </label>
        <div class="cf-turnstile" data-sitekey={siteKey}></div>
        <button type="submit" class="btn btn-primary btn-full">Sign in</button>
      </form>
    </div>
  </Layout>
);
