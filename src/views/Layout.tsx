import type { FC, PropsWithChildren } from 'hono/jsx';
import type { AuthContext } from '../types';

export interface LayoutProps {
  title: string;
  auth?: AuthContext | null;
  csrfToken?: string;
  turnstile?: boolean;
  showNav?: boolean;
}

const ThemeSelect: FC = () => (
  <div class="input-group input-group-sm w-auto">
    <span class="input-group-text" title="Color theme">
      <i class="bi bi-circle-half"></i>
    </span>
    <select
      class="form-select form-select-sm w-auto"
      data-theme-select
      aria-label="Theme"
      title="Theme (Auto / Dark / Light)"
    >
      <option value="auto" selected>Auto</option>
      <option value="dark">Dark</option>
      <option value="light">Light</option>
    </select>
  </div>
);

export const Layout: FC<PropsWithChildren<LayoutProps>> = ({
  title,
  auth,
  csrfToken = '',
  turnstile = false,
  showNav = false,
  children,
}) => {
  const isAdmin = Boolean(auth?.isSuperuser || auth?.user?.role === 'admin');
  const base = auth?.basePath || '';
  const hasSuperuserSession = Boolean(auth?.accounts?.some((a) => a.isSuperuser));
  const adminHref = auth?.isSuperuser ? '/u/superuser/admin' : `${base}/admin`;
  return (
    <html lang="en" data-bs-theme="dark">
      <head>
        <meta charset="UTF-8" />
        <meta name="viewport" content="width=device-width, initial-scale=1.0" />
        <meta name="csrf-token" content={csrfToken} />
        <meta name="account-base" content={base} />
        <title>{title}</title>
        <script src="/theme.js"></script>
        <link rel="stylesheet" href="/vendor/bootstrap.min.css" />
        <link rel="stylesheet" href="/vendor/bootstrap-icons.min.css" />
        <link rel="stylesheet" href="/styles.css" />
        {turnstile && (
          <script src="https://challenges.cloudflare.com/turnstile/v0/api.js" async defer></script>
        )}
        <script src="/app.js" defer></script>
      </head>
      <body class={showNav ? '' : 'centered-body'}>
        {showNav ? (
          <nav class="navbar navbar-expand bg-body-tertiary border-bottom">
            <div class="container">
              <div class="navbar-nav flex-row flex-wrap gap-2">
                {auth?.user && (
                  <a class="nav-link px-2" href={`${base}/account`}>
                    <i class="bi bi-person-circle me-1"></i>Account
                  </a>
                )}
                {auth?.user && (
                  <a class="nav-link px-2" href={`${base}/developer`}>
                    <i class="bi bi-code-square me-1"></i>Developer
                  </a>
                )}
                {isAdmin && (
                  <a class="nav-link px-2" href={adminHref}>
                    <i class="bi bi-shield-lock me-1"></i>Admin
                  </a>
                )}
                {!auth?.isSuperuser && hasSuperuserSession && (
                  <a class="nav-link px-2" href="/u/superuser/admin" title="Open Superuser Admin Console">
                    <i class="bi bi-shield-shaded me-1 text-success"></i>Superuser
                  </a>
                )}
              </div>
              <div class="d-flex align-items-center gap-2 ms-auto">
                <ThemeSelect />
                {auth?.sessionId ? (
                  <>
                    <a class="btn btn-sm btn-outline-secondary" href="/login">
                      <i class="bi bi-people me-1"></i>Switch account
                    </a>
                    <button type="button" class="btn btn-sm btn-outline-secondary" data-logout-btn>
                      <i class="bi bi-box-arrow-right me-1"></i>Sign out
                    </button>
                  </>
                ) : (
                  <a class="btn btn-sm btn-outline-primary" href="/login">
                    <i class="bi bi-box-arrow-in-right me-1"></i>Sign in
                  </a>
                )}
              </div>
            </div>
          </nav>
        ) : (
          <div class="floating-theme-toggle">
            <ThemeSelect />
          </div>
        )}
        <main class={showNav ? 'container main-content py-4' : 'minimal-main'}>{children}</main>
      </body>
    </html>
  );
};
