import type { FC, PropsWithChildren } from 'hono/jsx';
import type { AuthContext } from '../types';

export interface LayoutProps {
  title: string;
  auth?: AuthContext | null;
  csrfToken?: string;
  turnstile?: boolean;
  showNav?: boolean;
}

export const Layout: FC<PropsWithChildren<LayoutProps>> = ({
  title,
  auth,
  csrfToken = '',
  turnstile = false,
  showNav = false,
  children,
}) => {
  const isAdmin = Boolean(auth?.isSuperuser || auth?.user?.role === 'admin');
  return (
    <html lang="en">
      <head>
        <meta charset="UTF-8" />
        <meta name="viewport" content="width=device-width, initial-scale=1.0" />
        <meta name="csrf-token" content={csrfToken} />
        <title>{title}</title>
        <link rel="stylesheet" href="/styles.css" />
        {turnstile && (
          <script src="https://challenges.cloudflare.com/turnstile/v0/api.js" async defer></script>
        )}
        <script src="/app.js" defer></script>
      </head>
      <body class={showNav ? '' : 'centered-body'}>
        {showNav && (
          <nav class="subnav">
            <div class="container subnav-inner">
              <div class="nav">
                {auth?.user && <a href="/account">Account</a>}
                {auth?.user && <a href="/developer">Developer</a>}
                {isAdmin && <a href="/admin">Admin</a>}
                <a href="/docs">Docs</a>
              </div>
              <div class="nav">
                {auth?.sessionId ? (
                  <>
                    <a href="/login">Switch account</a>
                    <button type="button" class="btn btn-sm btn-ghost" data-logout-btn>
                      Sign out
                    </button>
                  </>
                ) : (
                  <a href="/login">Sign in</a>
                )}
              </div>
            </div>
          </nav>
        )}
        <main class={showNav ? 'container main-content' : 'minimal-main'}>{children}</main>
      </body>
    </html>
  );
};
