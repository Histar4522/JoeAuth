import { Hono } from 'hono';
import type { AppEnv } from '../types';
import {
  AccountChooserPage,
  AdminLoginPage,
  ForgotPasswordPage,
  LoginPage,
  RegisterPage,
  ResetPasswordPage,
} from '../views/AuthPages';
import { UserPanel } from '../views/UserPanel';
import { DevPanel } from '../views/DevPanel';
import { AdminPanel } from '../views/AdminPanel';
import { DocsPage } from '../views/DocsPage';

const pageRoutes = new Hono<AppEnv>();

pageRoutes.get('/', (c) => {
  const auth = c.get('auth');
  if (auth?.isSuperuser) return c.redirect('/admin');
  if (auth?.user) return c.redirect('/account');
  return c.redirect('/login');
});

pageRoutes.get('/login', (c) => {
  const auth = c.get('auth');
  const returnTo = c.req.query('return_to') || '/account';
  const mode = c.req.query('mode') || '';
  const userAccounts = (auth?.accounts || []).filter((a) => !a.isSuperuser && a.user);

  if (mode !== 'add' && userAccounts.length > 0) {
    return c.html(
      <AccountChooserPage
        csrfToken={c.get('csrfToken')}
        accounts={userAccounts}
        returnTo={returnTo}
      />
    );
  }

  return c.html(
    <LoginPage
      csrfToken={c.get('csrfToken')}
      siteKey={c.env.TURNSTILE_SITE_KEY}
      returnTo={returnTo}
      verified={c.req.query('verified') === '1'}
      hasSavedAccounts={userAccounts.length > 0}
    />
  );
});

pageRoutes.get('/register', (c) => {
  const returnTo = c.req.query('return_to') || '/account';
  return c.html(
    <RegisterPage
      csrfToken={c.get('csrfToken')}
      siteKey={c.env.TURNSTILE_SITE_KEY}
      returnTo={returnTo}
    />
  );
});

pageRoutes.get('/forgot-password', (c) => {
  return c.html(
    <ForgotPasswordPage
      csrfToken={c.get('csrfToken')}
      siteKey={c.env.TURNSTILE_SITE_KEY}
    />
  );
});

pageRoutes.get('/reset-password', (c) => {
  return c.html(
    <ResetPasswordPage
      csrfToken={c.get('csrfToken')}
      token={c.req.query('token') || ''}
    />
  );
});

pageRoutes.get('/account', (c) => {
  const auth = c.get('auth');
  if (!auth?.user) {
    return c.redirect('/login?return_to=/account');
  }
  return c.html(
    <UserPanel appName={c.env.APP_NAME || 'JoeAuth'} auth={auth} csrfToken={c.get('csrfToken')} />
  );
});

pageRoutes.get('/developer', (c) => {
  const auth = c.get('auth');
  if (!auth?.user) {
    return c.redirect('/login?return_to=/developer');
  }
  return c.html(
    <DevPanel
      appName={c.env.APP_NAME || 'JoeAuth'}
      auth={auth}
      csrfToken={c.get('csrfToken')}
      siteKey={c.env.TURNSTILE_SITE_KEY}
    />
  );
});

pageRoutes.get('/admin/login', (c) => {
  const auth = c.get('auth');
  if (auth?.isSuperuser || auth?.user?.role === 'admin') {
    return c.redirect('/admin');
  }
  return c.html(
    <AdminLoginPage
      csrfToken={c.get('csrfToken')}
      siteKey={c.env.TURNSTILE_SITE_KEY}
    />
  );
});

pageRoutes.get('/admin', (c) => {
  const auth = c.get('auth');
  if (!auth || !auth.sessionId || (!auth.isSuperuser && auth.user?.role !== 'admin')) {
    return c.redirect('/admin/login');
  }
  return c.html(
    <AdminPanel appName={c.env.APP_NAME || 'JoeAuth'} auth={auth} csrfToken={c.get('csrfToken')} />
  );
});

pageRoutes.get('/docs', (c) => {
  const issuer = (c.env.ISSUER_URL || new URL(c.req.url).origin).replace(/\/$/, '');
  return c.html(
    <DocsPage
      appName={c.env.APP_NAME || 'JoeAuth'}
      issuer={issuer}
      auth={c.get('auth')}
      csrfToken={c.get('csrfToken')}
    />
  );
});

export default pageRoutes;
