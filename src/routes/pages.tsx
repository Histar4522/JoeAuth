import { Hono } from 'hono';
import type { AppEnv } from '../types';
import { sanitizeReturnTo } from '../lib/session';
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

function getUserAccounts(auth: AppEnv['Variables']['auth']) {
  return (auth?.accounts || []).filter((a) => !a.isSuperuser && a.user);
}

pageRoutes.get('/', (c) => {
  const auth = c.get('auth');
  const base = auth?.basePath || '';
  if (base === '/u/superuser') {
    return c.redirect(auth?.isSuperuser ? '/u/superuser/admin' : '/admin/login');
  }
  if (base && auth?.user) {
    return c.redirect(`${base}/account`);
  }
  if (auth?.isSuperuser) {
    return c.redirect(getUserAccounts(auth).length > 0 ? '/u/superuser/admin' : '/admin');
  }
  if (auth?.user) {
    const userAccounts = getUserAccounts(auth);
    return c.redirect(userAccounts.length > 1 ? `/u/${auth.slot}/account` : '/account');
  }
  if (auth?.accounts?.some((a) => a.isSuperuser)) {
    return c.redirect('/u/superuser/admin');
  }
  return c.redirect('/login');
});

pageRoutes.get('/login', (c) => {
  const auth = c.get('auth');
  const returnTo = sanitizeReturnTo(c.req.query('return_to'), '/account');
  const mode = c.req.query('mode') || '';
  const userAccounts = (auth?.accounts || []).filter((a) => !a.isSuperuser && a.user);

  if (mode !== 'add' && userAccounts.length > 0) {
    return c.html(
      <AccountChooserPage
        csrfToken={c.get('csrfToken')}
        accounts={auth?.accounts || []}
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
  const returnTo = sanitizeReturnTo(c.req.query('return_to'), '/account');
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
  const base = auth?.basePath || '';
  if (base === '/u/superuser') {
    return c.redirect(auth?.isSuperuser ? '/u/superuser/admin' : '/admin/login');
  }
  if (!auth?.user) {
    return c.redirect('/login?return_to=/account');
  }
  const userAccounts = getUserAccounts(auth);
  if (!base && userAccounts.length > 1) {
    return c.redirect(`/u/${auth.slot}/account`);
  }
  return c.html(
    <UserPanel appName={c.env.APP_NAME || 'JoeAuth'} auth={auth} csrfToken={c.get('csrfToken')} />
  );
});

pageRoutes.get('/developer', (c) => {
  const auth = c.get('auth');
  const base = auth?.basePath || '';
  if (base === '/u/superuser') {
    return c.redirect(auth?.isSuperuser ? '/u/superuser/admin' : '/admin/login');
  }
  if (!auth?.user) {
    return c.redirect('/login?return_to=/developer');
  }
  const userAccounts = getUserAccounts(auth);
  if (!base && userAccounts.length > 1) {
    return c.redirect(`/u/${auth.slot}/developer`);
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
  if (auth?.isSuperuser || auth?.accounts?.some((a) => a.isSuperuser)) {
    return c.redirect('/u/superuser/admin');
  }
  if (auth?.user?.role === 'admin') {
    const userAccounts = getUserAccounts(auth);
    return c.redirect(userAccounts.length > 1 ? `/u/${auth.slot}/admin` : '/admin');
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
  const base = auth?.basePath || '';
  const userAccounts = getUserAccounts(auth);

  if (base === '/u/superuser') {
    if (!auth?.isSuperuser) return c.redirect('/admin/login');
    return c.html(
      <AdminPanel appName={c.env.APP_NAME || 'JoeAuth'} auth={auth} csrfToken={c.get('csrfToken')} />
    );
  }

  if (base) {
    if (!auth?.user || auth.user.role !== 'admin') return c.redirect('/admin/login');
    return c.html(
      <AdminPanel appName={c.env.APP_NAME || 'JoeAuth'} auth={auth} csrfToken={c.get('csrfToken')} />
    );
  }

  if (!auth || !auth.sessionId || (!auth.isSuperuser && auth.user?.role !== 'admin')) {
    if (auth?.accounts?.some((a) => a.isSuperuser)) {
      return c.redirect('/u/superuser/admin');
    }
    return c.redirect('/admin/login');
  }

  if (auth.isSuperuser && userAccounts.length > 0) {
    return c.redirect('/u/superuser/admin');
  }
  if (auth.user?.role === 'admin' && userAccounts.length > 1) {
    return c.redirect(`/u/${auth.slot}/admin`);
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
