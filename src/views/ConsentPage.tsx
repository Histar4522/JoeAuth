import type { FC } from 'hono/jsx';
import type { AuthContext } from '../types';
import { Layout } from './Layout';

export interface ConsentPageProps {
  appName: string;
  auth: AuthContext;
  csrfToken: string;
  clientApp: {
    name: string;
    description: string;
    homepage_url: string;
    client_id: string;
  };
  scopes: string[];
  params: {
    client_id: string;
    redirect_uri: string;
    response_type: string;
    scope: string;
    state: string;
    code_challenge: string;
    code_challenge_method: string;
    nonce: string;
  };
}

const SCOPE_LABELS: Record<string, string> = {
  openid: 'Verify your identity',
  profile: 'Read your display name and role',
  email: 'Read your email address',
  offline_access: 'Keep you signed in',
};

export const ConsentPage: FC<ConsentPageProps> = ({
  auth,
  csrfToken,
  clientApp,
  scopes,
  params,
}) => {
  const user = auth.user!;
  return (
    <Layout title={`Authorize ${clientApp.name}`} auth={auth} csrfToken={csrfToken}>
      <div class="card shadow-sm auth-card">
        <div class="card-body p-4">
          <h1 class="h4 fw-semibold mb-2">
            <i class="bi bi-shield-check me-2 text-primary"></i>{clientApp.name} wants access
          </h1>
          <p class="text-body-secondary small mb-3">
            Signed in as <strong>{user.email}</strong> ·{' '}
            <a href={`/oauth/authorize?${new URLSearchParams(params).toString()}`}>
              <i class="bi bi-people me-1"></i>Switch account
            </a>
          </p>

          {clientApp.description && (
            <p class="p-2 rounded bg-body-tertiary border small mb-3">{clientApp.description}</p>
          )}

          <div class="border rounded bg-body-tertiary p-3 mb-3">
            <div class="fw-semibold small mb-2">Permissions requested:</div>
            <ul class="list-unstyled mb-0 small">
              {scopes.map((s) => (
                <li key={s} class="mb-1">
                  <i class="bi bi-check2-circle text-success me-2"></i>
                  {SCOPE_LABELS[s] || s}
                </li>
              ))}
            </ul>
          </div>

          <form method="post" action="/oauth/authorize" class="d-flex gap-2">
            <input type="hidden" name="_csrf" value={csrfToken} />
            <input type="hidden" name="client_id" value={params.client_id} />
            <input type="hidden" name="redirect_uri" value={params.redirect_uri} />
            <input type="hidden" name="response_type" value={params.response_type} />
            <input type="hidden" name="scope" value={params.scope} />
            <input type="hidden" name="state" value={params.state} />
            <input type="hidden" name="code_challenge" value={params.code_challenge} />
            <input type="hidden" name="code_challenge_method" value={params.code_challenge_method} />
            <input type="hidden" name="nonce" value={params.nonce} />
            <button type="submit" name="decision" value="deny" class="btn btn-outline-secondary flex-fill">
              <i class="bi bi-x-lg me-1"></i>Cancel
            </button>
            <button type="submit" name="decision" value="allow" class="btn btn-primary flex-fill">
              <i class="bi bi-check-lg me-1"></i>Allow
            </button>
          </form>
        </div>
      </div>
    </Layout>
  );
};
