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
      <div class="auth-card">
        <h1>{clientApp.name} wants access</h1>
        <p class="muted small">
          Signed in as <strong>{user.email}</strong> ·{' '}
          <a href={`/oauth/authorize?${new URLSearchParams(params).toString()}`}>
            Switch account
          </a>
        </p>

        {clientApp.description && <p class="desc-box">{clientApp.description}</p>}

        <div class="scope-list">
          <div class="scope-title">Permissions requested:</div>
          <ul>
            {scopes.map((s) => (
              <li key={s}>
                {SCOPE_LABELS[s] || s}
              </li>
            ))}
          </ul>
        </div>

        <form method="post" action="/oauth/authorize" class="btn-row">
          <input type="hidden" name="_csrf" value={csrfToken} />
          <input type="hidden" name="client_id" value={params.client_id} />
          <input type="hidden" name="redirect_uri" value={params.redirect_uri} />
          <input type="hidden" name="response_type" value={params.response_type} />
          <input type="hidden" name="scope" value={params.scope} />
          <input type="hidden" name="state" value={params.state} />
          <input type="hidden" name="code_challenge" value={params.code_challenge} />
          <input type="hidden" name="code_challenge_method" value={params.code_challenge_method} />
          <input type="hidden" name="nonce" value={params.nonce} />
          <button type="submit" name="decision" value="deny" class="btn btn-ghost">
            Cancel
          </button>
          <button type="submit" name="decision" value="allow" class="btn btn-primary">
            Continue
          </button>
        </form>
      </div>
    </Layout>
  );
};
