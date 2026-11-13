export interface Bindings extends Omit<
  CloudflareBindings,
  'APP_NAME' | 'ISSUER_URL' | 'EMAIL_FROM' | 'TURNSTILE_SITE_KEY' | 'REQUIRE_EMAIL_VERIFICATION'
> {
  MEDIA_BUCKET: R2Bucket;
  APP_NAME: string;
  ISSUER_URL: string;
  EMAIL_FROM: string;
  TURNSTILE_SITE_KEY: string;
  REQUIRE_EMAIL_VERIFICATION: string;
  SUPERUSER_PASSWORD_HASH?: string;
  PASSWORD_PEPPER?: string;
  JWT_PRIVATE_JWK?: string;
  JWT_PUBLIC_JWK?: string;
  TURNSTILE_SECRET_KEY?: string;
  RESEND_API_KEY?: string;
}

export type UserRole = 'user' | 'admin';
export type DeveloperStatus = 'none' | 'pending' | 'approved' | 'rejected' | 'revoked';
export type UserStatus = 'active' | 'suspended' | 'deleted';

export interface UserRow {
  id: string;
  email: string;
  name: string;
  password_hash: string;
  role: UserRole;
  developer_status: DeveloperStatus;
  status: UserStatus;
  email_verified: number;
  totp_secret: string | null;
  totp_enabled: number;
  avatar_key: string | null;
  avatar_color: string;
  avatar_version: number;
  created_at: number;
  updated_at: number;
}

export interface SessionRow {
  id: string;
  user_id: string;
  is_superuser: number;
  ip_hash: string | null;
  user_agent: string | null;
  expires_at: number;
  created_at: number;
  last_seen_at: number;
}

export interface DeveloperApplicationRow {
  id: string;
  user_id: string;
  service_name: string;
  service_url: string;
  reason: string;
  status: 'pending' | 'approved' | 'rejected';
  review_note: string;
  reviewed_by: string | null;
  reviewed_at: number | null;
  created_at: number;
}

export interface AppRow {
  id: string;
  owner_user_id: string;
  name: string;
  description: string;
  privilege_description: string;
  homepage_url: string;
  client_id: string;
  client_secret_hash: string;
  client_secret_prefix: string;
  redirect_uris: string;
  allowed_scopes: string;
  logo_key: string | null;
  logo_version: number;
  is_first_party: number;
  status: 'approved' | 'suspended';
  created_at: number;
  updated_at: number;
}

export interface RegistrationRuleRow {
  id: string;
  rule_type: 'allow' | 'deny';
  pattern: string;
  description: string;
  priority: number;
  is_active: number;
  created_by: string;
  created_at: number;
}

export interface ResolvedAccountSession {
  sessionId: string;
  slot: string;
  isSuperuser: boolean;
  user: UserRow | null;
  lastSeenAt: number;
}

export interface AuthContext {
  sessionId: string;
  slot: string | null;
  basePath: string;
  isSuperuser: boolean;
  user: UserRow | null;
  accounts: ResolvedAccountSession[];
}

export interface Variables {
  auth: AuthContext | null;
  csrfToken: string;
}

export type AppEnv = {
  Bindings: Bindings;
  Variables: Variables;
};
