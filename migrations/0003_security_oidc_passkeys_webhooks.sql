-- Phase 1: Public vs Confidential clients, post-logout URIs, webhooks, auth_time, and Device Authorization Grant
ALTER TABLE apps ADD COLUMN client_type TEXT NOT NULL DEFAULT 'confidential';
ALTER TABLE apps ADD COLUMN post_logout_redirect_uris TEXT NOT NULL DEFAULT '[]';
ALTER TABLE apps ADD COLUMN webhook_url TEXT NOT NULL DEFAULT '';
ALTER TABLE apps ADD COLUMN webhook_secret_enc TEXT;

ALTER TABLE sessions ADD COLUMN auth_time INTEGER NOT NULL DEFAULT 0;
UPDATE sessions SET auth_time = created_at WHERE auth_time = 0;

ALTER TABLE oauth_codes ADD COLUMN auth_time INTEGER NOT NULL DEFAULT 0;

CREATE TABLE IF NOT EXISTS device_codes (
  device_code_hash TEXT PRIMARY KEY,
  user_code TEXT NOT NULL UNIQUE,
  app_id TEXT NOT NULL,
  scope TEXT NOT NULL,
  status TEXT NOT NULL DEFAULT 'pending',
  user_id TEXT,
  last_poll_at INTEGER NOT NULL DEFAULT 0,
  interval_sec INTEGER NOT NULL DEFAULT 5,
  expires_at INTEGER NOT NULL,
  created_at INTEGER NOT NULL,
  FOREIGN KEY (app_id) REFERENCES apps(id) ON DELETE CASCADE,
  FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
);
CREATE INDEX IF NOT EXISTS idx_device_codes_expires ON device_codes(expires_at);

-- Phase 2: 2FA recovery codes & WebAuthn passkeys
CREATE TABLE IF NOT EXISTS user_recovery_codes (
  id TEXT PRIMARY KEY,
  user_id TEXT NOT NULL,
  code_hash TEXT NOT NULL,
  used_at INTEGER,
  created_at INTEGER NOT NULL,
  FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
);
CREATE INDEX IF NOT EXISTS idx_recovery_user ON user_recovery_codes(user_id, used_at);

CREATE TABLE IF NOT EXISTS webauthn_credentials (
  id TEXT PRIMARY KEY,
  user_id TEXT NOT NULL,
  label TEXT NOT NULL DEFAULT 'Passkey',
  public_key_jwk TEXT NOT NULL,
  alg INTEGER NOT NULL DEFAULT -7,
  sign_count INTEGER NOT NULL DEFAULT 0,
  transports TEXT NOT NULL DEFAULT '[]',
  last_used_at INTEGER,
  created_at INTEGER NOT NULL,
  FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
);
CREATE INDEX IF NOT EXISTS idx_webauthn_user ON webauthn_credentials(user_id);

-- Phase 3: Per-app OAuth error logs (pruned by daily cron)
CREATE TABLE IF NOT EXISTS oauth_error_logs (
  id TEXT PRIMARY KEY,
  app_id TEXT NOT NULL,
  endpoint TEXT NOT NULL,
  error_code TEXT NOT NULL,
  detail TEXT NOT NULL,
  created_at INTEGER NOT NULL,
  FOREIGN KEY (app_id) REFERENCES apps(id) ON DELETE CASCADE
);
CREATE INDEX IF NOT EXISTS idx_oauth_err_app_time ON oauth_error_logs(app_id, created_at DESC);
