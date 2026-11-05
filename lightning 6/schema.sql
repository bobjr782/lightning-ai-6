-- Lightning account storage schema
CREATE TABLE IF NOT EXISTS users (
  id TEXT PRIMARY KEY,
  username TEXT NOT NULL,
  username_norm TEXT NOT NULL UNIQUE,
  salt TEXT NOT NULL,
  password_hash TEXT NOT NULL,
  created_at INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS sessions (
  token_hash TEXT PRIMARY KEY,
  user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  expires_at INTEGER NOT NULL,
  created_at INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS sessions_user_idx ON sessions(user_id);
CREATE INDEX IF NOT EXISTS sessions_expiry_idx ON sessions(expires_at);
CREATE TABLE IF NOT EXISTS user_data (
  user_id TEXT PRIMARY KEY REFERENCES users(id) ON DELETE CASCADE,
  data_json TEXT NOT NULL DEFAULT '{}',
  updated_at INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS shares (
  id TEXT PRIMARY KEY,
  owner_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  recipient_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  artifact_json TEXT NOT NULL,
  created_at INTEGER NOT NULL,
  UNIQUE(owner_id, recipient_id, id)
);
CREATE INDEX IF NOT EXISTS shares_recipient_idx ON shares(recipient_id, created_at);
CREATE TABLE IF NOT EXISTS auth_attempts (
  ip_hash TEXT NOT NULL,
  attempted_at INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS auth_attempts_ip_time_idx ON auth_attempts(ip_hash, attempted_at);
