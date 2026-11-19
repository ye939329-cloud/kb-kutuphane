CREATE TABLE IF NOT EXISTS users (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  name TEXT NOT NULL CHECK (length(name) BETWEEN 1 AND 120),
  email TEXT UNIQUE,
  phone TEXT UNIQUE,
  password_hash TEXT NOT NULL,
  role TEXT NOT NULL DEFAULT 'student' CHECK (role IN ('student', 'admin')),
  email_verified INTEGER NOT NULL DEFAULT 0 CHECK (email_verified IN (0, 1)),
  phone_verified INTEGER NOT NULL DEFAULT 0 CHECK (phone_verified IN (0, 1)),
  token_version INTEGER NOT NULL DEFAULT 0,
  created_at INTEGER NOT NULL,
  CHECK (email IS NOT NULL OR phone IS NOT NULL)
);

CREATE TABLE IF NOT EXISTS verification_codes (
  user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  type TEXT NOT NULL CHECK (type IN ('email', 'phone')),
  purpose TEXT NOT NULL CHECK (purpose IN ('verify', 'reset')),
  code_hash TEXT NOT NULL,
  expires_at INTEGER NOT NULL,
  attempts INTEGER NOT NULL DEFAULT 0 CHECK (attempts BETWEEN 0 AND 5),
  created_at INTEGER NOT NULL,
  PRIMARY KEY (user_id, type, purpose)
);

CREATE INDEX IF NOT EXISTS idx_verification_codes_expiry
  ON verification_codes (expires_at);
