const { Pool } = require("pg");

if (!process.env.DATABASE_URL) {
  throw new Error("DATABASE_URL is required");
}

const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  max: 10,
  idleTimeoutMillis: 30000,
  connectionTimeoutMillis: 5000,
});

async function initializeDatabase() {
  await pool.query(`
    CREATE TABLE IF NOT EXISTS users (
      id INTEGER GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
      full_name TEXT NOT NULL,
      email TEXT NOT NULL UNIQUE,
      country_code TEXT NOT NULL,
      mobile TEXT NOT NULL UNIQUE,
      password_hash TEXT NOT NULL,
      email_verified INTEGER NOT NULL DEFAULT 0,
      mobile_verified INTEGER NOT NULL DEFAULT 0,
      mfa_enabled INTEGER NOT NULL DEFAULT 0,
      mfa_method TEXT,
      mfa_secret_enc TEXT,
      created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
      updated_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP
    );

    CREATE TABLE IF NOT EXISTS registration_challenges (
      id TEXT PRIMARY KEY,
      user_id INTEGER NOT NULL,
      step TEXT NOT NULL,
      mfa_method TEXT,
      created_at BIGINT NOT NULL,
      expires_at BIGINT NOT NULL,
      FOREIGN KEY (user_id)
        REFERENCES users(id)
        ON DELETE CASCADE
    );

    CREATE TABLE IF NOT EXISTS otp_challenges (
      id TEXT PRIMARY KEY,
      registration_id TEXT NOT NULL,
      channel TEXT NOT NULL,
      purpose TEXT NOT NULL,
      otp_hash TEXT NOT NULL,
      created_at BIGINT NOT NULL,
      expires_at BIGINT NOT NULL,
      attempts INTEGER NOT NULL DEFAULT 0,
      max_attempts INTEGER NOT NULL DEFAULT 5,
      used INTEGER NOT NULL DEFAULT 0,
      FOREIGN KEY (registration_id)
        REFERENCES registration_challenges(id)
        ON DELETE CASCADE
    );

    CREATE INDEX IF NOT EXISTS idx_otp_registration
      ON otp_challenges(registration_id);

    CREATE INDEX IF NOT EXISTS idx_registration_user
      ON registration_challenges(user_id);

    CREATE TABLE IF NOT EXISTS login_challenges (
      id TEXT PRIMARY KEY,
      user_id INTEGER NOT NULL,
      step TEXT NOT NULL,
      mfa_method TEXT,
      created_at BIGINT NOT NULL,
      expires_at BIGINT NOT NULL,
      FOREIGN KEY (user_id)
      REFERENCES users(id)
      ON DELETE CASCADE
    );

    CREATE TABLE IF NOT EXISTS login_otp_challenges (
      id TEXT PRIMARY KEY,
      login_challenge_id TEXT NOT NULL,
      channel TEXT NOT NULL,
      otp_hash TEXT NOT NULL,
      created_at BIGINT NOT NULL,
      expires_at BIGINT NOT NULL,
      attempts INTEGER NOT NULL DEFAULT 0,
      max_attempts INTEGER NOT NULL DEFAULT 5,
      used INTEGER NOT NULL DEFAULT 0,
      FOREIGN KEY (login_challenge_id)
      REFERENCES login_challenges(id)
      ON DELETE CASCADE
    );

    CREATE INDEX IF NOT EXISTS idx_login_otp_challenge
      ON login_otp_challenges(login_challenge_id);

    CREATE INDEX IF NOT EXISTS idx_login_challenges_user
      ON login_challenges(user_id);

    CREATE TABLE IF NOT EXISTS login_sessions (
      id TEXT PRIMARY KEY,
      user_id INTEGER NOT NULL,
      token_hash TEXT NOT NULL UNIQUE,
      created_at BIGINT NOT NULL,
      expires_at BIGINT NOT NULL,
      revoked INTEGER NOT NULL DEFAULT 0,

      FOREIGN KEY (user_id)
        REFERENCES users(id)
        ON DELETE CASCADE
    );

    CREATE INDEX IF NOT EXISTS idx_login_sessions_user
      ON login_sessions(user_id);

    CREATE INDEX IF NOT EXISTS idx_login_sessions_token
      ON login_sessions(token_hash);
  `);
}

module.exports = {
  pool,
  initializeDatabase,
};
