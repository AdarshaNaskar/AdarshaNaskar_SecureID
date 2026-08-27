const crypto = require("crypto");

const { pool } = require("./database");

/* =====================================================
   CONFIGURATION
   ===================================================== */

const SESSION_TTL = 8 * 60 * 60 * 1000; // 8 hours
const REMEMBER_ME_TTL = 30 * 24 * 60 * 60 * 1000; // 30 days

const SESSION_COOKIE_NAME = "secureid_session";

/* =====================================================
   HASH SESSION TOKEN
   ===================================================== */

function hashSessionToken(token) {
  return crypto.createHash("sha256").update(token).digest("hex");
}

/* =====================================================
   CREATE SESSION
   ===================================================== */

async function createSession(userId, rememberMe = false) {
  if (!userId) {
    throw new Error("userId is required to create a session");
  }

  /*
   * Generate a cryptographically secure
   * random session token.
   *
   * 32 random bytes = 256 bits.
   */

  const token = crypto.randomBytes(32).toString("hex");

  /*
   * Never store the raw token in the database.
   */

  const tokenHash = hashSessionToken(token);

  const sessionId = crypto.randomBytes(32).toString("hex");

  const createdAt = Date.now();

  const expiresAt = createdAt + (rememberMe ? REMEMBER_ME_TTL : SESSION_TTL);

  await pool.query(
    `
    INSERT INTO login_sessions
      (
        id,
        user_id,
        token_hash,
        created_at,
        expires_at,
        revoked
      )
    VALUES
      ($1, $2, $3, $4, $5, 0)
    `,
    [sessionId, userId, tokenHash, createdAt, expiresAt],
  );

  return {
    token,
    sessionId,
    expiresAt,
  };
}

/* =====================================================
   GET SESSION
   ===================================================== */

async function getSession(token) {
  if (typeof token !== "string" || token.length === 0) {
    return null;
  }

  const tokenHash = hashSessionToken(token);

  const result = await pool.query(
    `
      SELECT
        ls.id,
        ls.user_id,
        ls.created_at,
        ls.expires_at,
        ls.revoked,

        u.email,
        u.full_name

      FROM login_sessions ls

      JOIN users u
        ON u.id = ls.user_id

      WHERE ls.token_hash = $1

        AND ls.revoked = 0

        AND ls.expires_at > $2

      LIMIT 1
      `,
    [tokenHash, Date.now()],
  );

  return result.rows[0] || null;
}

/* =====================================================
   REVOKE SESSION
   ===================================================== */

async function revokeSession(token) {
  if (typeof token !== "string" || token.length === 0) {
    return;
  }

  const tokenHash = hashSessionToken(token);

  await pool.query(
    `
    UPDATE login_sessions
    SET revoked = 1
    WHERE token_hash = $1
    `,
    [tokenHash],
  );
}

/* =====================================================
   SET SESSION COOKIE
   ===================================================== */

function setSessionCookie(res, token, expiresAt, rememberMe = false) {
  const cookieOptions = {
    httpOnly: true,
    secure: process.env.NODE_ENV === "production",
    sameSite: "lax",
    path: "/",
  };
  if (rememberMe) {
    cookieOptions.expires = new Date(expiresAt);
  }
  res.cookie(SESSION_COOKIE_NAME, token, cookieOptions);
}

/* =====================================================
   CLEAR SESSION COOKIE
   ===================================================== */

function clearSessionCookie(res) {
  res.clearCookie(SESSION_COOKIE_NAME, {
    httpOnly: true,

    secure: process.env.NODE_ENV === "production",

    sameSite: "lax",

    path: "/",
  });
}

/* =====================================================
   EXPORT
   ===================================================== */

module.exports = {
  SESSION_COOKIE_NAME,

  createSession,

  getSession,

  revokeSession,

  setSessionCookie,

  clearSessionCookie,
};
