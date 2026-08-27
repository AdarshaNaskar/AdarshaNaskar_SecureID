const crypto = require("crypto");
const argon2 = require("argon2");
const { pool } = require("./database");

/* =====================================================
   OTP CONFIGURATION
   ===================================================== */

const OTP_TTL_MS = 5 * 60 * 1000;

// Registration OTP limit
const OTP_MAX_ATTEMPTS = 5;

// Login OTP limit
const LOGIN_OTP_MAX_ATTEMPTS = 3;

/* =====================================================
   GENERATE OTP
   ===================================================== */

function generateOtp() {
  return String(crypto.randomInt(0, 1000000)).padStart(6, "0");
}

/* =====================================================
   REGISTRATION OTP
   ===================================================== */

async function createOtp({ registrationId, channel, purpose }) {
  const otp = generateOtp();

  const otpHash = await argon2.hash(otp, {
    type: argon2.argon2id,
  });

  const id = crypto.randomUUID();

  const now = Date.now();

  const expiresAt = now + OTP_TTL_MS;

  const client = await pool.connect();

  try {
    await client.query("BEGIN");

    /*
     * Invalidate previous unused
     * registration OTP.
     */

    await client.query(
      `
      UPDATE otp_challenges
      SET used = 1
      WHERE registration_id = $1
        AND channel = $2
        AND purpose = $3
        AND used = 0
      `,
      [registrationId, channel, purpose],
    );

    /*
     * Create new registration OTP.
     */

    await client.query(
      `
      INSERT INTO otp_challenges
        (
          id,
          registration_id,
          channel,
          purpose,
          otp_hash,
          created_at,
          expires_at,
          attempts,
          max_attempts,
          used
        )
      VALUES
        (
          $1,
          $2,
          $3,
          $4,
          $5,
          $6,
          $7,
          0,
          $8,
          0
        )
      `,
      [
        id,
        registrationId,
        channel,
        purpose,
        otpHash,
        now,
        expiresAt,
        OTP_MAX_ATTEMPTS,
      ],
    );

    await client.query("COMMIT");
  } catch (error) {
    await client.query("ROLLBACK");

    throw error;
  } finally {
    client.release();
  }

  /*
   * Development delivery simulation only.
   *
   * Never return the OTP to the browser.
   */

  console.log(`[SecureID DEV DELIVERY] ${channel}/${purpose}: ${otp}`);

  return {
    challengeId: id,
    expiresAt,
  };
}

/* =====================================================
   VERIFY REGISTRATION OTP
   ===================================================== */

async function verifyOtp({ registrationId, channel, purpose, otp }) {
  const result = await pool.query(
    `
      SELECT *
      FROM otp_challenges
      WHERE registration_id = $1
        AND channel = $2
        AND purpose = $3
        AND used = 0
      ORDER BY created_at DESC
      LIMIT 1
      `,
    [registrationId, channel, purpose],
  );

  const row = result.rows[0];

  if (!row) {
    return {
      ok: false,
      reason: "invalid",
    };
  }

  /* ---------------------------------------------
     EXPIRY
     --------------------------------------------- */

  if (Date.now() > Number(row.expires_at)) {
    await pool.query(
      `
      UPDATE otp_challenges
      SET used = 1
      WHERE id = $1
      `,
      [row.id],
    );

    return {
      ok: false,
      reason: "expired",
    };
  }

  /* ---------------------------------------------
     ATTEMPT LIMIT
     --------------------------------------------- */

  if (row.attempts >= row.max_attempts) {
    await pool.query(
      `
      UPDATE otp_challenges
      SET used = 1
      WHERE id = $1
      `,
      [row.id],
    );

    return {
      ok: false,
      reason: "locked",
    };
  }

  /* ---------------------------------------------
     VERIFY HASH
     --------------------------------------------- */

  const correct = await argon2.verify(row.otp_hash, otp);

  if (!correct) {
    const attempts = row.attempts + 1;

    await pool.query(
      `
      UPDATE otp_challenges
      SET attempts = $1
      WHERE id = $2
      `,
      [attempts, row.id],
    );

    if (attempts >= row.max_attempts) {
      await pool.query(
        `
        UPDATE otp_challenges
        SET used = 1
        WHERE id = $1
        `,
        [row.id],
      );

      return {
        ok: false,
        reason: "locked",
      };
    }

    return {
      ok: false,
      reason: "invalid",
      attemptsLeft: row.max_attempts - attempts,
    };
  }

  /* ---------------------------------------------
     SUCCESS
     --------------------------------------------- */

  await pool.query(
    `
    UPDATE otp_challenges
    SET used = 1
    WHERE id = $1
    `,
    [row.id],
  );

  return {
    ok: true,
  };
}

/* =====================================================
   LOGIN OTP
   ===================================================== */

async function createLoginOtp({ loginChallengeId, channel }) {
  const allowedChannels = ["email", "sms"];

  if (!allowedChannels.includes(channel)) {
    throw new Error("Invalid login OTP channel.");
  }

  const now = Date.now();

  /* ---------------------------------------------
     VERIFY LOGIN CHALLENGE
     --------------------------------------------- */

  const challengeResult = await pool.query(
    `
      SELECT
        id,
        user_id,
        step,
        expires_at
      FROM login_challenges
      WHERE id = $1
        AND expires_at > $2
      LIMIT 1
      `,
    [loginChallengeId, now],
  );

  const challenge = challengeResult.rows[0];

  if (!challenge) {
    throw new Error("Invalid or expired login challenge.");
  }

  if (challenge.step !== "mfa_otp") {
    throw new Error("Login challenge is not ready for OTP.");
  }

  const otp = generateOtp();

  const otpHash = await argon2.hash(otp, {
    type: argon2.argon2id,
  });

  const id = crypto.randomUUID();

  const expiresAt = now + OTP_TTL_MS;

  const client = await pool.connect();

  try {
    await client.query("BEGIN");

    /* ---------------------------------------------
       INVALIDATE PREVIOUS LOGIN OTP
       --------------------------------------------- */

    await client.query(
      `
      UPDATE login_otp_challenges
      SET used = 1
      WHERE login_challenge_id = $1
        AND channel = $2
        AND used = 0
      `,
      [loginChallengeId, channel],
    );

    /* ---------------------------------------------
       CREATE NEW LOGIN OTP
       --------------------------------------------- */

    await client.query(
      `
      INSERT INTO login_otp_challenges
        (
          id,
          login_challenge_id,
          channel,
          otp_hash,
          created_at,
          expires_at,
          attempts,
          max_attempts,
          used
        )
      VALUES
        (
          $1,
          $2,
          $3,
          $4,
          $5,
          $6,
          0,
          $7,
          0
        )
      `,
      [
        id,
        loginChallengeId,
        channel,
        otpHash,
        now,
        expiresAt,
        LOGIN_OTP_MAX_ATTEMPTS,
      ],
    );

    await client.query("COMMIT");
  } catch (error) {
    await client.query("ROLLBACK");

    throw error;
  } finally {
    client.release();
  }

  /*
   * Development delivery simulation only.
   *
   * The OTP is printed in the backend terminal
   * and is NOT returned to the browser.
   */

  console.log(`[SecureID DEV LOGIN DELIVERY] ${channel}: ${otp}`);

  return {
    challengeId: id,
    expiresAt,
  };
}

/* =====================================================
   VERIFY LOGIN OTP
   ===================================================== */

async function verifyLoginOtp({ loginChallengeId, channel, otp }) {
  const allowedChannels = ["email", "sms"];

  if (!allowedChannels.includes(channel)) {
    return {
      ok: false,
      reason: "invalid",
    };
  }

  if (typeof otp !== "string" || !/^\d{6}$/.test(otp)) {
    return {
      ok: false,
      reason: "invalid",
    };
  }

  /* ---------------------------------------------
     VERIFY LOGIN CHALLENGE
     --------------------------------------------- */

  const challengeResult = await pool.query(
    `
      SELECT
        id,
        step,
        mfa_method,
        expires_at
      FROM login_challenges
      WHERE id = $1
        AND expires_at > $2
      LIMIT 1
      `,
    [loginChallengeId, Date.now()],
  );

  const challenge = challengeResult.rows[0];

  if (!challenge) {
    return {
      ok: false,
      reason: "expired",
    };
  }

  /* ---------------------------------------------
     MAKE SURE CORRECT MFA METHOD WAS SELECTED
     --------------------------------------------- */

  if (challenge.step !== "mfa_otp" || challenge.mfa_method !== channel) {
    return {
      ok: false,
      reason: "invalid",
    };
  }

  /* ---------------------------------------------
     GET ACTIVE OTP
     --------------------------------------------- */

  const result = await pool.query(
    `
      SELECT *
      FROM login_otp_challenges
      WHERE login_challenge_id = $1
        AND channel = $2
        AND used = 0
      ORDER BY created_at DESC
      LIMIT 1
      `,
    [loginChallengeId, channel],
  );

  const row = result.rows[0];

  if (!row) {
    return {
      ok: false,
      reason: "invalid",
    };
  }

  /* ---------------------------------------------
     EXPIRY
     --------------------------------------------- */

  if (Date.now() > Number(row.expires_at)) {
    await pool.query(
      `
      UPDATE login_otp_challenges
      SET used = 1
      WHERE id = $1
      `,
      [row.id],
    );

    return {
      ok: false,
      reason: "expired",
    };
  }

  /* ---------------------------------------------
     THREE ATTEMPT LIMIT
     --------------------------------------------- */

  if (row.attempts >= row.max_attempts) {
    await pool.query(
      `
      UPDATE login_otp_challenges
      SET used = 1
      WHERE id = $1
      `,
      [row.id],
    );

    return {
      ok: false,
      reason: "locked",
    };
  }

  /* ---------------------------------------------
     VERIFY OTP HASH
     --------------------------------------------- */

  const correct = await argon2.verify(row.otp_hash, otp);

  if (!correct) {
    const attempts = row.attempts + 1;

    await pool.query(
      `
      UPDATE login_otp_challenges
      SET attempts = $1
      WHERE id = $2
      `,
      [attempts, row.id],
    );

    if (attempts >= row.max_attempts) {
      await pool.query(
        `
        UPDATE login_otp_challenges
        SET used = 1
        WHERE id = $1
        `,
        [row.id],
      );

      return {
        ok: false,
        reason: "locked",
      };
    }

    return {
      ok: false,
      reason: "invalid",
      attemptsLeft: row.max_attempts - attempts,
    };
  }

  /* ---------------------------------------------
     OTP SUCCESS
     --------------------------------------------- */

  await pool.query(
    `
    UPDATE login_otp_challenges
    SET used = 1
    WHERE id = $1
    `,
    [row.id],
  );

  return {
    ok: true,
  };
}

/* =====================================================
   EXPORTS
   ===================================================== */

module.exports = {
  OTP_TTL_MS,
  OTP_MAX_ATTEMPTS,
  LOGIN_OTP_MAX_ATTEMPTS,

  createOtp,
  verifyOtp,

  createLoginOtp,
  verifyLoginOtp,
};
