const crypto = require("crypto");
const argon2 = require("argon2");
const { pool } = require("./database");

const OTP_TTL_MS = 5 * 60 * 1000;
const OTP_MAX_ATTEMPTS = 5;

function generateOtp() {
  return String(crypto.randomInt(0, 1000000)).padStart(6, "0");
}

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

    // Invalidate any previous unused OTP for the same purpose.
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

    // Create the new OTP challenge.
    await client.query(
      `
      INSERT INTO otp_challenges
        (id, registration_id, channel, purpose, otp_hash,
         created_at, expires_at, attempts, max_attempts, used)
      VALUES ($1, $2, $3, $4, $5, $6, $7, 0, $8, 0)
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

  // Development delivery simulation only.
  console.log(`[SecureID DEV DELIVERY] ${channel}/${purpose}: ${otp}`);

  return {
    challengeId: id,
    expiresAt,
  };
}

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

  if (Date.now() > Number(row.expires_at)) {
    await pool.query("UPDATE otp_challenges SET used = 1 WHERE id = $1", [
      row.id,
    ]);

    return {
      ok: false,
      reason: "expired",
    };
  }

  if (row.attempts >= row.max_attempts) {
    await pool.query("UPDATE otp_challenges SET used = 1 WHERE id = $1", [
      row.id,
    ]);

    return {
      ok: false,
      reason: "locked",
    };
  }

  const correct = await argon2.verify(row.otp_hash, otp);

  if (!correct) {
    const attempts = row.attempts + 1;

    await pool.query("UPDATE otp_challenges SET attempts = $1 WHERE id = $2", [
      attempts,
      row.id,
    ]);

    if (attempts >= row.max_attempts) {
      await pool.query("UPDATE otp_challenges SET used = 1 WHERE id = $1", [
        row.id,
      ]);

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

  await pool.query("UPDATE otp_challenges SET used = 1 WHERE id = $1", [
    row.id,
  ]);

  return {
    ok: true,
  };
}

module.exports = {
  OTP_TTL_MS,
  OTP_MAX_ATTEMPTS,
  createOtp,
  verifyOtp,
};
