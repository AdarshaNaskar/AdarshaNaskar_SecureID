const crypto = require("crypto");
const argon2 = require("argon2");
const db = require("./database");

const OTP_TTL_MS = 5 * 60 * 1000;
const OTP_MAX_ATTEMPTS = 5;

function generateOtp() {
  return String(crypto.randomInt(0, 1000000)).padStart(6, "0");
}

async function createOtp({ registrationId, channel, purpose }) {
  const otp = generateOtp();
  const otpHash = await argon2.hash(otp, { type: argon2.argon2id });

  const id = crypto.randomUUID();
  const now = Date.now();

  db.prepare(
    `
    UPDATE otp_challenges
    SET used = 1
    WHERE registration_id = ? AND channel = ? AND purpose = ? AND used = 0
  `,
  ).run(registrationId, channel, purpose);

  db.prepare(
    `
    INSERT INTO otp_challenges
      (id, registration_id, channel, purpose, otp_hash,
       created_at, expires_at, attempts, max_attempts, used)
    VALUES (?, ?, ?, ?, ?, ?, ?, 0, ?, 0)
  `,
  ).run(
    id,
    registrationId,
    channel,
    purpose,
    otpHash,
    now,
    now + OTP_TTL_MS,
    OTP_MAX_ATTEMPTS,
  );

  // Development delivery simulation only.
  console.log(`[SecureID DEV DELIVERY] ${channel}/${purpose}: ${otp}`);

  return { challengeId: id, expiresAt: now + OTP_TTL_MS };
}

async function verifyOtp({ registrationId, channel, purpose, otp }) {
  const row = db
    .prepare(
      `
    SELECT *
    FROM otp_challenges
    WHERE registration_id = ?
      AND channel = ?
      AND purpose = ?
      AND used = 0
    ORDER BY created_at DESC
    LIMIT 1
  `,
    )
    .get(registrationId, channel, purpose);

  if (!row) return { ok: false, reason: "invalid" };

  if (Date.now() > row.expires_at) {
    db.prepare("UPDATE otp_challenges SET used = 1 WHERE id = ?").run(row.id);
    return { ok: false, reason: "expired" };
  }

  if (row.attempts >= row.max_attempts) {
    db.prepare("UPDATE otp_challenges SET used = 1 WHERE id = ?").run(row.id);
    return { ok: false, reason: "locked" };
  }

  const correct = await argon2.verify(row.otp_hash, otp);

  if (!correct) {
    const attempts = row.attempts + 1;
    db.prepare("UPDATE otp_challenges SET attempts = ? WHERE id = ?").run(
      attempts,
      row.id,
    );

    if (attempts >= row.max_attempts) {
      db.prepare("UPDATE otp_challenges SET used = 1 WHERE id = ?").run(row.id);
      return { ok: false, reason: "locked" };
    }

    return {
      ok: false,
      reason: "invalid",
      attemptsLeft: row.max_attempts - attempts,
    };
  }

  db.prepare("UPDATE otp_challenges SET used = 1 WHERE id = ?").run(row.id);
  return { ok: true };
}

module.exports = {
  OTP_TTL_MS,
  OTP_MAX_ATTEMPTS,
  createOtp,
  verifyOtp,
};
