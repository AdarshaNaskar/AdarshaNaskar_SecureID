const express = require("express");
const crypto = require("crypto");
const rateLimit = require("express-rate-limit");

const { pool } = require("../database");
const { verifyPassword } = require("../security");
const { createLoginOtp } = require("../otp");
const router = express.Router();

/* =====================================================
   CONFIGURATION
   ===================================================== */

const LOGIN_CHALLENGE_TTL = 10 * 60 * 1000;

/* =====================================================
   RATE LIMITING
   ===================================================== */

const loginLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,

  max: 10,

  standardHeaders: true,
  legacyHeaders: false,

  message: {
    success: false,
    message: "Too many login attempts. Please try again later.",
  },

  handler: (req, res) => {
    return res.status(429).json({
      success: false,
      message: "Too many login attempts. Please try again later.",
    });
  },
});

/* =====================================================
   INPUT NORMALIZATION
   ===================================================== */

function normalizeEmail(value) {
  return String(value || "")
    .trim()
    .toLowerCase();
}

/* =====================================================
   INPUT VALIDATION
   ===================================================== */

function validEmail(email) {
  return /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email);
}

/* =====================================================
   GENERIC AUTHENTICATION ERROR
   ===================================================== */

const INVALID_CREDENTIALS_MESSAGE =
  "Invalid email or password. Please try again.";

/* =====================================================
   POST /api/login
   ===================================================== */

router.post("/", loginLimiter, async (req, res, next) => {
  try {
    const { email, password } = req.body;

    /* ---------------------------------------------
         BASIC INPUT CHECK
         --------------------------------------------- */

    const normalizedEmail = normalizeEmail(email);

    if (
      !normalizedEmail ||
      typeof password !== "string" ||
      password.length === 0
    ) {
      return res.status(401).json({
        success: false,
        message: INVALID_CREDENTIALS_MESSAGE,
      });
    }

    /* ---------------------------------------------
         EMAIL FORMAT
         --------------------------------------------- */

    if (!validEmail(normalizedEmail)) {
      return res.status(401).json({
        success: false,
        message: INVALID_CREDENTIALS_MESSAGE,
      });
    }

    /* ---------------------------------------------
         FIND USER
         --------------------------------------------- */

    /*
     * Parameterized query protects against
     * SQL injection.
     */

    const result = await pool.query(
      `
          SELECT
            id,
            email,
            password_hash,
            email_verified,
            mobile_verified,
            mfa_enabled,
            mfa_method,
            mfa_secret_enc
          FROM users
          WHERE LOWER(email) = $1
          LIMIT 1
          `,
      [normalizedEmail],
    );

    const user = result.rows[0];

    /* ---------------------------------------------
         USER DOES NOT EXIST
         --------------------------------------------- */

    if (!user) {
      return res.status(401).json({
        success: false,
        message: INVALID_CREDENTIALS_MESSAGE,
      });
    }

    /* ---------------------------------------------
         VERIFY PASSWORD
         --------------------------------------------- */

    let passwordValid = false;

    try {
      passwordValid = await verifyPassword(password, user.password_hash);
    } catch (error) {
      console.error("Password verification error:", error);

      return res.status(500).json({
        success: false,
        message: "Unable to process login right now.",
      });
    }

    /* ---------------------------------------------
         INVALID PASSWORD
         --------------------------------------------- */

    if (!passwordValid) {
      return res.status(401).json({
        success: false,
        message: INVALID_CREDENTIALS_MESSAGE,
      });
    }

    /* =================================================
         DETERMINE AVAILABLE MFA METHODS
         ================================================= */

    const availableMethods = [];

    /*
     * EMAIL
     *
     * Email was successfully verified during
     * registration.
     */

    if (Number(user.email_verified) === 1) {
      availableMethods.push("email");
    }

    /*
     * SMS
     *
     * Mobile number was successfully verified
     * during registration.
     */

    if (Number(user.mobile_verified) === 1) {
      availableMethods.push("sms");
    }

    /*
     * AUTHENTICATOR
     *
     * An encrypted authenticator secret must
     * actually exist before this option can
     * be offered.
     */

    if (user.mfa_secret_enc && String(user.mfa_secret_enc).trim().length > 0) {
      availableMethods.push("authenticator");
    }

    /* ---------------------------------------------
         MFA MUST HAVE AT LEAST ONE METHOD
         --------------------------------------------- */

    if (availableMethods.length === 0) {
      return res.status(403).json({
        success: false,
        message:
          "No valid authentication method is configured for this account.",
      });
    }

    /* =================================================
         CREATE LOGIN CHALLENGE
         ================================================= */

    const challengeId = crypto.randomBytes(32).toString("hex");

    const now = Date.now();

    const expiresAt = now + LOGIN_CHALLENGE_TTL;

    /*
     * At this point the user has only passed
     * the password stage.
     *
     * Therefore the challenge is still waiting
     * for MFA selection.
     */

    await pool.query(
      `
        INSERT INTO login_challenges
          (
            id,
            user_id,
            step,
            mfa_method,
            created_at,
            expires_at
          )
        VALUES
          (
            $1,
            $2,
            $3,
            $4,
            $5,
            $6
          )
        `,
      [challengeId, user.id, "mfa_selection", null, now, expiresAt],
    );

    /* =================================================
         SUCCESS
         ================================================= */

    return res.status(200).json({
      success: true,

      mfaRequired: true,

      challengeId,

      availableMethods,

      expiresAt,
    });
  } catch (error) {
    console.error("Login error:", error);

    next(error);
  }
});

/* =====================================================
   POST /api/login/select-mfa
   ===================================================== */

router.post("/select-mfa", async (req, res, next) => {
  try {
    const { challengeId, method } = req.body;

    /* ---------------------------------------------
       BASIC INPUT VALIDATION
       --------------------------------------------- */

    if (
      typeof challengeId !== "string" ||
      !/^[a-f0-9]{64}$/i.test(challengeId) ||
      typeof method !== "string"
    ) {
      return res.status(400).json({
        success: false,
        message: "Invalid MFA selection.",
      });
    }

    const allowedMethods = ["email", "sms", "authenticator"];

    if (!allowedMethods.includes(method)) {
      return res.status(400).json({
        success: false,
        message: "Invalid MFA method.",
      });
    }

    /* ---------------------------------------------
       FIND VALID LOGIN CHALLENGE
       --------------------------------------------- */

    const challengeResult = await pool.query(
      `
      SELECT
        lc.id,
        lc.user_id,
        lc.step,
        lc.expires_at,
        u.email_verified,
        u.mobile_verified,
        u.mfa_secret_enc
      FROM login_challenges lc
      JOIN users u
        ON u.id = lc.user_id
      WHERE lc.id = $1
        AND lc.expires_at > $2
      LIMIT 1
      `,
      [challengeId, Date.now()],
    );

    const challenge = challengeResult.rows[0];

    if (!challenge) {
      return res.status(401).json({
        success: false,
        message: "Your login session has expired. Please log in again.",
      });
    }

    /* ---------------------------------------------
       CHALLENGE STATE
       --------------------------------------------- */

    if (challenge.step !== "mfa_selection") {
      return res.status(400).json({
        success: false,
        message: "This MFA selection is no longer valid.",
      });
    }

    /* ---------------------------------------------
       DETERMINE ACTUALLY AVAILABLE METHODS
       --------------------------------------------- */

    const availableMethods = [];

    if (Number(challenge.email_verified) === 1) {
      availableMethods.push("email");
    }

    if (Number(challenge.mobile_verified) === 1) {
      availableMethods.push("sms");
    }

    if (
      challenge.mfa_secret_enc &&
      String(challenge.mfa_secret_enc).trim().length > 0
    ) {
      availableMethods.push("authenticator");
    }

    /* ---------------------------------------------
       MAKE SURE USER SELECTED A REAL METHOD
       --------------------------------------------- */

    if (!availableMethods.includes(method)) {
      return res.status(403).json({
        success: false,
        message:
          "This authentication method is not available for your account.",
      });
    }

    /* ---------------------------------------------
       SAVE MFA SELECTION
       --------------------------------------------- */

    await pool.query(
      `
      UPDATE login_challenges
      SET
        mfa_method = $1,
        step = $2
      WHERE id = $3
        AND expires_at > $4
        AND step = $5
      `,
      [
        method,
        method === "authenticator" ? "mfa_authenticator" : "mfa_otp",
        challengeId,
        Date.now(),
        "mfa_selection",
      ],
    );

    /* ---------------------------------------------
    GENERATE LOGIN OTP
    --------------------------------------------- */

    if (method === "email" || method === "sms") {
      await createLoginOtp({
        loginChallengeId: challengeId,
        channel: method,
      });
    }

    /* ---------------------------------------------
       RESPONSE
       --------------------------------------------- */

    return res.status(200).json({
      success: true,
      challengeId,
      method,
      nextStep: method === "authenticator" ? "authenticator" : "otp",
    });
  } catch (error) {
    console.error("MFA selection error:", error);

    next(error);
  }
});

module.exports = router;
