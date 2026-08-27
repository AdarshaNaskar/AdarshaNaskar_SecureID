const { createSession, setSessionCookie } = require("../session");

const express = require("express");

const { verifyLoginOtp, createLoginOtp } = require("../otp");

const { pool } = require("../database");

const router = express.Router();

/* =====================================================
   POST /api/verify-login-otp
   ===================================================== */

router.post("/verify-login-otp", async (req, res, next) => {
  try {
    const { challengeId, otp, rememberMe } = req.body;

    /* ---------------------------------------------
       BASIC INPUT VALIDATION
       --------------------------------------------- */

    if (
      typeof challengeId !== "string" ||
      !/^[a-f0-9]{64}$/i.test(challengeId)
    ) {
      return res.status(400).json({
        success: false,
        message: "Invalid login challenge.",
      });
    }

    if (typeof otp !== "string" || !/^\d{6}$/.test(otp)) {
      return res.status(400).json({
        success: false,
        message: "Enter a valid 6-digit OTP.",
      });
    }

    /* ---------------------------------------------
       FIND LOGIN CHALLENGE
       --------------------------------------------- */

    const challengeResult = await pool.query(
      `
      SELECT
        id,
        user_id,
        step,
        mfa_method,
        expires_at
      FROM login_challenges
      WHERE id = $1
        AND expires_at > $2
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
       MFA METHOD CHECK
       --------------------------------------------- */

    if (
      challenge.step !== "mfa_otp" ||
      !["email", "sms"].includes(challenge.mfa_method)
    ) {
      return res.status(400).json({
        success: false,
        message: "This login challenge is not ready for OTP verification.",
      });
    }

    /* ---------------------------------------------
       VERIFY LOGIN OTP
       --------------------------------------------- */

    const result = await verifyLoginOtp({
      loginChallengeId: challengeId,

      channel: challenge.mfa_method,

      otp,
    });

    /* ---------------------------------------------
       SUCCESS
       --------------------------------------------- */

    if (result.ok) {
      /* ---------------------------------------------
     CREATE AUTHENTICATED SESSION
     --------------------------------------------- */

      const shouldRemember = rememberMe === true;

      const session = await createSession(challenge.user_id, shouldRemember);

      /* ---------------------------------------------
     MARK LOGIN CHALLENGE COMPLETE
     --------------------------------------------- */

      await pool.query(
        `
    UPDATE login_challenges
    SET step = 'complete'
    WHERE id = $1
    `,
        [challengeId],
      );

      /* ---------------------------------------------
     SET SESSION COOKIE
     --------------------------------------------- */

      setSessionCookie(res, session.token, session.expiresAt, shouldRemember);

      /* ---------------------------------------------
     SUCCESS
     --------------------------------------------- */

      return res.status(200).json({
        success: true,
        authenticated: true,
        message: "Login verification successful.",
      });
    }

    /* ---------------------------------------------
       EXPIRED OTP
       --------------------------------------------- */

    if (result.reason === "expired") {
      return res.status(401).json({
        success: false,
        reason: "expired",
        message: "This OTP has expired. Please request a new one.",
      });
    }

    /* ---------------------------------------------
       THREE ATTEMPTS USED
       --------------------------------------------- */

    if (result.reason === "locked") {
      return res.status(429).json({
        success: false,
        reason: "locked",
        attemptsLeft: 0,
        message: "You have used all 3 attempts. Please resend a new OTP.",
      });
    }

    /* ---------------------------------------------
       WRONG OTP
       --------------------------------------------- */

    return res.status(401).json({
      success: false,
      reason: "invalid",
      attemptsLeft: result.attemptsLeft ?? 0,

      message:
        result.attemptsLeft === 1
          ? "Incorrect OTP. You have 1 attempt left."
          : `Incorrect OTP. You have ${result.attemptsLeft} attempts left.`,
    });
  } catch (error) {
    console.error("Login OTP verification error:", error);

    next(error);
  }
});

/* =====================================================
   POST /api/login/resend-otp
   ===================================================== */

router.post("/login/resend-otp", async (req, res, next) => {
  try {
    const { challengeId } = req.body;

    /* ---------------------------------------------
       BASIC INPUT VALIDATION
       --------------------------------------------- */

    if (
      typeof challengeId !== "string" ||
      !/^[a-f0-9]{64}$/i.test(challengeId)
    ) {
      return res.status(400).json({
        success: false,
        message: "Invalid login challenge.",
      });
    }

    /* ---------------------------------------------
       FIND LOGIN CHALLENGE
       --------------------------------------------- */

    const challengeResult = await pool.query(
      `
      SELECT
        id,
        user_id,
        step,
        mfa_method,
        expires_at
      FROM login_challenges
      WHERE id = $1
      LIMIT 1
      `,
      [challengeId],
    );

    const challenge = challengeResult.rows[0];

    if (!challenge) {
      return res.status(401).json({
        success: false,
        message: "Your login session is invalid. Please log in again.",
      });
    }

    /* ---------------------------------------------
       CHECK LOGIN SESSION EXPIRY
       --------------------------------------------- */

    if (Date.now() > Number(challenge.expires_at)) {
      return res.status(401).json({
        success: false,
        message: "Your login session has expired. Please log in again.",
      });
    }

    /* ---------------------------------------------
       ONLY EMAIL / SMS CAN USE OTP RESEND
       --------------------------------------------- */

    if (
      challenge.step !== "mfa_otp" ||
      !["email", "sms"].includes(challenge.mfa_method)
    ) {
      return res.status(400).json({
        success: false,
        message: "OTP resend is not available for this authentication method.",
      });
    }

    /* ---------------------------------------------
       GENERATE NEW OTP
       --------------------------------------------- */

    const newOtp = await createLoginOtp({
      loginChallengeId: challengeId,

      channel: challenge.mfa_method,
    });

    /* ---------------------------------------------
       RESPONSE
       --------------------------------------------- */

    return res.status(200).json({
      success: true,
      message: "A new verification code has been generated.",
      expiresAt: newOtp.expiresAt,
    });
  } catch (error) {
    console.error("Login OTP resend error:", error);

    next(error);
  }
});

/* =====================================================
   EXPORT
   ===================================================== */

module.exports = router;
