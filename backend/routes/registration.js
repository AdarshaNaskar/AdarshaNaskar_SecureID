const express = require("express");
const crypto = require("crypto");
const { pool } = require("../database");
const { validatePassword, hashPassword } = require("../security");
const { createOtp, verifyOtp } = require("../otp");
const {
  createAuthenticatorSetup,
  createQrCode,
  verifyTotp,
  protectSecret,
} = require("../mfa");

const router = express.Router();

const REGISTRATION_TTL = 30 * 60 * 1000;

function normalizeEmail(value) {
  return String(value || "")
    .trim()
    .toLowerCase();
}

function normalizeMobile(value) {
  return String(value || "").replace(/\D/g, "");
}

function validEmail(email) {
  return /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email);
}

function validName(name) {
  return (
    typeof name === "string" &&
    name.trim().length >= 2 &&
    name.trim().length <= 100
  );
}

function validCountryCode(code) {
  return /^\+\d{1,4}$/.test(code);
}

function validMobile(mobile) {
  return /^\d{7,15}$/.test(mobile);
}

async function getRegistration(id) {
  const result = await pool.query(
    `
    SELECT r.*, u.email, u.mobile, u.country_code
    FROM registration_challenges r
    JOIN users u ON u.id = r.user_id
    WHERE r.id = $1
    `,
    [id],
  );

  return result.rows[0];
}

async function requireRegistration(req, res, next) {
  try {
    const registrationId = req.body.registrationId;

    if (!registrationId) {
      return res.status(400).json({
        success: false,
        message: "Registration session is required.",
      });
    }

    const registration = await getRegistration(registrationId);

    if (!registration || Date.now() > Number(registration.expires_at)) {
      return res.status(400).json({
        success: false,
        message: "Registration session has expired.",
      });
    }

    req.registration = registration;
    next();
  } catch (error) {
    next(error);
  }
}

router.post("/start", async (req, res, next) => {
  try {
    const { fullName, email, countryCode, mobile, password, termsAccepted } =
      req.body;

    const normalizedEmail = normalizeEmail(email);
    const normalizedMobile = normalizeMobile(mobile);

    if (!validName(fullName)) {
      return res.status(400).json({
        success: false,
        field: "fullName",
        message: "Please enter a valid full name.",
      });
    }

    if (!validEmail(normalizedEmail)) {
      return res.status(400).json({
        success: false,
        field: "email",
        message: "Please enter a valid email address.",
      });
    }

    if (!validCountryCode(countryCode) || !validMobile(normalizedMobile)) {
      return res.status(400).json({
        success: false,
        field: "mobile",
        message: "Please enter a valid mobile number.",
      });
    }

    if (!validatePassword(password)) {
      return res.status(400).json({
        success: false,
        field: "password",
        message: "Password does not meet the required criteria.",
      });
    }

    if (termsAccepted !== true) {
      return res.status(400).json({
        success: false,
        field: "terms",
        message: "Terms and Privacy Policy must be accepted.",
      });
    }

    const existingResult = await pool.query(
      `
      SELECT email, mobile
      FROM users
      WHERE LOWER(email) = LOWER($1)
         OR mobile = $2
      LIMIT 1
      `,
      [normalizedEmail, normalizedMobile],
    );

    if (existingResult.rows.length > 0) {
      // Keep the response generic to reduce account enumeration.
      return res.status(409).json({
        success: false,
        message: "Unable to create this account with the supplied details.",
      });
    }

    const passwordHash = await hashPassword(password);

    const userResult = await pool.query(
      `
      INSERT INTO users
        (full_name, email, country_code, mobile, password_hash)
      VALUES ($1, $2, $3, $4, $5)
      RETURNING id
      `,
      [
        fullName.trim(),
        normalizedEmail,
        countryCode,
        normalizedMobile,
        passwordHash,
      ],
    );

    const userId = userResult.rows[0].id;

    const registrationId = crypto.randomUUID();
    const now = Date.now();

    await pool.query(
      `
      INSERT INTO registration_challenges
        (id, user_id, step, created_at, expires_at)
      VALUES ($1, $2, 'email_verification', $3, $4)
      `,
      [registrationId, userId, now, now + REGISTRATION_TTL],
    );

    const otp = await createOtp({
      registrationId,
      channel: "email",
      purpose: "registration_email",
    });

    res.status(201).json({
      success: true,
      registrationId,
      expiresAt: otp.expiresAt,
    });
  } catch (error) {
    next(error);
  }
});

router.post("/email/resend", requireRegistration, async (req, res, next) => {
  try {
    if (req.registration.step !== "email_verification") {
      return res.status(400).json({
        success: false,
        message: "Email verification is not the current step.",
      });
    }

    const otp = await createOtp({
      registrationId: req.registration.id,
      channel: "email",
      purpose: "registration_email",
    });

    res.json({
      success: true,
      expiresAt: otp.expiresAt,
    });
  } catch (error) {
    next(error);
  }
});

router.post("/email/verify", requireRegistration, async (req, res, next) => {
  try {
    if (req.registration.step !== "email_verification") {
      return res.status(400).json({
        success: false,
        message: "Email verification is not the current step.",
      });
    }

    const otp = String(req.body.otp || "");

    if (!/^\d{6}$/.test(otp)) {
      return res.status(400).json({
        success: false,
        message: "Enter a valid 6-digit code.",
      });
    }

    const result = await verifyOtp({
      registrationId: req.registration.id,
      channel: "email",
      purpose: "registration_email",
      otp,
    });

    if (!result.ok) {
      return res.status(400).json({
        success: false,
        reason: result.reason,
        attemptsLeft: result.attemptsLeft,
      });
    }

    await pool.query(
      `
      UPDATE users
      SET email_verified = 1,
          updated_at = CURRENT_TIMESTAMP
      WHERE id = $1
      `,
      [req.registration.user_id],
    );

    await pool.query(
      `
      UPDATE registration_challenges
      SET step = 'mobile_verification'
      WHERE id = $1
      `,
      [req.registration.id],
    );

    const mobileOtp = await createOtp({
      registrationId: req.registration.id,
      channel: "sms",
      purpose: "registration_mobile",
    });

    res.json({
      success: true,
      nextStep: "mobile_verification",
      expiresAt: mobileOtp.expiresAt,
    });
  } catch (error) {
    next(error);
  }
});

router.post("/mobile/send", requireRegistration, async (req, res, next) => {
  try {
    if (req.registration.step !== "mobile_verification") {
      return res.status(400).json({
        success: false,
        message: "Mobile verification is not the current step.",
      });
    }

    const otp = await createOtp({
      registrationId: req.registration.id,
      channel: "sms",
      purpose: "registration_mobile",
    });

    res.json({
      success: true,
      expiresAt: otp.expiresAt,
    });
  } catch (error) {
    next(error);
  }
});

router.post("/mobile/resend", requireRegistration, async (req, res, next) => {
  try {
    if (req.registration.step !== "mobile_verification") {
      return res.status(400).json({
        success: false,
        message: "Mobile verification is not the current step.",
      });
    }

    const otp = await createOtp({
      registrationId: req.registration.id,
      channel: "sms",
      purpose: "registration_mobile",
    });

    res.json({
      success: true,
      expiresAt: otp.expiresAt,
    });
  } catch (error) {
    next(error);
  }
});

router.post("/mobile/verify", requireRegistration, async (req, res, next) => {
  try {
    if (req.registration.step !== "mobile_verification") {
      return res.status(400).json({
        success: false,
        message: "Mobile verification is not the current step.",
      });
    }

    const otp = String(req.body.otp || "");

    if (!/^\d{6}$/.test(otp)) {
      return res.status(400).json({
        success: false,
        message: "Enter a valid 6-digit code.",
      });
    }

    const result = await verifyOtp({
      registrationId: req.registration.id,
      channel: "sms",
      purpose: "registration_mobile",
      otp,
    });

    if (!result.ok) {
      return res.status(400).json({
        success: false,
        reason: result.reason,
        attemptsLeft: result.attemptsLeft,
      });
    }

    await pool.query(
      `
      UPDATE users
      SET mobile_verified = 1,
          updated_at = CURRENT_TIMESTAMP
      WHERE id = $1
      `,
      [req.registration.user_id],
    );

    await pool.query(
      `
      UPDATE registration_challenges
      SET step = 'mfa_selection'
      WHERE id = $1
      `,
      [req.registration.id],
    );

    res.json({
      success: true,
      nextStep: "mfa_selection",
    });
  } catch (error) {
    next(error);
  }
});

router.post("/mfa/select", requireRegistration, async (req, res, next) => {
  try {
    if (req.registration.step !== "mfa_selection") {
      return res.status(400).json({
        success: false,
        message: "MFA selection is not the current step.",
      });
    }

    const method = req.body.method;

    if (!["authenticator", "sms", "email"].includes(method)) {
      return res.status(400).json({
        success: false,
        message: "Invalid MFA method.",
      });
    }

    await pool.query(
      `
      UPDATE registration_challenges
      SET step = $1,
          mfa_method = $2
      WHERE id = $3
      `,
      [
        method === "authenticator" ? "authenticator_setup" : "mfa_verification",
        method,
        req.registration.id,
      ],
    );

    if (method === "authenticator") {
      const setup = createAuthenticatorSetup(req.registration.email);
      const qr = await createQrCode(setup.otpauth);

      await pool.query(
        `
        UPDATE users
        SET mfa_method = $1,
            mfa_secret_enc = $2,
            updated_at = CURRENT_TIMESTAMP
        WHERE id = $3
        `,
        [
          "authenticator",
          protectSecret(setup.secret),
          req.registration.user_id,
        ],
      );

      return res.json({
        success: true,
        nextStep: "authenticator_setup",
        qrDataUrl: qr,
        setupKey: setup.secret,
      });
    }

    const channel = method === "sms" ? "sms" : "email";

    const otp = await createOtp({
      registrationId: req.registration.id,
      channel,
      purpose: "mfa",
    });

    await pool.query(
      `
      UPDATE users
      SET mfa_method = $1,
          updated_at = CURRENT_TIMESTAMP
      WHERE id = $2
      `,
      [method, req.registration.user_id],
    );

    return res.json({
      success: true,
      nextStep: "mfa_verification",
      method,
      expiresAt: otp.expiresAt,
    });
  } catch (error) {
    next(error);
  }
});

router.post(
  "/mfa/authenticator/complete",
  requireRegistration,
  async (req, res, next) => {
    try {
      if (
        req.registration.step !== "authenticator_setup" ||
        req.registration.mfa_method !== "authenticator"
      ) {
        return res.status(400).json({
          success: false,
          message: "Authenticator setup is not the current step.",
        });
      }

      const userResult = await pool.query(
        `
        SELECT mfa_secret_enc
        FROM users
        WHERE id = $1
        `,
        [req.registration.user_id],
      );

      const user = userResult.rows[0];

      if (!user?.mfa_secret_enc) {
        return res.status(400).json({
          success: false,
          message: "Authenticator setup is incomplete.",
        });
      }

      /*
       * The QR code has already been generated and the
       * encrypted secret has already been stored.
       *
       * Registration is completed here without requesting
       * a TOTP code, as specified for this flow.
       */

      await pool.query(
        `
        UPDATE users
        SET mfa_enabled = 1,
            updated_at = CURRENT_TIMESTAMP
        WHERE id = $1
        `,
        [req.registration.user_id],
      );

      await pool.query(
        `
        UPDATE registration_challenges
        SET step = 'complete'
        WHERE id = $1
        `,
        [req.registration.id],
      );

      return res.json({
        success: true,
        nextStep: "success",
      });
    } catch (error) {
      next(error);
    }
  },
);

router.post(
  "/mfa/authenticator/verify",
  requireRegistration,
  async (req, res, next) => {
    try {
      if (
        req.registration.step !== "authenticator_setup" ||
        req.registration.mfa_method !== "authenticator"
      ) {
        return res.status(400).json({
          success: false,
          message: "Authenticator setup is not the current step.",
        });
      }

      const code = String(req.body.code || "");

      if (!/^\d{6}$/.test(code)) {
        return res.status(400).json({
          success: false,
          message: "Enter a valid 6-digit authenticator code.",
        });
      }

      const userResult = await pool.query(
        `
        SELECT mfa_secret_enc
        FROM users
        WHERE id = $1
        `,
        [req.registration.user_id],
      );

      const user = userResult.rows[0];

      if (!user?.mfa_secret_enc) {
        return res.status(400).json({
          success: false,
          message: "Authenticator setup is incomplete.",
        });
      }

      const { revealSecret } = require("../mfa");
      const secret = revealSecret(user.mfa_secret_enc);

      if (!(await verifyTotp(secret, code))) {
        return res.status(400).json({
          success: false,
          reason: "invalid",
        });
      }

      await pool.query(
        `
        UPDATE users
        SET mfa_enabled = 1,
            updated_at = CURRENT_TIMESTAMP
        WHERE id = $1
        `,
        [req.registration.user_id],
      );

      await pool.query(
        `
        UPDATE registration_challenges
        SET step = 'complete'
        WHERE id = $1
        `,
        [req.registration.id],
      );

      res.json({
        success: true,
        nextStep: "success",
      });
    } catch (error) {
      next(error);
    }
  },
);

router.post("/mfa/otp/resend", requireRegistration, async (req, res, next) => {
  try {
    if (
      req.registration.step !== "mfa_verification" ||
      !["sms", "email"].includes(req.registration.mfa_method)
    ) {
      return res.status(400).json({
        success: false,
        message: "MFA OTP is not the current step.",
      });
    }

    const channel = req.registration.mfa_method;

    const otp = await createOtp({
      registrationId: req.registration.id,
      channel,
      purpose: "mfa",
    });

    res.json({
      success: true,
      expiresAt: otp.expiresAt,
    });
  } catch (error) {
    next(error);
  }
});

router.post("/mfa/otp/verify", requireRegistration, async (req, res, next) => {
  try {
    if (
      req.registration.step !== "mfa_verification" ||
      !["sms", "email"].includes(req.registration.mfa_method)
    ) {
      return res.status(400).json({
        success: false,
        message: "MFA OTP verification is not the current step.",
      });
    }

    const otp = String(req.body.otp || "");

    if (!/^\d{6}$/.test(otp)) {
      return res.status(400).json({
        success: false,
        message: "Enter a valid 6-digit code.",
      });
    }

    const result = await verifyOtp({
      registrationId: req.registration.id,
      channel: req.registration.mfa_method,
      purpose: "mfa",
      otp,
    });

    if (!result.ok) {
      return res.status(400).json({
        success: false,
        reason: result.reason,
        attemptsLeft: result.attemptsLeft,
      });
    }

    await pool.query(
      `
        UPDATE users
        SET mfa_enabled = 1,
            updated_at = CURRENT_TIMESTAMP
        WHERE id = $1
        `,
      [req.registration.user_id],
    );

    await pool.query(
      `
        UPDATE registration_challenges
        SET step = 'complete'
        WHERE id = $1
        `,
      [req.registration.id],
    );

    res.json({
      success: true,
      nextStep: "success",
    });
  } catch (error) {
    next(error);
  }
});

module.exports = router;
