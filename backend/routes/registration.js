const express = require("express");
const crypto = require("crypto");
const db = require("../database");
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

function getRegistration(id) {
  return db
    .prepare(
      `
    SELECT r.*, u.email, u.mobile, u.country_code
    FROM registration_challenges r
    JOIN users u ON u.id = r.user_id
    WHERE r.id = ?
  `,
    )
    .get(id);
}

function requireRegistration(req, res, next) {
  const registrationId = req.body.registrationId;

  if (!registrationId) {
    return res.status(400).json({
      success: false,
      message: "Registration session is required.",
    });
  }

  const registration = getRegistration(registrationId);

  if (!registration || Date.now() > registration.expires_at) {
    return res.status(400).json({
      success: false,
      message: "Registration session has expired.",
    });
  }

  req.registration = registration;
  next();
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

    const existing = db
      .prepare(
        `
      SELECT email, mobile
      FROM users
      WHERE email = ? OR mobile = ?
      LIMIT 1
    `,
      )
      .get(normalizedEmail, normalizedMobile);

    if (existing) {
      // Keep the response generic to reduce account enumeration.
      return res.status(409).json({
        success: false,
        message: "Unable to create this account with the supplied details.",
      });
    }

    const passwordHash = await hashPassword(password);
    const userInsert = db.prepare(`
      INSERT INTO users
        (full_name, email, country_code, mobile, password_hash)
      VALUES (?, ?, ?, ?, ?)
    `);

    const user = userInsert.run(
      fullName.trim(),
      normalizedEmail,
      countryCode,
      normalizedMobile,
      passwordHash,
    );

    const registrationId = crypto.randomUUID();
    const now = Date.now();

    db.prepare(
      `
      INSERT INTO registration_challenges
        (id, user_id, step, created_at, expires_at)
      VALUES (?, ?, 'email_verification', ?, ?)
    `,
    ).run(registrationId, user.lastInsertRowid, now, now + REGISTRATION_TTL);

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

    db.prepare(
      "UPDATE users SET email_verified = 1, updated_at = CURRENT_TIMESTAMP WHERE id = ?",
    ).run(req.registration.user_id);

    db.prepare(
      `
      UPDATE registration_challenges
      SET step = 'mobile_verification'
      WHERE id = ?
    `,
    ).run(req.registration.id);

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

    db.prepare(
      "UPDATE users SET mobile_verified = 1, updated_at = CURRENT_TIMESTAMP WHERE id = ?",
    ).run(req.registration.user_id);

    db.prepare(
      `
      UPDATE registration_challenges
      SET step = 'mfa_selection'
      WHERE id = ?
    `,
    ).run(req.registration.id);

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

    db.prepare(
      `
      UPDATE registration_challenges
      SET step = ?, mfa_method = ?
      WHERE id = ?
    `,
    ).run(
      method === "authenticator" ? "authenticator_setup" : "mfa_verification",
      method,
      req.registration.id,
    );

    if (method === "authenticator") {
      const setup = createAuthenticatorSetup(req.registration.email);
      const qr = await createQrCode(setup.otpauth);

      db.prepare(
        `
        UPDATE users
        SET mfa_method = ?, mfa_secret_enc = ?, updated_at = CURRENT_TIMESTAMP
        WHERE id = ?
      `,
      ).run(
        "authenticator",
        protectSecret(setup.secret),
        req.registration.user_id,
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

    db.prepare(
      `
      UPDATE users
      SET mfa_method = ?, updated_at = CURRENT_TIMESTAMP
      WHERE id = ?
    `,
    ).run(method, req.registration.user_id);

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

      const user = db
        .prepare(
          `
          SELECT mfa_secret_enc
          FROM users
          WHERE id = ?
          `,
        )
        .get(req.registration.user_id);

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
      db.prepare(
        `
        UPDATE users
        SET mfa_enabled = 1,
            updated_at = CURRENT_TIMESTAMP
        WHERE id = ?
        `,
      ).run(req.registration.user_id);

      db.prepare(
        `
        UPDATE registration_challenges
        SET step = 'complete'
        WHERE id = ?
        `,
      ).run(req.registration.id);

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

      const user = db
        .prepare(
          `
      SELECT mfa_secret_enc
      FROM users
      WHERE id = ?
    `,
        )
        .get(req.registration.user_id);

      const { revealSecret } = require("../mfa");
      const secret = revealSecret(user.mfa_secret_enc);

      if (!(await verifyTotp(secret, code))) {
        return res.status(400).json({
          success: false,
          reason: "invalid",
        });
      }

      db.prepare(
        `
      UPDATE users
      SET mfa_enabled = 1, updated_at = CURRENT_TIMESTAMP
      WHERE id = ?
    `,
      ).run(req.registration.user_id);

      db.prepare(
        `
      UPDATE registration_challenges
      SET step = 'complete'
      WHERE id = ?
    `,
      ).run(req.registration.id);

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

    db.prepare(
      `
      UPDATE users
      SET mfa_enabled = 1, updated_at = CURRENT_TIMESTAMP
      WHERE id = ?
    `,
    ).run(req.registration.user_id);

    db.prepare(
      `
      UPDATE registration_challenges
      SET step = 'complete'
      WHERE id = ?
    `,
    ).run(req.registration.id);

    res.json({
      success: true,
      nextStep: "success",
    });
  } catch (error) {
    next(error);
  }
});

module.exports = router;
