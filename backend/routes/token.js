const express = require("express");
const jwt = require("jsonwebtoken");

const { requireAuth } = require("../middleware/requireAuth");

const router = express.Router();

const JWT_SECRET = process.env.JWT_SECRET;

if (!JWT_SECRET) {
  throw new Error("JWT_SECRET is not configured.");
}

/* =====================================================
   POST /api/token
   Issue a short-lived JWT
   ===================================================== */

router.post("/token", requireAuth, (req, res) => {
  try {
    const token = jwt.sign(
      {
        sub: String(req.user.id),
        email: req.user.email,
      },
      JWT_SECRET,
      {
        expiresIn: "15m",
        issuer: "secureid",
      },
    );

    return res.status(200).json({
      success: true,
      token,
      tokenType: "Bearer",
      expiresIn: 900,
    });
  } catch (error) {
    console.error("JWT creation error:", error);

    return res.status(500).json({
      success: false,
      message: "Unable to issue token.",
    });
  }
});

/* =====================================================
   GET /api/protected
   Validate JWT before allowing access
   ===================================================== */

router.get("/protected", (req, res) => {
  try {
    const authorization = req.headers.authorization || "";

    if (!authorization.startsWith("Bearer ")) {
      return res.status(401).json({
        success: false,
        message: "Bearer token required.",
      });
    }

    const token = authorization.slice(7).trim();

    if (!token) {
      return res.status(401).json({
        success: false,
        message: "Bearer token required.",
      });
    }

    const decoded = jwt.verify(token, JWT_SECRET, {
      issuer: "secureid",
    });

    return res.status(200).json({
      success: true,
      message: "Protected API access granted.",
      user: {
        id: decoded.sub,
        email: decoded.email,
      },
    });
  } catch (error) {
    return res.status(401).json({
      success: false,
      message: "Invalid or expired JWT.",
    });
  }
});

module.exports = router;
