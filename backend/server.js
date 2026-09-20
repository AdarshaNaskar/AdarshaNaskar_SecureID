require("dotenv").config();

const { requireAuth } = require("./middleware/requireAuth");
const express = require("express");
const { initializeDatabase } = require("./database");
const path = require("path");
const helmet = require("helmet");
const rateLimit = require("express-rate-limit");

const registrationRoutes = require("./routes/registration");
const loginRoutes = require("./routes/login.js");
const loginOtpRoutes = require("./routes/loginOtp.js");
const tokenRoutes = require("./routes/token");

const {
  SESSION_COOKIE_NAME,
  revokeSession,
  clearSessionCookie,
} = require("./session");

/* =====================================================
   ENVIRONMENT
   ===================================================== */

if (!process.env.SESSION_SECRET) {
  throw new Error("SESSION_SECRET is required");
}

/* =====================================================
   APP
   ===================================================== */

const app = express();

// Vercel runs Express behind a proxy.
app.set("trust proxy", 1);

const PORT = Number(process.env.PORT || 3000);

app.disable("x-powered-by");

/* =====================================================
   SECURITY HEADERS
   ===================================================== */

app.use(
  helmet({
    contentSecurityPolicy: false,
  }),
);

/* =====================================================
   REQUEST BODY LIMITS
   ===================================================== */

app.use(
  express.json({
    limit: "10kb",
  }),
);

app.use(
  express.urlencoded({
    extended: false,
    limit: "10kb",
  }),
);

/* =====================================================
   GENERAL API RATE LIMIT
   ===================================================== */

const generalLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  limit: 300,
  standardHeaders: "draft-8",
  legacyHeaders: false,
});

/* =====================================================
   REGISTRATION RATE LIMIT
   ===================================================== */

const registrationLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  limit: 15,
  standardHeaders: "draft-8",
  legacyHeaders: false,
  message: {
    success: false,
    message: "Too many requests. Please try again later.",
  },
});

/* =====================================================
   GLOBAL API LIMIT & DB INITIALIZATION
   ===================================================== */

app.use(generalLimiter);

app.use(async (req, res, next) => {
  try {
    await initializeDatabase();
    next();
  } catch (err) {
    next(err);
  }
});

/* =====================================================
   REGISTRATION API
   ===================================================== */

app.use("/api/registration", registrationLimiter, registrationRoutes);

/* =====================================================
   LOGIN API
   ===================================================== */

app.use("/api/login", loginRoutes);

app.use("/api", loginOtpRoutes);

app.use("/api", tokenRoutes);

app.get("/api/me", requireAuth, (req, res) => {
  return res.status(200).json({
    success: true,
    user: {
      id: req.user.id,
      email: req.user.email,
      fullName: req.user.fullName,
    },
  });
});

app.post("/api/logout", async (req, res, next) => {
  try {
    const cookieHeader = req.headers.cookie || "";

    let sessionToken = null;

    const cookies = cookieHeader.split(";");

    for (const cookie of cookies) {
      const [name, ...valueParts] = cookie.trim().split("=");

      if (name === SESSION_COOKIE_NAME) {
        sessionToken = decodeURIComponent(valueParts.join("="));

        break;
      }
    }

    /* ---------------------------------------------
       REVOKE SESSION
       --------------------------------------------- */

    if (sessionToken) {
      await revokeSession(sessionToken);
    }

    /* ---------------------------------------------
       CLEAR COOKIE
       --------------------------------------------- */

    clearSessionCookie(res);

    /* ---------------------------------------------
       SUCCESS
       --------------------------------------------- */

    return res.status(200).json({
      success: true,
      message: "Logged out successfully.",
    });
  } catch (error) {
    console.error("Logout error:", error);

    next(error);
  }
});

/* =====================================================
   FRONTEND
   ===================================================== */

const frontendPath = path.join(__dirname, "..", "frontend");

app.use(express.static(frontendPath));

app.get("/", (req, res) => {
  res.sendFile(path.join(frontendPath, "index.html"));
});

/* =====================================================
   UNKNOWN API ROUTE
   ===================================================== */

app.use("/api", (req, res) => {
  res.status(404).json({
    success: false,
    message: "API endpoint not found.",
  });
});

/* =====================================================
   ERROR HANDLER
   ===================================================== */

app.use((err, req, res, next) => {
  console.error("[SecureID SERVER]", err.message);

  res.status(500).json({
    success: false,
    message: "Something went wrong. Please try again.",
  });
});

/* =====================================================
   START SERVER
   ===================================================== */

if (require.main === module) {
  initializeDatabase()
    .then(() => {
      console.log("Database initialized successfully.");

      app.listen(PORT, () => {
        console.log(`SecureID server running at http://localhost:${PORT}`);
      });
    })
    .catch((error) => {
      console.error("Database initialization failed:", error);
    });
}

module.exports = app;
