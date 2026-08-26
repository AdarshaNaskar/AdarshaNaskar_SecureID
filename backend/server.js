require("dotenv").config();

const express = require("express");
const path = require("path");
const helmet = require("helmet");
const rateLimit = require("express-rate-limit");

const registrationRoutes = require("./routes/registration");

if (!process.env.SESSION_SECRET) {
  throw new Error("SESSION_SECRET is required");
}

const app = express();
const PORT = Number(process.env.PORT || 3000);

app.disable("x-powered-by");

/*
 * Security headers
 */
app.use(
  helmet({
    contentSecurityPolicy: false,
  }),
);

/*
 * Request body limits
 */
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

/*
 * General API rate limit
 */
const generalLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  limit: 300,
  standardHeaders: "draft-8",
  legacyHeaders: false,
});

/*
 * Registration rate limit
 *
 * This is intentionally stricter.
 */
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

app.use(generalLimiter);

/*
 * Registration API
 */
app.use("/api/registration", registrationLimiter, registrationRoutes);

/*
 * Serve frontend
 */
const frontendPath = path.join(__dirname, "..", "frontend");

app.use(express.static(frontendPath));

app.get("/", (req, res) => {
  res.sendFile(path.join(frontendPath, "index.html"));
});

/*
 * Unknown API route
 */
app.use("/api", (req, res) => {
  res.status(404).json({
    success: false,
    message: "API endpoint not found.",
  });
});

app.use((err, req, res, next) => {
  console.error("[SecureID SERVER]", err.message);

  res.status(500).json({
    success: false,
    message: "Something went wrong. Please try again.",
  });
});

app.listen(PORT, () => {
  console.log(`SecureID server running at http://localhost:${PORT}`);
});

module.exports = app;
