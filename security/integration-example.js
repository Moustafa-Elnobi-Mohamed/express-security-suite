/**
 * ================================================================
 *  INTEGRATION EXAMPLE — server.js / app.js  (v3.0)
 *  Wire the complete security suite into your Express app.
 *
 *  REQUIRED packages (run once):
 *  npm install helmet express-rate-limit express-slow-down \
 *              express-mongo-sanitize xss-clean hpp cors \
 *              winston validator nodemailer
 *
 *  OPTIONAL:
 *  npm install winston-daily-rotate-file
 * ================================================================
 */

"use strict";

require("dotenv").config();
const express = require("express");
const path    = require("path");

const {
  applySecurityMiddleware,
  registerHoneypots,
  authLimiter,
  createLimiter,
} = require("./security/security-middleware");

const healthRoutes = require("./security/health-routes");

const app = express();

// ── Step 1: Parse bodies with strict size limits
app.use(express.json({ limit: "10kb" }));
app.use(express.urlencoded({ extended: true, limit: "10kb" }));

// ── Step 2: Trust proxy (required for correct IP behind Hostinger/Nginx)
app.set("trust proxy", 1);

// ── Step 3: Apply full security stack
applySecurityMiddleware(app);

// ── Step 4: Register honeypot traps (BEFORE real routes)
//    Any hit from a real attacker is auto-logged, alerted, and banned
registerHoneypots(app);

// ── Step 5: Health + security status routes
app.use("/", healthRoutes);

// ── Step 6: Auth-specific rate limiting on sensitive routes
app.use("/api/auth/login",           authLimiter);
app.use("/api/auth/register",        authLimiter);
app.use("/api/auth/reset-password",  authLimiter);
app.use("/api/auth/forgot-password", authLimiter);

// ── Step 7: Per-route custom limiters (NEW v3.0)
//    Example: expensive AI/search endpoints get their own tight window
app.use("/api/search", createLimiter({ max: 20, windowMs: 60 * 1000, message: "Search rate limit exceeded." }));
app.use("/api/export", createLimiter({ max: 5,  windowMs: 60 * 1000, message: "Export rate limit exceeded." }));

// ── Step 8: Your application routes
// app.use("/api/users",    require("./routes/users"));
// app.use("/api/products", require("./routes/products"));

// ── Step 9: Serve React build in production
if (process.env.NODE_ENV === "production") {
  app.use(express.static(path.join(__dirname, "client/build")));
  app.get("*", (req, res) => {
    res.sendFile(path.join(__dirname, "client/build", "index.html"));
  });
}

// ── Step 10: Global error handler — never expose stack traces in production
app.use((err, req, res, next) => {
  const alerter = require("./security/alerter");
  const logger  = require("./security/logger");

  logger.error("[APP] Unhandled error", {
    error:     err.message,
    stack:     err.stack,
    requestId: req.requestId,
    path:      req.path,
    ip:        req.ip,
  });

  alerter.send("SERVER_ERROR", {
    error:     err.message,
    path:      req.path,
    ip:        req.ip,
    requestId: req.requestId,
  });

  res.status(err.status || 500).json({
    error: process.env.NODE_ENV === "production"
      ? "An unexpected error occurred."
      : err.message,
    requestId: req.requestId,
  });
});

// ── Step 11: 404 handler
app.use((req, res) => {
  res.status(404).json({ error: "Route not found", requestId: req.requestId });
});

const PORT = process.env.PORT || 5000;
app.listen(PORT, () => {
  console.log(`🚀 Server running on port ${PORT}`);
  console.log(`🛡️  Security suite v3.0: ACTIVE`);
  console.log(`📋 Environment: ${process.env.NODE_ENV || "development"}`);
  console.log(`🔍 OWASP Top 10 coverage: A01-A10`);
  console.log(`🍯 Honeypot traps: ACTIVE`);
  console.log(`🌍 Geo-blocking: ACTIVE`);
  console.log(`🧠 Threat intel: ACTIVE`);
});

module.exports = app;
