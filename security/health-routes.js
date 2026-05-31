/**
 * ================================================================
 *  SECURITY HEALTH CHECK ROUTES v3.0
 *  GET /health              — Public (load balancer / uptime monitor)
 *  GET /security-status     — Protected (internal dashboards only)
 *  GET /threat-intel        — Protected (threat intelligence summary)
 *  GET /security-metrics    — Protected (Prometheus-compatible format)
 * ================================================================
 */

"use strict";

const router    = require("express").Router();
const os        = require("os");
const logger    = require("./logger");
const threatIntel = require("./threat-intel");

// Internal token guard — returns 404 to frustrate enumeration
const internalOnly = (req, res, next) => {
  const token = req.headers["x-internal-token"];
  if (!token || token !== process.env.INTERNAL_HEALTH_TOKEN) {
    logger.warn(`[HEALTH] Unauthorized status attempt: IP=${req.ip}`);
    return res.status(404).json({ error: "Not found" });
  }
  next();
};

// ── Public — safe for load balancers / uptime monitors
router.get("/health", (req, res) => {
  res.json({ status: "ok", timestamp: new Date().toISOString() });
});

// ── Protected — for your internal monitoring dashboard
router.get("/security-status", internalOnly, (req, res) => {
  const uptimeHuman = new Date(process.uptime() * 1000).toISOString().substr(11, 8);
  res.json({
    status:    "operational",
    timestamp: new Date().toISOString(),
    system: {
      nodeVersion:   process.version,
      platform:      process.platform,
      uptime:        uptimeHuman,
      memoryUsageMB: Math.round(process.memoryUsage().heapUsed / 1024 / 1024),
      cpuLoad:       os.loadavg()[0].toFixed(2),
    },
    security: {
      version:               "3.0",
      helmet:                true,
      rateLimiting:          true,
      inputSanitization:     true,
      threatDetection:       true,
      sqlInjectionBlocking:  true,
      xssProtection:         true,
      cors:                  true,
      auditLogging:          true,
      geoBlocking:           true,          // NEW v3.0
      ipBanning:             true,          // NEW v3.0
      anomalyScoring:        true,          // NEW v3.0
      jwtReplayProtection:   true,          // NEW v3.0
      honeypotTraps:         true,          // NEW v3.0
      log4ShellBlocking:     true,          // NEW v3.0
      bidiStrippping:        true,          // NEW v3.0
      owaspCoverage:         "A01-A10",
    },
    environment: process.env.NODE_ENV || "development",
  });
});

// ── NEW v3.0: Threat intelligence summary
router.get("/threat-intel", internalOnly, (req, res) => {
  res.json(threatIntel.getSummary());
});

// ── NEW v3.0: Prometheus-compatible metrics endpoint
//    Integrate with Grafana or any Prometheus-compatible scraper
router.get("/security-metrics", internalOnly, (req, res) => {
  const summary = threatIntel.getSummary();
  const lines = [
    `# HELP absall_total_incidents Total security incidents recorded`,
    `# TYPE absall_total_incidents counter`,
    `absall_total_incidents ${summary.totalIncidents}`,
    `# HELP absall_unique_attacker_ips Unique attacker IPs tracked`,
    `# TYPE absall_unique_attacker_ips gauge`,
    `absall_unique_attacker_ips ${summary.uniqueAttackerIPs}`,
    ...Object.entries(summary.attackTypeSummary).map(
      ([type, count]) =>
        `absall_attack_type_total{type="${type}"} ${count}`
    ),
  ];
  res.setHeader("Content-Type", "text/plain; version=0.0.4");
  res.send(lines.join("\n") + "\n");
});

module.exports = router;
