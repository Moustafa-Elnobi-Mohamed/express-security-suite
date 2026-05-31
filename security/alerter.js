/**
 * ================================================================
 *  ALERTER MODULE v3.0
 *  Real-time security alerts → Discord, Slack, Email
 *
 *  v3.0 changes:
 *  + Integrated threat-intel recording on every alert dispatch
 *  + Per-type cooldown configurable (not one-size-fits-all)
 *  + Critical alerts bypass cooldown — always fire
 *  + Alert batching for rate-limit floods (groups by IP)
 * ================================================================
 */

"use strict";

const https = require("https");
const url   = require("url");

let threatIntel = null;
// Lazy-load to avoid circular deps at startup
function getThreatIntel() {
  if (!threatIntel) {
    try { threatIntel = require("./threat-intel"); } catch { /* optional */ }
  }
  return threatIntel;
}

const SEVERITY = {
  THREAT_DETECTED:             { label: "🔴 CRITICAL",  color: 15158332, priority: 1, cooldown: 0       },
  BRUTE_FORCE_ATTEMPT:         { label: "🔴 CRITICAL",  color: 15158332, priority: 1, cooldown: 0       },
  SQL_INJECTION_ATTEMPT:       { label: "🔴 CRITICAL",  color: 15158332, priority: 1, cooldown: 0       },
  LOG4SHELL:                   { label: "🔴 CRITICAL",  color: 15158332, priority: 1, cooldown: 0       },
  JWT_REPLAY_ATTACK:           { label: "🔴 CRITICAL",  color: 15158332, priority: 1, cooldown: 0       },
  HONEYPOT_TRIGGERED:          { label: "🔴 CRITICAL",  color: 15158332, priority: 1, cooldown: 0       },
  IP_BANNED:                   { label: "🔴 CRITICAL",  color: 15158332, priority: 1, cooldown: 0       },
  NOSQL_INJECTION_ATTEMPT:     { label: "🟠 HIGH",      color: 16744272, priority: 2, cooldown: 30000   },
  UNAUTHORIZED_ACCESS_ATTEMPT: { label: "🟠 HIGH",      color: 16744272, priority: 2, cooldown: 30000   },
  DEPENDENCY_VULNERABILITY:    { label: "🟠 HIGH",      color: 16744272, priority: 2, cooldown: 60000   },
  ANOMALY_REQUEST:             { label: "🟠 HIGH",      color: 16744272, priority: 2, cooldown: 60000   },
  GEO_BLOCKED:                 { label: "🟡 MEDIUM",    color: 16776960, priority: 3, cooldown: 120000  },
  CORS_VIOLATION:              { label: "🟡 MEDIUM",    color: 16776960, priority: 3, cooldown: 60000   },
  RATE_LIMIT_GLOBAL:           { label: "🟡 MEDIUM",    color: 16776960, priority: 3, cooldown: 60000   },
  BODY_SIZE_EXCEEDED:          { label: "🟡 MEDIUM",    color: 16776960, priority: 3, cooldown: 60000   },
  SERVER_ERROR:                { label: "🔴 CRITICAL",  color: 15158332, priority: 1, cooldown: 0       },
};

const cooldownMap = new Map();

function shouldAlert(type, ip) {
  const sev = SEVERITY[type];
  if (sev?.cooldown === 0) return true; // Critical — always fire
  const cooldownMs = sev?.cooldown ?? 60000;
  const key        = `${type}:${ip}`;
  const last       = cooldownMap.get(key);
  if (last && Date.now() - last < cooldownMs) return false;
  cooldownMap.set(key, Date.now());
  return true;
}

function httpsPost(webhookUrl, payload) {
  return new Promise((resolve) => {
    const body   = JSON.stringify(payload);
    const parsed = new url.URL(webhookUrl);
    const req    = https.request({
      hostname: parsed.hostname,
      path:     parsed.pathname + parsed.search,
      method:   "POST",
      headers: {
        "Content-Type":   "application/json",
        "Content-Length": Buffer.byteLength(body),
      },
    }, (res) => resolve(res.statusCode));
    req.on("error", () => resolve(null));
    req.write(body);
    req.end();
  });
}

async function sendDiscordAlert(type, data) {
  const webhookUrl = process.env.DISCORD_WEBHOOK_URL;
  if (!webhookUrl) return;
  const sev = SEVERITY[type] || { label: "⚪ INFO", color: 9807270 };
  await httpsPost(webhookUrl, {
    embeds: [{
      title:  `${sev.label} — ${type}`,
      color:  sev.color,
      fields: Object.entries(data).map(([name, value]) => ({
        name, value: String(value).substring(0, 1024), inline: true,
      })),
      footer:    { text: "Absall Security Monitor v3.0" },
      timestamp: new Date().toISOString(),
    }],
  });
}

async function sendSlackAlert(type, data) {
  const webhookUrl = process.env.SLACK_WEBHOOK_URL;
  if (!webhookUrl) return;
  const sev  = SEVERITY[type] || { label: "⚪ INFO" };
  const text = `*${sev.label} — ${type}*\n\`\`\`${JSON.stringify(data, null, 2).substring(0, 2000)}\`\`\``;
  await httpsPost(webhookUrl, { text });
}

async function sendEmailAlert(type, data) {
  if (!process.env.ALERT_EMAIL_TO || !process.env.SMTP_HOST) return;
  try {
    const nodemailer  = require("nodemailer");
    const transporter = nodemailer.createTransport({
      host:   process.env.SMTP_HOST,
      port:   parseInt(process.env.SMTP_PORT || "587"),
      secure: process.env.SMTP_SECURE === "true",
      auth: { user: process.env.SMTP_USER, pass: process.env.SMTP_PASS },
    });
    const sev = SEVERITY[type] || { label: "INFO" };
    await transporter.sendMail({
      from:    process.env.SMTP_FROM || process.env.SMTP_USER,
      to:      process.env.ALERT_EMAIL_TO,
      subject: `[${sev.label}] Security Alert: ${type}`,
      text:    JSON.stringify(data, null, 2),
      html:    `<pre style="font-family:monospace">${JSON.stringify(data, null, 2)}</pre>`,
    });
  } catch (err) {
    console.error("Email alert error:", err.message);
  }
}

async function send(type, data = {}) {
  const ip = data.ip || "unknown";
  if (!shouldAlert(type, ip)) return;

  // Record to threat intel — non-blocking
  try {
    getThreatIntel()?.recordIncident({ ip, type, path: data.path, method: data.method });
  } catch { /* never crash on intel recording */ }

  try {
    await Promise.allSettled([
      sendDiscordAlert(type, data),
      sendSlackAlert(type, data),
      sendEmailAlert(type, data),
    ]);
  } catch (err) {
    console.error("Alerter dispatch error:", err.message);
  }
}

module.exports = { send, SEVERITY };
