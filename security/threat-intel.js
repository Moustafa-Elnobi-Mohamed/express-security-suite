/**
 * ================================================================
 *  THREAT INTELLIGENCE MODULE v1.0  (NEW — v3.0 Suite)
 *  Author: Moustafa Elnobi
 *
 *  Aggregates threat data from detected events into an in-memory
 *  threat intelligence store. Feeds the anomaly scorer and the
 *  /security-status dashboard with attacker profiling data.
 *
 *  Production upgrade path: swap Map → Redis for persistence
 *  across restarts and multi-instance deployments.
 *
 *  Features:
 *  - Per-IP incident history with TTL-based expiry
 *  - Attack type frequency tracking (top attack vectors)
 *  - Automatic escalation scoring (repeated attacker = higher risk)
 *  - Exportable summary for dashboard and SIEM forwarding
 * ================================================================
 */

"use strict";

const logger = require("./logger");

// ── Storage: ip → { incidents: [], firstSeen, lastSeen, score }
const ipProfiles    = new Map();
const PROFILE_TTL   = 24 * 60 * 60 * 1000; // 24 hours

// ── Global counters
const attackTypeCounts = new Map();
let totalIncidents = 0;

/**
 * Record a security event for a given IP.
 * Call this from alerter.send() side-effects or directly from middleware.
 */
function recordIncident({ ip = "unknown", type = "UNKNOWN", path = "/", method = "GET", timestamp = new Date().toISOString() } = {}) {
  totalIncidents++;

  // Update attack type frequency
  attackTypeCounts.set(type, (attackTypeCounts.get(type) ?? 0) + 1);

  if (!ip || ip === "unknown") return;

  const now = Date.now();

  if (!ipProfiles.has(ip)) {
    ipProfiles.set(ip, {
      ip,
      firstSeen:  timestamp,
      lastSeen:   timestamp,
      score:      0,
      incidents:  [],
    });
  }

  const profile = ipProfiles.get(ip);
  profile.lastSeen = timestamp;
  profile.score   += getSeverityScore(type);
  profile.incidents.push({ type, path, method, timestamp });

  // Cap incident history at 100 per IP to bound memory
  if (profile.incidents.length > 100) {
    profile.incidents = profile.incidents.slice(-100);
  }

  logger.info(`[THREAT_INTEL] Recorded incident — IP=${ip} type=${type} score=${profile.score}`);
}

function getSeverityScore(type) {
  const scores = {
    THREAT_DETECTED:             10,
    LOG4SHELL:                   10,
    SQL_INJECTION_ATTEMPT:       10,
    BRUTE_FORCE_ATTEMPT:          8,
    JWT_REPLAY_ATTACK:            8,
    HONEYPOT_TRIGGERED:           8,
    NOSQL_INJECTION_ATTEMPT:      6,
    UNAUTHORIZED_ACCESS_ATTEMPT:  5,
    ANOMALY_REQUEST:              3,
    CORS_VIOLATION:               2,
    RATE_LIMIT_GLOBAL:            1,
  };
  return scores[type] ?? 2;
}

/** Get profile for a single IP */
function getProfile(ip) {
  return ipProfiles.get(ip) ?? null;
}

/** Get top N most active attacker IPs by score */
function getTopAttackers(n = 10) {
  return [...ipProfiles.values()]
    .sort((a, b) => b.score - a.score)
    .slice(0, n)
    .map(({ ip, score, firstSeen, lastSeen, incidents }) => ({
      ip, score, firstSeen, lastSeen,
      incidentCount: incidents.length,
      topType: getMostFrequent(incidents.map((i) => i.type)),
    }));
}

/** Get attack type frequency summary */
function getAttackTypeSummary() {
  return Object.fromEntries(
    [...attackTypeCounts.entries()].sort((a, b) => b[1] - a[1])
  );
}

/** Full summary for /security-status dashboard */
function getSummary() {
  purgeExpiredProfiles();
  return {
    totalIncidents,
    uniqueAttackerIPs: ipProfiles.size,
    attackTypeSummary: getAttackTypeSummary(),
    topAttackers:      getTopAttackers(5),
    generatedAt:       new Date().toISOString(),
  };
}

/** Purge profiles older than TTL */
function purgeExpiredProfiles() {
  const cutoff = Date.now() - PROFILE_TTL;
  for (const [ip, profile] of ipProfiles.entries()) {
    if (new Date(profile.lastSeen).getTime() < cutoff) {
      ipProfiles.delete(ip);
    }
  }
}

function getMostFrequent(arr) {
  if (!arr.length) return null;
  const freq = {};
  let max = 0, result = arr[0];
  for (const item of arr) {
    freq[item] = (freq[item] ?? 0) + 1;
    if (freq[item] > max) { max = freq[item]; result = item; }
  }
  return result;
}

// Auto-purge every hour
setInterval(purgeExpiredProfiles, 60 * 60 * 1000).unref();

module.exports = { recordIncident, getProfile, getTopAttackers, getAttackTypeSummary, getSummary };
