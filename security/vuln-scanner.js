#!/usr/bin/env node
/**
 * ================================================================
 *  DEPENDENCY VULNERABILITY SCANNER v2.0
 *  Runs npm audit, parses results, and alerts on critical CVEs.
 *
 *  Usage:
 *    node security/vuln-scanner.js
 *    # Or set as a cron job: 0 9 * * 1 (every Monday 9 AM)
 * ================================================================
 */

"use strict";

const { execSync } = require("child_process");
const fs           = require("fs");
const alerter      = require("./alerter");
const logger       = require("./logger");

async function runVulnScan() {
  const startTime = Date.now();
  console.log("\n🔍 Running dependency vulnerability scan...\n");

  // ── Run npm audit
  let auditResult;
  try {
    const output = execSync("npm audit --json 2>&1", { encoding: "utf8" });
    auditResult  = JSON.parse(output);
  } catch (err) {
    try {
      auditResult = JSON.parse(err.stdout);
    } catch {
      console.error("❌ Failed to parse npm audit output");
      process.exit(1);
    }
  }

  const { vulnerabilities, metadata } = auditResult;
  const counts = metadata?.vulnerabilities || {};
  const { total = 0, critical = 0, high = 0, moderate = 0, low = 0 } = counts;

  console.log("═══════════════════════════════════════");
  console.log("   VULNERABILITY SCAN RESULTS");
  console.log("═══════════════════════════════════════");
  console.log(`   Total:    ${total}`);
  console.log(`   Critical: ${critical}  🔴`);
  console.log(`   High:     ${high}  🟠`);
  console.log(`   Moderate: ${moderate}  🟡`);
  console.log(`   Low:      ${low}  🟢`);
  console.log(`   Scan time: ${Date.now() - startTime}ms`);
  console.log("═══════════════════════════════════════\n");

  if (critical + high > 0) {
    const critVulns = Object.entries(vulnerabilities || {})
      .filter(([, v]) => v.severity === "critical" || v.severity === "high")
      .map(([name, v]) => ({
        package:      name,
        severity:     v.severity,
        via:          v.via?.map((x) => (typeof x === "string" ? x : x.title)).join(", "),
        fixAvailable: v.fixAvailable ? "YES" : "NO",
        url:          v.via?.[0]?.url || "",
      }));

    console.log("🚨 Critical/High vulnerabilities:\n");
    critVulns.forEach((v) => {
      console.log(`  [${v.severity.toUpperCase()}] ${v.package}`);
      console.log(`    Vulnerability: ${v.via}`);
      console.log(`    Fix available: ${v.fixAvailable}`);
      if (v.url) console.log(`    Details: ${v.url}`);
      console.log();
    });

    await alerter.send("DEPENDENCY_VULNERABILITY", {
      critical,
      high,
      packages:   critVulns.map((v) => `${v.package} (${v.severity})`).join(", "),
      action:     "Run: npm audit fix",
      scannedAt:  new Date().toISOString(),
    });

    // Write report to disk
    const report = {
      timestamp: new Date().toISOString(),
      counts: { total, critical, high, moderate, low },
      vulnerabilities: critVulns,
    };
    fs.mkdirSync("logs", { recursive: true });
    fs.writeFileSync("logs/last-audit-report.json", JSON.stringify(report, null, 2));

    console.log("⚠️  Alert dispatched to all configured channels.");
    console.log("💡 Run: npm audit fix          (non-breaking fixes)");
    console.log("💡 Run: npm audit fix --force  (breaking fixes — test first!)\n");
    process.exit(1); // Fail CI/CD pipeline
  } else {
    console.log("✅ No critical or high vulnerabilities found.\n");
    logger.info("Dependency scan passed", { total, moderate, low });
  }
}

runVulnScan().catch((err) => {
  console.error("Scanner error:", err);
  process.exit(1);
});
