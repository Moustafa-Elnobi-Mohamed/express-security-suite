# 🛡️ Enterprise Security Middleware Suite for Node.js/Express

> Production-grade, OWASP Top 10 (2021) aligned security layer for React + Node.js/Express applications.  
> Built by a SOC Analyst. Designed to mirror real enterprise WAF and detection engineering patterns.

[![Security Pipeline](https://github.com/yourusername/absall-security-suite/actions/workflows/security-pipeline.yml/badge.svg)](https://github.com/yourusername/absall-security-suite/actions)
[![OWASP Coverage](https://img.shields.io/badge/OWASP%20Top%2010-A01--A10-green)](https://owasp.org/Top10/)
[![Node.js](https://img.shields.io/badge/Node.js-18%2B-brightgreen)](https://nodejs.org)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)

---

## 📌 Why this project exists

I built this while hardening a production web application and noticed that most Express security tutorials stop at "add Helmet and a rate limiter." This goes further — it implements the same defense-in-depth layering used in enterprise SOC environments: anomaly detection, attacker profiling, honeypot trapping, Log4Shell blocking, and a real-time threat intelligence feed, all without any external paid service.

This is live in production. Every middleware layer is documented with the OWASP control it satisfies and the attack scenario it defeats.

---

## 🏗️ Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                     INCOMING REQUEST                         │
└──────────────────────────┬──────────────────────────────────┘
                           │
          ┌────────────────▼────────────────┐
          │      Hostinger / Nginx           │  ← TLS termination, HSTS
          └────────────────┬────────────────┘
                           │
          ┌────────────────▼────────────────┐
          │    Express Security Stack v3.0   │
          │                                  │
          │  Phase 0  Request ID (UUID)       │  → Forensic correlation
          │  Phase 1  IP Ban Check            │  → Fast-reject known bad IPs
          │  Phase 2  Geo-Blocking            │  → CIDR/country filtering
          │  Phase 3  Helmet + CORS + Headers │  → XSS, clickjacking, MIME
          │  Phase 4  Anomaly Scorer          │  → Risk-score each request
          │  Phase 5  Rate Limiting           │  → DDoS, brute force
          │  Phase 6  Input Sanitization      │  → XSS, NoSQL, HPP, BiDi
          │  Phase 7  Threat Detection (WAF)  │  → 21 attack patterns
          │  Phase 8  JWT Replay Guard        │  → Stolen token protection
          │  Phase 9  Audit Logger + TTFB     │  → Full forensic trail
          └────────────────┬────────────────┘
                           │
          ┌────────────────▼────────────────┐
          │         Honeypot Traps           │  → Attacker fingerprinting
          └────────────────┬────────────────┘
                           │
          ┌────────────────▼────────────────┐
          │      Application Routes          │
          └────────────────┬────────────────┘
                           │
          ┌────────────────▼────────────────┐
          │    Threat Intelligence Store     │  → Per-IP incident profiles
          │    Alert Dispatcher              │  → Discord / Slack / Email
          └──────────────────────────────────┘
```

---

## ✅ OWASP Top 10 Coverage Matrix

| OWASP ID | Risk | Controls Implemented |
|----------|------|----------------------|
| **A01** | Broken Access Control | CORS whitelist · `authLimiter` · `internalOnly` token guard · geo-blocking |
| **A02** | Cryptographic Failures | HSTS 1yr + preload · TLS enforcement · JWT algorithm pinning |
| **A03** | Injection (XSS/SQL/NoSQL) | `xss-clean` · `mongoSanitize` · recursive `deepSanitize` · SQL pattern scanner · Log4Shell/JNDI · CSP headers |
| **A04** | Insecure Design | Rate limiting · speed throttling · anomaly scoring · body size limits |
| **A05** | Security Misconfiguration | Helmet full config · CORS strict mode · geo-blocking · no `X-Powered-By` |
| **A06** | Vulnerable Components | `vuln-scanner.js` · GitHub Actions weekly audit · CodeQL · OWASP Dependency-Check |
| **A07** | Auth & Session Failures | `authLimiter` (10 req/15min) · JWT replay-attack protection · brute-force alerting |
| **A08** | Software & Data Integrity | CSP blocks inline scripts · SRI-ready header config · JWT alg pinning |
| **A09** | Logging & Monitoring | Winston structured JSON logging · TTFB tracking · real-time Discord/Slack/email alerts · threat intel store |
| **A10** | SSRF | Blocks `169.254.169.254` · `file://` · `gopher://` · JNDI · open redirect patterns |

---

## 🆕 What's New in v3.0

| Feature | Description | Security Benefit |
|---------|-------------|-----------------|
| **Geo-Blocking** | Allowlist by country code via Cloudflare `CF-IPCountry` header | Reduces attack surface to operational regions |
| **IP Ban System** | Automatic 10-minute bans on repeated abuse, manual ban API | Stops persistent attackers without firewall rules |
| **Anomaly Scorer** | Scores each request across 6 risk signals; ban threshold auto-triggers | Catches scripted attacks that evade rate limits |
| **JWT Replay Guard** | Tracks used JTIs; flags + bans on reuse | Defeats stolen-token replay attacks |
| **Honeypot Traps** | 12 fake admin/config paths; any hit = instant ban + alert | Fingerprints and stops automated scanners |
| **Log4Shell / JNDI** | Blocks `${jndi:...}` and variant patterns in all inputs | Stops Log4Shell exploitation attempts |
| **OGNL Injection** | Blocks Apache Struts/Confluence OGNL attack patterns | Defense-in-depth for Java-adjacent stacks |
| **Prototype Pollution** | Blocks `__proto__`, `constructor[` query patterns | Stops JS prototype chain attacks |
| **BiDi Strip** | Removes Unicode direction-override characters | Defeats invisible-character code disguise attacks |
| **Threat Intel Module** | Per-IP incident profiles, attack type frequency, top-attacker leaderboard | SIEM-ready data for incident response |
| **Prometheus Metrics** | `/security-metrics` in Prometheus text format | Grafana dashboard integration |
| **TTFB Tracking** | Audit log now measures time-to-first-byte | Performance regression detection |
| **Per-Route Limiters** | `createLimiter()` factory for per-endpoint rate windows | Tighter control on expensive endpoints |

---

## 📁 File Structure

```
security/
├── security-middleware.js   — Core: all middleware layers (Phases 0–9)
├── threat-intel.js          — NEW: per-IP profiling and attack frequency tracking
├── alerter.js               — Real-time alerts with per-type cooldowns
├── logger.js                — Winston structured JSON logger + daily rotation
├── health-routes.js         — /health · /security-status · /threat-intel · /security-metrics
├── vuln-scanner.js          — Dependency CVE scanner (CI step)
├── frontendSecurity.js      — React client-side security utilities
├── integration-example.js   — Copy-paste Express server setup
└── .env.example             — All required environment variables

.github/workflows/
└── security-pipeline.yml    — CI/CD: audit · CodeQL · TruffleHog · OWASP
```

---

## 🚀 Quickstart

### 1. Install dependencies

```bash
npm install helmet express-rate-limit express-slow-down \
            express-mongo-sanitize xss-clean hpp cors \
            winston validator

# Optional
npm install winston-daily-rotate-file nodemailer
```

### 2. Environment variables

```bash
cp security/.env.example .env
```

Generate secure tokens:
```bash
node -e "console.log(require('crypto').randomBytes(32).toString('hex'))"  # INTERNAL_HEALTH_TOKEN
node -e "console.log(require('crypto').randomBytes(64).toString('hex'))"  # JWT_SECRET
```

### 3. Wire into Express

```js
const {
  applySecurityMiddleware,
  registerHoneypots,
  authLimiter,
  createLimiter,
} = require('./security/security-middleware');

app.use(express.json({ limit: '10kb' }));
app.set('trust proxy', 1);

applySecurityMiddleware(app);   // All layers active
registerHoneypots(app);         // Must come before your routes

app.use('/api/auth/login', authLimiter);
app.use('/api/export', createLimiter({ max: 5, windowMs: 60000 }));
```

### 4. Verify it's working

```bash
# Should return 200 { "status": "ok" }
curl http://localhost:5000/health

# Should return 404 (security obscurity)
curl http://localhost:5000/security-status

# Should return security status
curl -H "x-internal-token: YOUR_TOKEN" http://localhost:5000/security-status

# Threat intel summary
curl -H "x-internal-token: YOUR_TOKEN" http://localhost:5000/threat-intel

# Test honeypot (should return 404 + trigger alert + ban your IP)
curl http://localhost:5000/wp-admin
```

### 5. Discord alerts (free, instant)

1. Discord → Server Settings → Integrations → Webhooks → New Webhook
2. Copy URL → add to `.env` as `DISCORD_WEBHOOK_URL`

---

## 🛡️ Alert Types

| Alert | Severity | Trigger |
|-------|----------|---------|
| `THREAT_DETECTED` | 🔴 Critical | WAF pattern match (21 attack signatures) |
| `LOG4SHELL` | 🔴 Critical | JNDI/Log4Shell injection pattern |
| `BRUTE_FORCE_ATTEMPT` | 🔴 Critical | >10 auth failures from same IP in 15 min |
| `JWT_REPLAY_ATTACK` | 🔴 Critical | Reused JWT token detected |
| `HONEYPOT_TRIGGERED` | 🔴 Critical | Hit on admin/config decoy route |
| `IP_BANNED` | 🔴 Critical | IP auto-banned by anomaly scorer or honeypot |
| `SQL_INJECTION_ATTEMPT` | 🔴 Critical | SQL pattern in any input field |
| `NOSQL_INJECTION_ATTEMPT` | 🟠 High | `$` / `.` operator in JSON body |
| `ANOMALY_REQUEST` | 🟠 High | Risk score ≥ 3 (suspicious but not ban-worthy) |
| `UNAUTHORIZED_ACCESS_ATTEMPT` | 🟠 High | 401/403 response triggered |
| `DEPENDENCY_VULNERABILITY` | 🟠 High | Critical/High CVE in npm packages |
| `GEO_BLOCKED` | 🟡 Medium | Request from non-allowed country |
| `CORS_VIOLATION` | 🟡 Medium | Request from non-whitelisted origin |
| `RATE_LIMIT_GLOBAL` | 🟡 Medium | IP exceeds 300 req/15min |
| `SERVER_ERROR` | 🔴 Critical | Unhandled 500 error |

---

## 📊 Threat Intelligence API

The `/threat-intel` endpoint (protected) returns a live summary:

```json
{
  "totalIncidents": 47,
  "uniqueAttackerIPs": 3,
  "attackTypeSummary": {
    "SCANNER": 18,
    "HONEYPOT_TRIGGERED": 12,
    "RATE_LIMIT_GLOBAL": 9,
    "SQL_INJECTION_ATTEMPT": 5,
    "BRUTE_FORCE_ATTEMPT": 3
  },
  "topAttackers": [
    {
      "ip": "1.2.3.4",
      "score": 88,
      "firstSeen": "2025-01-15T09:12:00.000Z",
      "lastSeen": "2025-01-15T09:47:00.000Z",
      "incidentCount": 23,
      "topType": "SCANNER"
    }
  ]
}
```

---

## 🔗 Production Checklist

```
☐ NODE_ENV=production in .env
☐ FRONTEND_URL set to your domain (no trailing slash)
☐ DISCORD_WEBHOOK_URL configured and tested
☐ INTERNAL_HEALTH_TOKEN generated (32-byte hex)
☐ ALLOWED_COUNTRIES set to your operational regions
☐ .env added to .gitignore
☐ HSTS preload submitted at hstspreload.org (post go-live)
☐ npm audit passes (no critical/high vulnerabilities)
☐ /health → 200 { "status": "ok" }
☐ /security-status without token → 404
☐ /wp-admin → 404 + Discord alert fired
☐ React build served statically (client/build)
☐ Logs directory writable (mkdir logs)
☐ Redis configured for JWT JTI store (multi-instance deployments)
```

---

## 🧠 Security Design Decisions

**Why ban IPs instead of just rate-limit them?**  
Rate limiting still processes every request through the stack. Banned IPs are rejected at Phase 1, before CORS, sanitization, or business logic runs — zero overhead.

**Why a custom anomaly scorer instead of just rate limiting?**  
Rate limiting catches volume attacks. The anomaly scorer catches low-and-slow probing by automated tools that deliberately stay under rate limits. Missing User-Agent + unusual depth + no Accept header = scanner, even at 1 req/hour.

**Why are critical alerts exempt from cooldown?**  
Honeypot hits, Log4Shell, and JWT replay attacks are high-fidelity, low-noise signals. Every single hit is a real event that needs immediate attention. Cooldowns are for noisy signals like rate limit hits.

**Why in-memory for the JTI store and IP bans?**  
Simplicity for single-instance deployments. The code comments all say "swap for Redis" — this is the correct production upgrade path, and it's a one-line change per store.

---

## 📄 License

MIT — Built for production use on Hostinger-hosted Node.js/React applications.

---

*If this helped you, consider starring the repo. For questions or collaboration, find me on [LinkedIn](https://www.linkedin.com/in/moustafa-elnobi-mohamed/).*
