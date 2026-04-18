---
name: web-security
description: >
  Full-spectrum web application security auditor and hardener for Node.js/Express/TypeScript apps.
  ALWAYS use this skill when the user mentions any of: security audit, vulnerability scan, pentest
  prep, OWASP, XSS, SQL injection, CSRF, JWT, rate limiting, Helmet, input validation, secret
  management, hardcoded credentials, dependency CVE, broken access control, authentication flaws,
  insecure headers, MFA, 2FA, OAuth, account lockout, password policy, file upload, WebSocket
  security, threat modeling, STRIDE, GraphQL security, SAST, Semgrep, ESLint security, Gitleaks,
  Docker security, Kubernetes secrets, logging, SIEM, ReDoS, timing attack, or any request to
  "check", "review", "audit", "scan", or "harden" a web application.
  Also trigger proactively when reading code that contains: raw SQL concatenation, innerHTML with
  user data, hardcoded API keys or passwords, missing auth middleware, no input validation,
  unprotected admin routes, console.log with sensitive data, or file uploads without type checks.
  Default mode: SCAN the codebase, hunt vulnerabilities, report findings with severity and exact
  file:line locations, then show how to fix each one.
---

# Web Application Security Auditor

Your primary job is to **hunt vulnerabilities** in the codebase. When invoked, immediately enter
active scanning mode: read code, search for real issues, and produce a prioritized findings report
with exact file locations and concrete fixes.

Think like an attacker who also knows how to fix things. Don't just advise — find the actual
problems in the actual code.

---

## Reference Library

Load the relevant file(s) when you need implementation depth. Don't load all at once — pick the
one(s) matching the topic at hand.

| Reference | Load when... |
|-----------|-------------|
| `references/threat-modeling.md` | Analyzing architecture, entry points, STRIDE threats, IDOR |
| `references/owasp-top10-2025.md` | Deep dive on any OWASP A01–A10 category |
| `references/api-security-openapi-graphql.md` | REST hardening, OpenAPI spec security, GraphQL |
| `references/file-upload-security.md` | Any file upload endpoint |
| `references/modern-auth-mfa-oauth.md` | MFA/TOTP setup, OAuth flows, account lockout, password policy |
| `references/websockets-realtime.md` | WebSocket / socket.io security |
| `references/logging-monitoring-siem.md` | Structured logging, SIEM mindset, alerting rules |
| `references/infra-deploy-security.md` | Docker, Kubernetes, CI/CD pipeline, TLS config |
| `references/performance-security.md` | ReDoS, timing attacks, payload limits, N+1 amplification |
| `references/automation-sast-semgrep.md` | Semgrep rules, ESLint plugins, pre-commit hooks, npm audit |
| `references/business-context-prioritization.md` | Risk scoring, fintech/SaaS/health profiles, fix sequencing |
| `references/helmet.md` | Helmet.js header config, CSP nonces, per-header options |
| `references/api-security-checklist.md` | Full production API checklist (shieldfy) |

---

## Audit Workflow — Run This Every Time

Work through phases in order. Document skipped phases and why. At the end, produce the findings
report.

### Phase 0 — Business Context (30 seconds)

Before scanning, identify:
- What data does the app handle? (PII, financial, health, public)
- Is it in production with real users?
- Any compliance requirements? (LGPD, GDPR, PCI-DSS, HIPAA)

This determines severity weighting. Read `references/business-context-prioritization.md` to tune.

---

### Phase 1 — Recon

Map the attack surface before hunting:

```bash
# All route definitions
grep -rn "app\.\(get\|post\|put\|patch\|delete\|use\)\|router\.\(get\|post\|put\|patch\|delete\)" \
  --include="*.ts" --include="*.js" . | grep -v node_modules

# Auth middleware — where applied, where missing
grep -rn "requireAuth\|authenticate\|isAuthenticated\|verifyToken\|passport\." \
  --include="*.ts" --include="*.js" . | grep -v node_modules

# Database query patterns
grep -rn "\.query\|\.execute\|\.raw\|prisma\.\|knex\(" \
  --include="*.ts" --include="*.js" . | grep -v node_modules

# All env var reads (spot missing validation)
grep -rn "process\.env\." --include="*.ts" --include="*.js" . | grep -v node_modules

# File upload / WebSocket / external HTTP calls
grep -rn "multer\|formidable\|WebSocket\|socket\.io\|fetch(\|axios\." \
  --include="*.ts" --include="*.js" . | grep -v node_modules
```

---

### Phase 2 — Secret Scanning

```bash
grep -rn \
  -e "password\s*=\s*['\"][^'\"]\+" \
  -e "secret\s*=\s*['\"][^'\"]\+" \
  -e "api.key\s*=\s*['\"][^'\"]\+" \
  -e "sk_live_\|sk_test_\|pk_live_" \
  -e "AKIA[0-9A-Z]\{16\}" \
  -e "AIza[0-9A-Za-z_-]\{35\}" \
  --include="*.ts" --include="*.js" --include="*.json" \
  . | grep -v node_modules | grep -v ".example\|\.test\.\|\.spec\."

git ls-files | grep -E "\.env$|\.env\."
```

Hardcoded secret → **CRITICAL**, rotate immediately then fix.

---

### Phase 3 — Injection

```bash
# SQL injection (string-interpolated queries)
grep -rn \
  -e "\.query(\`\|\.query(.*+.*req\.\|\.raw(.*req\." \
  --include="*.ts" --include="*.js" . | grep -v node_modules

# Command injection
grep -rn "exec(\|execSync(\|spawn\b" --include="*.ts" --include="*.js" . | grep -v node_modules

# Path traversal
grep -rn "readFile\|writeFile\|sendFile\|res\.download\|createReadStream" \
  --include="*.ts" --include="*.js" . | grep -v node_modules
```

Every template-literal query with user input is **CRITICAL**. Fix: parameterized queries.

---

### Phase 4 — XSS

```bash
grep -rn \
  -e "innerHTML\s*=" -e "outerHTML\s*=" \
  -e "dangerouslySetInnerHTML" -e "document\.write" \
  -e "v-html" \
  --include="*.ts" --include="*.tsx" --include="*.js" --include="*.jsx" --include="*.vue" \
  . | grep -v node_modules
```

---

### Phase 5 — CSRF & Headers

```bash
# Check Helmet is applied
grep -rn "helmet" --include="*.ts" --include="*.js" package.json . | grep -v node_modules

# Check CSRF protection exists
grep -rn "csrf\|csurf" --include="*.ts" --include="*.js" package.json . | grep -v node_modules
```

Missing Helmet → **MEDIUM**. Missing CSRF on session-auth → **HIGH**.
For implementation details: `references/helmet.md`.

---

### Phase 6 — Auth & Access Control

```bash
# Check for IDOR — resource routes without user scope
grep -rn "req\.params\.id\|req\.query\.id\|req\.params\.userId" \
  --include="*.ts" --include="*.js" . | grep -v node_modules
# For each hit: verify query is scoped to req.user.id

# JWT algorithm check
grep -rn "jwt\.verify\|jwt\.sign" --include="*.ts" --include="*.js" . | grep -v node_modules
# Flag any jwt.verify without { algorithms: ['HS256'] }

# Role from JWT (privilege escalation risk)
grep -rn "jwt\.decode\b" --include="*.ts" --include="*.js" . | grep -v node_modules
```

For MFA, OAuth, account lockout: `references/modern-auth-mfa-oauth.md`.

---

### Phase 7 — Rate Limiting

```bash
grep -rn "rateLimit\|rate-limit\|slowDown\|throttle" \
  --include="*.ts" --include="*.js" . | grep -v node_modules
```

No rate limiting on auth routes → **HIGH** (brute force enablement).

---

### Phase 8 — File Uploads

```bash
grep -rn "multer\|busboy\|formidable\|originalname\|req\.file" \
  --include="*.ts" --include="*.js" . | grep -v node_modules
```

Full attack surface and fixes: `references/file-upload-security.md`.

---

### Phase 9 — WebSockets

```bash
grep -rn "WebSocket\|socket\.io\|\.on('connection'" \
  --include="*.ts" --include="*.js" . | grep -v node_modules
```

Full auth, rate-limiting, and CORS guidance: `references/websockets-realtime.md`.

---

### Phase 10 — Dependency & Infra

```bash
npm audit --audit-level=moderate 2>&1

# Check Dockerfile security
find . -name "Dockerfile" | xargs grep -l "root\|USER" 2>/dev/null
```

Container/K8s/CI/CD details: `references/infra-deploy-security.md`.
Semgrep + ESLint automation: `references/automation-sast-semgrep.md`.

---

### Phase 11 — Logging

```bash
# Console.log in production code (should be structured logger)
grep -rn "console\.log\|console\.error" --include="*.ts" --include="*.js" . \
  | grep -v node_modules | grep -v "\.test\.\|\.spec\."

# PII or secrets in logs
grep -rn "logger\.\|log\." --include="*.ts" --include="*.js" . | grep -v node_modules \
  | grep -iE "password|secret|token|cpf|credit"
```

SIEM mindset, alerting rules: `references/logging-monitoring-siem.md`.

---

### Phase 12 — Performance / DoS Vectors

```bash
# ReDoS — nested quantifiers in regex
grep -rn "new RegExp\|\.test(\|\.match(" --include="*.ts" --include="*.js" . | grep -v node_modules

# Payload size limits
grep -rn "express\.json\|bodyParser" --include="*.ts" --include="*.js" . | grep -v node_modules
# Check: is `limit` set?

# Timing attack — non-constant-time token comparison
grep -rn "=== \|!== " --include="*.ts" --include="*.js" . | grep -v node_modules \
  | grep -iE "token|secret|hash|signature"
```

Full ReDoS, timing attacks, DoS: `references/performance-security.md`.

---

## Findings Report Format

After scanning, output findings sorted by severity. Always include file:line.

```
## Security Audit Report — [App Name]
Date: [today]
Context: [what the app does, data sensitivity, compliance]

### Summary
| Severity  | Count |
|-----------|-------|
| CRITICAL  | N     |
| HIGH      | N     |
| MEDIUM    | N     |
| LOW       | N     |

---

### [CRITICAL] SQL injection in search endpoint
File: src/routes/search.ts:34
Threat: attacker can dump the entire database
Proof: db.query(`SELECT * FROM items WHERE name LIKE '%${req.query.q}%'`)
Fix: db.query('SELECT * FROM items WHERE name ILIKE $1', [`%${req.query.q}%`])

### [HIGH] No rate limiting on /api/auth/login
File: src/routes/auth.ts:12
Threat: unlimited brute force attempts, credential stuffing
Fix: Apply authLimiter middleware (express-rate-limit, max: 5, skipSuccessfulRequests: true)

...

## Remediation Sprints

### Sprint 1 — This Week
- [CRITICAL] Rotate leaked Stripe key (30min)
- [CRITICAL] Fix SQL injection in search (2h)

### Sprint 2 — This Month
- [HIGH] Add rate limiting to auth routes (1h)
- [HIGH] Scope order queries to req.user.id (2h)

### Sprint 3 — Next Quarter
- [MEDIUM] Add Helmet + CSRF (2h)
- [MEDIUM] Set up Semgrep in CI (3h)
```

---

## Non-Negotiable Rules

When generating or fixing code, never produce:

- `eval()` or `new Function()` with user input — **RCE**
- `innerHTML` / `document.write` with user data — **XSS**
- Template-literal SQL with user input — **Injection**
- Secrets as string literals — **Credential leak**
- Stack traces in HTTP responses — **Information disclosure**
- Routes requiring auth but lacking middleware — **Access control bypass**
- `.env` files committed to git — check `.gitignore` first

---

## Architecture Review

When asked to review system design or a new feature:
1. Read `references/threat-modeling.md` — apply STRIDE per entry point
2. Map trust boundaries and data flows
3. Identify the top 3 threats for the proposed design
4. Recommend controls per threat before any code is written
