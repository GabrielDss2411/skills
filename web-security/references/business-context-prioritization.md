# Security Prioritization by Business Context

## Why Context Changes Everything

A CRITICAL finding in a hobby project is different from the same finding in a fintech app handling
payments. Prioritization must account for: data sensitivity, regulatory exposure, attack surface
size, and the cost of exploitation vs. the cost of fixing.

Don't hand the user a flat list of 40 findings — triage and sequence them.

---

## Risk Scoring Formula

```
Risk Score = Likelihood × Impact

Likelihood factors:
  - Is the vulnerability externally exposed? (multiplier: 2x)
  - Does it require authentication? (no auth = higher)
  - Is it easily discoverable? (known pattern = higher)
  - Is the app actively targeted? (public-facing = higher)

Impact factors:
  - Data sensitivity: PII / financial / health data = high
  - Blast radius: affects all users vs. one user
  - Reversibility: can the damage be undone?
  - Regulatory: LGPD / GDPR / PCI-DSS violation?
```

---

## Business Context Profiles

### Profile: Fintech / Payments

**Highest priority findings:**
1. Any injection vulnerability near payment or balance logic
2. Missing transaction integrity (no DB transactions on multi-step ops)
3. Insecure direct object reference on financial records
4. JWT algorithm confusion (privilege escalation to admin)
5. Missing rate limiting on payment initiation endpoints
6. Secrets in code (Stripe key leakage = direct financial loss)

**Regulatory exposure:** PCI-DSS (card data), LGPD/GDPR (PII)
**Audience:** Attackers actively target payment flows — assume you're being probed

```
Fix order: CRITICAL → HIGH before any new features ship
MFA: mandatory for financial operations (even internal admin)
Audit logs: append-only, retained minimum 90 days
```

---

### Profile: SaaS / B2B Multi-Tenant

**Highest priority findings:**
1. Tenant isolation failures (user from tenant A accessing tenant B data)
2. Admin route without tenant scope check
3. Insecure direct object reference (cross-tenant IDOR)
4. Weak session management (session sharing across tenants)
5. Subdomain takeover risk (dangling DNS)

**Critical question:** Are all DB queries scoped by `tenantId`?

```ts
// Every query in multi-tenant must include tenant scope
const data = await db.record.findMany({
  where: {
    tenantId: req.user.tenantId,  // ← always required
    ...filters,
  },
});
```

**Fix order:** Tenant isolation > auth > everything else
**Audience:** Disgruntled customers, corporate espionage, insider threat

---

### Profile: Healthcare / Medical

**Highest priority findings:**
1. PHI (Protected Health Information) accessible without auth
2. Missing audit trail on any record access/modification
3. PHI in logs or error messages
4. Insecure API returning patient data to wrong user
5. No MFA for clinical staff accounts

**Regulatory exposure:** HIPAA (US), LGPD + CFM regulations (Brazil), GDPR (EU)
**Audience:** Privacy-motivated, occasionally nation-state

```
Every access to patient record must be logged with: who, what, when, why
Minimum necessary principle: API only returns fields needed for the use case
```

---

### Profile: Early-Stage Startup / MVP

**Reality check:** Perfect security takes time the team may not have.
Prioritize by attack probability:

**Tier 1 — Fix now (high probability, low effort):**
- Helmet + HTTPS (30 min, prevents passive attacks)
- Rate limiting on auth (1 hour, prevents brute force)
- Parameterized queries (ongoing, prevents SQLi)
- No secrets in code (30 min, prevents credential leak)

**Tier 2 — Fix before Series A / first enterprise customer:**
- CSRF protection
- Input validation with Joi
- Error handler (no stack traces)
- `npm audit` clean

**Tier 3 — Fix when you have security budget:**
- Full OWASP audit
- Penetration test
- MFA
- SIEM / alerting

---

### Profile: Internal Tool / Admin Panel

**Don't underestimate internal tools** — they often have:
- Higher privilege (admin operations, bulk data access)
- Weaker auth (assumed trusted network)
- No rate limiting ("nobody would attack this")

**Must-have regardless of "internal" label:**
- Auth required on every route (zero trust — internal network ≠ trusted)
- RBAC with minimum necessary permissions
- All actions logged to immutable audit log
- IP allowlist if truly internal-only
- Session timeout (short — 2-4h)

---

## Severity Escalation Rules

Upgrade severity when these multipliers apply:

| Condition | Effect |
|-----------|--------|
| Externally accessible (no VPN/IP restriction) | +1 severity level |
| Handles PII, financial, or health data | +1 severity level |
| No authentication required to trigger | +1 severity level |
| Automated exploitation possible (known tool/script) | +1 severity level |
| Affects all users (not just the attacker's account) | +1 severity level |

Example: Missing rate limiting (normally MEDIUM) + on public login endpoint + fintech app = **CRITICAL**

---

## Remediation Sequencing

When presenting findings, group them into sprints:

```
## Sprint 1 — This Week (stop bleeding)
- [CRITICAL] Rotate exposed Stripe key (1h)
- [CRITICAL] Fix SQL injection in /api/search (2h)
- [HIGH] Add rate limiting to /api/auth/login (1h)

## Sprint 2 — This Month (harden the perimeter)
- [HIGH] Scope all order queries to req.user.id (3h)
- [HIGH] Add CSRF protection (2h)
- [MEDIUM] Remove stack traces from error responses (30min)
- [MEDIUM] Add Helmet middleware (1h)

## Sprint 3 — Next Quarter (defense in depth)
- [MEDIUM] Implement MFA for admin accounts
- [MEDIUM] Set up structured security logging
- [LOW] Dependency audit automation (Dependabot)
- [LOW] SAST pipeline (Semgrep in CI)
```

---

## Questions to Ask the User Before Prioritizing

Before generating your fix order, ask (or infer from context):

1. **What data does this app handle?** (PII, financial, health, public-only)
2. **Who are the users?** (public internet, authenticated customers, internal staff)
3. **Is this in production?** (live users = higher urgency)
4. **Any compliance requirements?** (LGPD, GDPR, PCI-DSS, HIPAA, SOC2)
5. **What's the team's security capacity?** (How much time can they spend this month?)
6. **Has there been any known incident?** (Active exploitation changes everything)

These answers let you tune the remediation plan to what will actually get shipped.
