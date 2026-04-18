# Threat Modeling & Architecture Security Analysis

Source: OWASP Threat Modeling Cheat Sheet + STRIDE methodology

## What Is Threat Modeling

Threat modeling answers four questions before you write code (or when auditing existing code):
1. **What are we building?** — data flows, trust boundaries, entry points
2. **What can go wrong?** — threats per the STRIDE model
3. **What do we do about it?** — mitigations per threat
4. **Did we do a good job?** — verification

Use this during design review, pre-launch audit, or whenever a new feature is proposed that
touches auth, data storage, external services, or user permissions.

---

## STRIDE Threat Categories

| Threat | Violates | Examples | Key Controls |
|--------|----------|----------|-------------|
| **S**poofing | Authentication | Fake user identity, token forgery, DNS spoofing | Strong auth, MFA, JWT signing, mTLS |
| **T**ampering | Integrity | Modified requests, MITM, DB record alteration | HTTPS, HMAC signatures, signed JWTs, DB constraints |
| **R**epudiation | Non-repudiation | Denying actions taken, log deletion | Append-only audit logs, signed log entries |
| **I**nformation Disclosure | Confidentiality | Data leaks, verbose errors, exposed backups | Encryption at rest/transit, minimal data in responses |
| **D**enial of Service | Availability | DDoS, resource exhaustion, regex DoS | Rate limiting, circuit breakers, input size limits |
| **E**levation of Privilege | Authorization | Accessing admin features, IDOR, JWT role manipulation | RBAC, scope checks per endpoint, signed claims |

---

## Step 1 — Draw the Data Flow Diagram (DFD)

Before scanning code, map what you're working with. Even a rough mental model helps.

**Elements to identify:**

```
External Entities  →  [Browser, Mobile App, External APIs, Webhooks]
Processes          →  [Auth Service, API Server, Background Jobs, Edge Functions]
Data Stores        →  [PostgreSQL, Redis, S3, Elasticsearch]
Data Flows         →  arrows between elements, labeled with data type
Trust Boundaries   →  dashed lines separating different trust levels
```

**Trust boundaries to always identify:**
- Public internet ↔ API server
- API server ↔ Database
- API server ↔ Third-party services (Stripe, SendGrid, etc.)
- Regular user ↔ Admin
- Unauthenticated ↔ Authenticated

**Questions to ask for each data flow:**
- Is this flow encrypted in transit?
- Who can initiate this flow?
- What validation happens at the receiving end?
- What's the worst case if this is compromised?

---

## Step 2 — Identify Entry Points

```bash
# All HTTP entry points
grep -rn "app\.\(get\|post\|put\|patch\|delete\)\|router\.\(get\|post\|put\|patch\|delete\)" \
  --include="*.ts" --include="*.js" . | grep -v node_modules

# WebSocket entry points
grep -rn "\.on('connection'\|\.on(\"connection\"" --include="*.ts" --include="*.js" . | grep -v node_modules

# Cron/scheduled jobs (no HTTP — but still process data)
grep -rn "cron\|schedule\|setInterval\|setTimeout.*\d{5,}" --include="*.ts" --include="*.js" . | grep -v node_modules

# Queue consumers
grep -rn "\.process\|\.consume\|onJob\|worker\." --include="*.ts" --include="*.js" . | grep -v node_modules

# Webhook receivers (external systems calling you)
grep -rn "webhook\|stripe\|github.*event\|sendgrid" --include="*.ts" --include="*.js" . | grep -v node_modules
```

---

## Step 3 — Apply STRIDE Per Entry Point

For each entry point, systematically ask:

**Spoofing:** Can someone pretend to be another user/service?
- Is auth checked before any logic runs?
- Is the JWT algorithm explicitly set?
- Are webhook payloads signature-verified?

**Tampering:** Can someone modify data in transit or at rest?
- Is HTTPS enforced?
- Are request parameters validated (type, range, length)?
- Can someone modify their own request to affect other users' data?

**Repudiation:** Can someone deny performing an action?
- Are security events logged with userId, IP, timestamp?
- Are logs tamper-evident (append-only, shipped to SIEM)?

**Information Disclosure:** What data leaks?
- What does the error response contain? (Stack trace? Email? Internal ID?)
- What's in the JWT payload? (Is sensitive PII in it?)
- Are API responses returning fields the user shouldn't see?

**Denial of Service:** Can this be overwhelmed?
- Is there a rate limit?
- Is there a maximum payload size?
- Are expensive operations (bcrypt, regex, N+1 queries) behind auth?

**Elevation of Privilege:** Can a low-privilege user do something they shouldn't?
- Is the role/permission check server-side?
- Can a user modify their own JWT claims?
- Are admin routes protected separately from user routes?

---

## Step 4 — High-Risk Architecture Patterns to Flag

### Insecure Direct Object Reference (IDOR)

```ts
// 🚩 Flag this pattern — user can access any record by ID
app.get('/api/orders/:id', requireAuth, async (req, res) => {
  const order = await db.order.findUnique({ where: { id: req.params.id } });
  res.json(order);
});

// ✅ Scoped to authenticated user
app.get('/api/orders/:id', requireAuth, async (req, res) => {
  const order = await db.order.findFirst({
    where: { id: req.params.id, userId: req.user.id },
  });
  if (!order) return res.status(404).json({ error: 'Not found' });
  res.json(order);
});
```

### Sensitive Data Returned Unnecessarily

```bash
# Find API responses that might return password hashes, secrets
grep -rn "res\.json\|res\.send" --include="*.ts" --include="*.js" . | grep -v node_modules
# Manually check: is passwordHash, mfaSecret, refreshToken, internalId in the response?
```

### Privilege Escalation via Role in JWT

```ts
// 🚩 Role comes from JWT — user can forge their own token payload
const { role } = jwt.decode(token); // NEVER trust decoded without verify
if (role === 'admin') { /* ... */ }

// ✅ Role comes from DB — JWT only contains userId
const { userId } = jwt.verify(token, secret, { algorithms: ['HS256'] });
const user = await db.user.findUnique({ where: { id: userId }, select: { role: true } });
if (user.role === 'admin') { /* ... */ }
```

---

## Step 5 — Document Findings in Architecture Terms

After threat modeling, output:

```
## Architecture Security Review

### Trust Boundaries Identified
- Public → API Server: [HTTPS enforced ✓ / Rate limited ✓ / Auth required on protected routes ✓]
- API Server → DB: [Connection string in env ✓ / Least privilege DB user? UNKNOWN]
- API Server → Stripe: [Webhook signature verified ✓]
- User → Admin: [Role check: DB-sourced ✓ / Separate middleware ✓]

### Threats Found (STRIDE)

[SPOOFING - HIGH] No webhook signature verification on GitHub webhooks (src/webhooks/github.ts:34)
[TAMPERING - MEDIUM] Order ID not scoped to user (src/routes/orders.ts:12) — IDOR risk
[INFORMATION DISCLOSURE - LOW] Stack trace exposed in dev-like error handler (src/middleware/error.ts:8)
[ELEVATION OF PRIVILEGE - CRITICAL] Role read from JWT payload, not DB (src/middleware/auth.ts:23)
```

---

## Threat Modeling Checklist

- [ ] Data flow diagram drawn (even rough)
- [ ] All entry points identified (HTTP, WS, queues, crons, webhooks)
- [ ] Trust boundaries marked
- [ ] STRIDE applied to each high-risk entry point
- [ ] IDOR checked on all resource routes
- [ ] Role/permission source verified (DB, not JWT payload)
- [ ] Webhook signature verification present for all external webhooks
- [ ] Sensitive data in responses audited
- [ ] Error responses checked for information leakage
