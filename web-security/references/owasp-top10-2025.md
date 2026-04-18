# OWASP Top 10 — 2025 Edition

Source: https://owasp.org/www-project-top-ten/

> Note: The 2025 list reflects a reshuffling from 2021. Supply chain and misconfiguration moved up significantly.

---

## A01 — Broken Access Control

**What it is:** Users can act outside their intended permissions — access other users' data,
escalate privileges, view admin pages, perform unauthorized CRUD operations.

**Common patterns to look for in code:**
- Route protected by auth middleware, but no ownership check on the resource
- Sequential integer IDs in API paths (IDOR: `/api/orders/1042` → try `/api/orders/1041`)
- Admin routes without role check
- CORS misconfiguration allowing arbitrary origins
- `isAdmin` flag controlled by client-supplied parameter
- Missing function-level access control (frontend hides button, but backend allows the action)

**Scan:**
```bash
grep -rn "req\.params\.id\|req\.query\.id" --include="*.ts" --include="*.js" . | grep -v node_modules
# Manually verify each: is the query scoped to req.user.id?
```

**Fix:**
```ts
// Always scope to authenticated user — never trust a client-supplied user ID
const resource = await db.query(
  'SELECT * FROM orders WHERE id = $1 AND user_id = $2',
  [req.params.id, req.user.id]
);
if (!resource) return res.status(404).json({ error: 'Not found' });
```

---

## A02 — Security Misconfiguration

**What it is:** Insecure default configurations, incomplete setups, open cloud storage, verbose
error messages, unnecessary features enabled, missing security headers.

**Common patterns:**
- `X-Powered-By: Express` header revealing stack info
- Stack traces returned to clients on errors
- Default credentials not changed
- Debug mode enabled in production
- Open S3 buckets / GCS buckets
- CORS `Access-Control-Allow-Origin: *` on authenticated APIs

**Scan:**
```bash
grep -rn "debug.*true\|DEBUG.*=.*1\|app\.set.*trust proxy" --include="*.ts" --include="*.js" . | grep -v node_modules
grep -rn "err\.stack\|error\.stack" --include="*.ts" --include="*.js" . | grep -v node_modules
curl -I https://your-api.com | grep -i "x-powered-by\|server:"
```

**Fix:**
```ts
// Remove Express fingerprint
app.disable('x-powered-by'); // or use helmet() which does this automatically

// Safe error handler — no stack traces to client
app.use((err, req, res, next) => {
  logger.error({ err, path: req.path }); // log internally
  res.status(err.status || 500).json({
    error: process.env.NODE_ENV === 'production' ? 'Internal server error' : err.message,
  });
});
```

---

## A03 — Software and Supply Chain Failures (formerly "Vulnerable Components" — moved up)

**What it is:** Using components with known vulnerabilities, unverified packages, malicious
packages in the supply chain, compromised build pipelines.

**Common patterns:**
- Outdated packages with known CVEs
- No lockfile committed (`package-lock.json` / `yarn.lock`)
- `npm install` in CI (not `npm ci`) — can drift from lockfile
- No integrity checking of downloaded packages
- Broad `*` version ranges in `package.json`

**Scan:**
```bash
npm audit --audit-level=moderate
npm outdated
# Check for lockfile
ls package-lock.json yarn.lock bun.lockb 2>/dev/null
```

**Fix:**
```bash
# Always use npm ci in CI (respects lockfile, fails on drift)
npm ci --frozen-lockfile

# Keep lockfile committed
git add package-lock.json

# Enable Dependabot or Renovate for automatic PR updates
# .github/dependabot.yml
```

```yaml
# .github/dependabot.yml
version: 2
updates:
  - package-ecosystem: "npm"
    directory: "/"
    schedule:
      interval: "weekly"
    open-pull-requests-limit: 5
```

---

## A04 — Cryptographic Failures

**What it is:** Data transmitted or stored without adequate encryption. Weak algorithms, improper
key management, missing TLS, sensitive data in logs or URLs.

**Common patterns:**
- Passwords hashed with MD5 or SHA1 (not bcrypt/argon2)
- Sensitive data in URLs (leaks to logs, referrer headers)
- PII stored in plaintext
- HTTP instead of HTTPS
- Weak JWT secrets (short strings, dictionary words)
- Tokens/secrets in application logs

**Scan:**
```bash
grep -rn "md5\|sha1\|createHash.*md5\|createHash.*sha1" --include="*.ts" --include="*.js" . | grep -v node_modules
grep -rn "console\.log.*password\|console\.log.*token\|console\.log.*secret" --include="*.ts" --include="*.js" . | grep -v node_modules
```

**Fix:**
```ts
import bcrypt from 'bcrypt';
import argon2 from 'argon2';

// bcrypt — good default
const hash = await bcrypt.hash(password, 12); // cost factor 12+
const valid = await bcrypt.compare(password, hash);

// argon2 — better for new systems
const hash = await argon2.hash(password, { type: argon2.argon2id });
const valid = await argon2.verify(hash, password);
```

---

## A05 — Injection (SQL, NoSQL, OS, LDAP, SSRF)

**What it is:** Untrusted data sent to an interpreter as part of a command or query.

See `SKILL.md` Phase 3 for full scan commands and fixes.

**Quick summary:**
- SQL: always parameterized queries
- NoSQL: always validate type before passing to `find()`
- OS: never `exec()` with user input, use `spawn()` with arg array
- LDAP: use a library that escapes, never string-build LDAP queries
- SSRF: allowlist outbound hosts, block private IPs

---

## A06 — Insecure Design

**What it is:** Missing or ineffective control design — the threat wasn't modeled, the security
requirement wasn't written, or the design inherently enables abuse.

**This is harder to scan for with grep — it requires reading the logic:**
- Are there rate limits that prevent API abuse (credential stuffing, scraping)?
- Is there a maximum on things users can create (to prevent resource exhaustion)?
- Does the app reveal too much information in error messages?
- Are account recovery flows resistant to enumeration (do they reveal whether an email exists)?
- Is PII returned in API responses where it's not needed?

**Fix patterns:**
```ts
// Account enumeration prevention — same response whether email exists or not
app.post('/api/auth/forgot-password', async (req, res) => {
  const user = await db.user.findFirst({ where: { email: req.body.email } });
  if (user) {
    await sendPasswordResetEmail(user); // do this asynchronously
  }
  // Always return same response — never reveal whether email exists
  res.json({ message: 'If that email exists, you will receive a reset link.' });
});
```

---

## A07 — Authentication Failures

**What it is:** Broken or missing authentication. Weak passwords permitted, no account lockout,
sessions not properly invalidated, credential stuffing attacks succeed.

See `SKILL.md` Phase 6 for full JWT implementation.

**Checklist:**
- [ ] Rate limit on login (5 attempts/15min minimum)
- [ ] Account lockout or exponential backoff after failures
- [ ] Password complexity requirements enforced server-side
- [ ] Compromised password check (optional: HaveIBeenPwned API)
- [ ] Secure session invalidation on logout
- [ ] MFA available for sensitive accounts
- [ ] Sessions expire (don't live forever)

---

## A08 — Software or Data Integrity Failures

**What it is:** Code and infrastructure that doesn't protect against integrity violations. Insecure
deserialization, missing signature validation, CSRF, compromised CI/CD pipelines.

**Common patterns:**
- CSRF missing on session-authenticated endpoints
- No signature verification on incoming webhooks (Stripe, GitHub, Twilio all sign payloads)
- Deserializing untrusted data without validation (YAML/JSON with constructors)

**Fix — verify webhook signatures:**
```ts
// Stripe webhook signature verification
import Stripe from 'stripe';
const stripe = new Stripe(process.env.STRIPE_SECRET_KEY!);

app.post('/webhooks/stripe', express.raw({ type: 'application/json' }), (req, res) => {
  const sig = req.headers['stripe-signature'] as string;
  let event: Stripe.Event;
  try {
    event = stripe.webhooks.constructEvent(req.body, sig, process.env.STRIPE_WEBHOOK_SECRET!);
  } catch {
    return res.status(400).json({ error: 'Invalid signature' });
  }
  // process event...
  res.json({ received: true });
});
```

---

## A09 — Security Logging and Alerting Failures

**What it is:** Not logging security events, or logging them in a way that's incomplete,
unmonitored, or tampered with.

**What must be logged (with structured JSON):**
```ts
// Every auth event
logger.info({ event: 'login_success', userId, ip: req.ip, userAgent: req.headers['user-agent'] });
logger.warn({ event: 'login_failure', email: req.body.email, ip: req.ip });
logger.warn({ event: 'rate_limit_exceeded', ip: req.ip, endpoint: req.path });
logger.warn({ event: 'permission_denied', userId, resource: req.path, method: req.method });
logger.info({ event: 'token_refreshed', userId });
logger.info({ event: 'logout', userId });
```

**Never log:**
- Passwords (even hashed)
- Full JWT tokens
- Credit card numbers, SSNs, or any PII beyond what's needed for debugging
- API keys or secrets

**Scan:**
```bash
grep -rn "console\.log" --include="*.ts" --include="*.js" . | grep -v node_modules | grep -v test
# Every console.log in production code is a logging smell — use a structured logger
```

---

## A10 — Mishandling of Exceptional Conditions (new in 2025)

**What it is:** Race conditions, incomplete error handling, resource exhaustion, and other
exceptional conditions that attackers can exploit.

**Common patterns:**
- TOCTOU (Time-of-check-time-of-use) race conditions in critical operations
- Unhandled promise rejections crashing the server
- Missing transaction rollbacks leaving data inconsistent
- Memory leaks under sustained attack traffic

**Fix — global unhandled rejection handler:**
```ts
process.on('unhandledRejection', (reason, promise) => {
  logger.error({ event: 'unhandled_rejection', reason, promise });
  // Do NOT crash in production without investigation
});

process.on('uncaughtException', (err) => {
  logger.fatal({ event: 'uncaught_exception', err });
  process.exit(1); // exit and let process manager restart
});
```

**Fix — use DB transactions for multi-step operations:**
```ts
// Never do multi-step DB ops without a transaction
await prisma.$transaction(async (tx) => {
  const order = await tx.order.create({ data: orderData });
  await tx.inventory.update({ where: { id: item.id }, data: { stock: { decrement: 1 } } });
  await tx.payment.create({ data: { orderId: order.id, amount } });
  // If any step fails, all roll back — no partial state
});
```
