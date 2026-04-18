# Logging, Monitoring & SIEM Mindset

Source: OWASP Logging Cheat Sheet + SIEM best practices

## The SIEM Mindset

Security logging is not just "write to console". Think like a SOC analyst: every log entry must
answer *who did what, from where, when, and with what result* — so that anomalies are detectable,
incidents are reconstructable, and attackers can't hide.

**The three failure modes:**
1. Not logging security events at all
2. Logging but no one is watching (no alerts)
3. Logging PII/secrets (creates a new vulnerability)

---

## Scan — Logging Gaps

```bash
# Find all console.log in production code (should be using a structured logger)
grep -rn "console\.log\|console\.error\|console\.warn\|console\.debug" \
  --include="*.ts" --include="*.js" . | grep -v node_modules | grep -v "\.test\.\|\.spec\."

# Find auth events that should be logged
grep -rn "login\|signup\|register\|logout\|password\|token\|jwt\|session" \
  --include="*.ts" --include="*.js" . | grep -v node_modules | grep -v "test\|spec"
# For each hit: is there a logger.info/warn call nearby?

# Detect PII leaking into logs
grep -rn "logger\.\|log\." --include="*.ts" --include="*.js" . | grep -v node_modules \
  | grep -iE "password|secret|token|ssn|cpf|credit.card|card.number"
```

---

## Structured Logger Setup

Use a structured logger from day 1. `console.log` is not acceptable in production.

```bash
npm install pino pino-pretty  # fast, structured, production-ready
```

```ts
// src/lib/logger.ts
import pino from 'pino';

export const logger = pino({
  level: process.env.LOG_LEVEL ?? 'info',
  // In production: ship JSON logs to your SIEM
  // In development: pretty-print for readability
  transport: process.env.NODE_ENV !== 'production'
    ? { target: 'pino-pretty', options: { colorize: true } }
    : undefined,
  // Never log these fields — redact before shipping
  redact: {
    paths: ['req.headers.authorization', 'body.password', 'body.token', 'body.secret'],
    censor: '[REDACTED]',
  },
  base: {
    service: process.env.SERVICE_NAME ?? 'api',
    env: process.env.NODE_ENV,
  },
});
```

---

## Security Events — What Must Be Logged

Every security event must be logged as structured JSON with consistent fields:

```ts
// Standard security event structure
interface SecurityEvent {
  event: string;       // machine-readable event name
  userId?: string;     // who (never email/name — use ID)
  ip: string;          // where from
  userAgent?: string;  // what client
  timestamp: string;   // when (ISO 8601)
  success: boolean;    // outcome
  resource?: string;   // what was accessed
  reason?: string;     // why it failed (generic — not internal details)
}
```

**Authentication events:**

```ts
// Successful login
logger.info({
  event: 'auth.login.success',
  userId: user.id,
  ip: req.ip,
  userAgent: req.headers['user-agent'],
  mfaUsed: user.mfaEnabled,
});

// Failed login — log email hash (not plaintext) for correlation without PII
logger.warn({
  event: 'auth.login.failure',
  emailHash: crypto.createHash('sha256').update(email).digest('hex').slice(0, 16),
  ip: req.ip,
  reason: 'invalid_credentials', // never say "wrong password" or "user not found"
});

// Account lockout triggered
logger.warn({
  event: 'auth.account.locked',
  userId: user.id,
  ip: req.ip,
  failedAttempts: user.failedAttempts,
});

// Logout
logger.info({ event: 'auth.logout', userId: req.user.id, ip: req.ip });

// Password changed
logger.info({ event: 'auth.password.changed', userId: req.user.id, ip: req.ip });

// MFA enrolled / removed
logger.info({ event: 'auth.mfa.enrolled', userId: req.user.id, ip: req.ip });
logger.warn({ event: 'auth.mfa.removed', userId: req.user.id, ip: req.ip });

// Token refresh
logger.info({ event: 'auth.token.refreshed', userId: req.user.id });

// Suspicious: token reuse detected
logger.error({
  event: 'auth.token.reuse_detected',
  userId: req.user.id,
  ip: req.ip,
  action: 'all_sessions_invalidated',
});
```

**Authorization events:**

```ts
// Permission denied
logger.warn({
  event: 'authz.denied',
  userId: req.user?.id ?? 'anonymous',
  ip: req.ip,
  resource: req.path,
  method: req.method,
  requiredRole: 'admin',
  userRole: req.user?.role,
});

// Admin action
logger.info({
  event: 'admin.action',
  adminId: req.user.id,
  action: 'user.delete',
  targetId: req.params.id,
  ip: req.ip,
});
```

**Rate limit & abuse events:**

```ts
logger.warn({
  event: 'security.rate_limit',
  ip: req.ip,
  endpoint: req.path,
  limit: 5,
  windowMs: 900000,
});

logger.error({
  event: 'security.scan_detected',
  ip: req.ip,
  pattern: 'sequential_id_enumeration',
  requestCount: consecutiveRequests,
});
```

---

## Express Request Logging Middleware

```ts
import { randomUUID } from 'crypto';

// Assign a trace ID to every request — essential for correlating events in SIEM
app.use((req, res, next) => {
  req.traceId = req.headers['x-request-id'] as string ?? randomUUID();
  res.setHeader('X-Request-ID', req.traceId);
  next();
});

// Log every request (HTTP access log)
app.use((req, res, next) => {
  const start = Date.now();
  res.on('finish', () => {
    // Don't log health check endpoints (noise)
    if (req.path === '/health') return;

    const level = res.statusCode >= 500 ? 'error'
      : res.statusCode >= 400 ? 'warn'
      : 'info';

    logger[level]({
      event: 'http.request',
      traceId: req.traceId,
      method: req.method,
      path: req.path,
      statusCode: res.statusCode,
      durationMs: Date.now() - start,
      ip: req.ip,
      userId: (req as any).user?.id,
    });
  });
  next();
});
```

---

## Alerting Rules (SIEM Mindset)

Define what should trigger an alert — not every log, just anomalies:

```
CRITICAL ALERTS (page on-call immediately):
- event = 'auth.token.reuse_detected'                  → possible account takeover
- event = 'auth.account.locked' AND count > 50/hour    → credential stuffing attack
- event = 'authz.denied' AND userId = admin            → privilege escalation attempt
- statusCode = 500 AND count > 100/5min                → application error spike
- event = 'security.scan_detected'                     → active enumeration

HIGH ALERTS (notify security team, next business day):
- event = 'auth.login.failure' AND same IP > 20/hour   → brute force
- event = 'auth.mfa.removed' AND no prior disable-mfa  → account compromise indicator
- event = 'admin.action' outside business hours         → suspicious admin activity
- New IP for existing user after long absence           → account sharing or takeover

MEDIUM ALERTS (weekly review):
- event = 'security.rate_limit' from new IP ranges
- Spike in 401/403 errors on specific endpoint
- Unusual geographic access patterns
```

---

## What to NEVER Log

```ts
// ❌ Never log these — they create a secondary vulnerability
logger.info({ password: req.body.password });     // plaintext password in logs
logger.info({ token: req.body.refreshToken });    // token in logs = session hijack
logger.info({ email: user.email });               // PII — use userId instead
logger.info({ creditCard: req.body.card });       // PCI violation
logger.error(err.stack);                          // stack trace to log is OK; to client is not

// ✅ Safe alternatives
logger.info({ userId: user.id });
logger.warn({ emailHash: hash(email).slice(0,16) }); // for correlation without PII
logger.error({ event: 'payment.failed', orderId, reason: 'insufficient_funds' });
```

---

## Log Retention & Integrity

- **Retention:** Minimum 90 days hot (searchable), 1 year cold (archived) for most apps
- **Regulatory:** LGPD/GDPR: access to personal data must be logged. PCI: 12 months minimum
- **Tamper-resistance:** Ship logs to a write-only sink (S3, CloudWatch, Elastic) from app — the app server should not be able to delete logs
- **Correlation:** All services must use the same `traceId` / `requestId` header for distributed tracing

```bash
# CloudWatch log group (never expires by default — set retention)
aws logs put-retention-policy \
  --log-group-name /myapp/production \
  --retention-in-days 365
```

---

## Monitoring Stack Options

| Stack | Best for | Key tools |
|-------|----------|-----------|
| ELK (Elastic + Logstash + Kibana) | Self-hosted, full control | Beats shipper, Kibana dashboards |
| Grafana + Loki | Cost-efficient, metrics + logs | Promtail for log shipping |
| Datadog | Enterprise, built-in anomaly detection | APM + logs + security monitoring |
| AWS CloudWatch | AWS-native, minimal ops | CloudWatch Insights, Metric Alarms |
| Sentry | Error tracking + performance | `@sentry/node` SDK |

**Minimum viable monitoring for any app:**
1. Structured JSON logs shipped to persistent store (not just stdout)
2. Alert on error rate spike (5xx > threshold)
3. Alert on auth failure spike
4. Alert on response latency spike (p99 > 2s)
