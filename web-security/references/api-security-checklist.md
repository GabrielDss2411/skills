# API Security Checklist

Source: https://github.com/shieldfy/API-Security-Checklist

A production-grade checklist for every API you ship. Use this during audit Phase recon to quickly
identify gaps. Each item is a concrete, verifiable control — not a vague recommendation.

---

## Authentication

- [ ] Never use Basic Auth — use standard protocols (OAuth2, OpenID Connect, JWT)
- [ ] Never roll your own auth crypto — use battle-tested libraries
- [ ] Use `max retry` + lockout on login (`MAX_LOGIN_ATTEMPTS`, exponential backoff)
- [ ] Encrypt all sensitive data in transit (TLS 1.2+) and at rest

## JWT Specifics

- [ ] Use a strong random secret (≥256 bits) — never hardcode
- [ ] Use HS256 or RS256 — explicitly specify algorithm, never allow `alg: none`
- [ ] Set short expiration on access tokens (`exp`, `iat` claims — 15m typical)
- [ ] Never store sensitive data in JWT payload — it's base64, not encrypted
- [ ] Validate `iss`, `aud`, `exp` claims on every verify

## OAuth

- [ ] Validate `redirect_uri` server-side against a strict allowlist
- [ ] Always exchange code for token server-side (never expose client_secret to browser)
- [ ] Use `state` parameter (random hash, stored in session) to prevent CSRF on OAuth flow
- [ ] Define and validate scopes — never issue more permission than requested
- [ ] Use short-lived access tokens; rotate refresh tokens on each use

---

## Access Control

- [ ] Rate limit all endpoints — use sliding window per IP + per API key
- [ ] Apply stricter limits to auth endpoints (login, register, reset-password)
- [ ] Enforce HTTPS — TLS 1.2 minimum, TLS 1.3 preferred; strong cipher suites
- [ ] Add HSTS header (`Strict-Transport-Security`)
- [ ] Disable directory listing on file servers
- [ ] Restrict private/admin APIs to whitelisted IPs or internal VPC only
- [ ] Use UUID v4 for resource IDs — never expose sequential integers (IDOR risk)
- [ ] Use `/me/orders` style routes — never `/users/{user_id}/orders` where user_id comes from client

---

## Input Validation

- [ ] Validate HTTP method matches operation (GET=read, POST=create, PUT=replace, PATCH=update, DELETE=remove)
- [ ] Validate `Content-Type` header — reject mismatches with 415
- [ ] Validate `Accept` header — return 406 for unsupported response formats
- [ ] Sanitize all user input against: XSS, SQL injection, NoSQL injection, LDAP injection, OS command injection
- [ ] Never trust client-provided IDs for ownership — always verify against authenticated user
- [ ] Never pass secrets/API keys in URL query strings — use `Authorization` header
- [ ] Disable XML external entity parsing (XXE) on any XML parser
- [ ] Limit XML/JSON payload size to prevent entity expansion attacks (XML bombs)

---

## Processing / Business Logic

- [ ] Verify authentication on **every** endpoint — no unintended anonymous access
- [ ] Avoid exposing user IDs in paths — use `/me/` self-referential endpoints
- [ ] Use UUIDs instead of auto-increment IDs (prevents resource enumeration)
- [ ] Handle file uploads via CDN/object storage — never serve them from app server
- [ ] Process heavy or time-consuming operations asynchronously via job queues
- [ ] Disable debug mode (`DEBUG=false`) in production — log to disk, not stdout
- [ ] Enable non-executable stack (OS-level) where supported

---

## Output

- [ ] `X-Content-Type-Options: nosniff` — prevents MIME sniffing
- [ ] `X-Frame-Options: deny` — prevents clickjacking
- [ ] `Content-Security-Policy: default-src 'none'` — strict baseline
- [ ] Remove `X-Powered-By`, `Server`, `X-AspNet-Version` headers — don't advertise stack
- [ ] Return correct `Content-Type` for all responses
- [ ] Return generic error messages to client — log details server-side only
- [ ] Never return credentials, tokens, or PII in response bodies unless explicitly required
- [ ] Use correct HTTP status codes — don't return 200 for errors

---

## CI/CD Security

- [ ] Automated test coverage including security-relevant paths (auth, permissions, input validation)
- [ ] Code review required — no self-approval of PRs
- [ ] Dependency scanning in CI (`npm audit`, Snyk, Dependabot)
- [ ] Secret scanning in CI — scan for accidentally committed keys (GitLeaks, truffleHog)
- [ ] SAST (Static Application Security Testing) in CI pipeline
- [ ] Rollback procedure documented and tested

---

## Monitoring & Alerting

- [ ] Centralized structured logging (include: timestamp, userId, IP, endpoint, status)
- [ ] Alert on anomalies: spike in 401/403s, unusual traffic patterns, new IPs on admin routes
- [ ] Never log sensitive data: passwords, tokens, PII, card numbers
- [ ] Deploy IDS/IPS or WAF in front of the API (CloudFlare, AWS WAF, ModSecurity)
- [ ] Correlate logs across services — use a request ID / trace ID header (`X-Request-ID`)

---

## Advanced / Production-Grade

### Rate Limiting Strategy
```
Sliding window per IP: 100 req/15min (general)
Sliding window per API key: 1000 req/hour
Auth endpoints: 5 failures/15min with lockout
Exponential backoff after threshold: 2s → 4s → 8s → 16s
```

### GraphQL-Specific
- [ ] Disable introspection in production (`introspection: false`)
- [ ] Set query depth limit (prevent deeply nested attack queries)
- [ ] Analyze query complexity cost — reject queries above threshold
- [ ] Rate limit by query cost, not just request count

### Secrets Management
- [ ] Rotate secrets regularly — automated where possible
- [ ] Use HSM (Hardware Security Module) for signing keys in high-security contexts
- [ ] Scan CI/CD pipeline artifacts for leaked secrets (GitLeaks pre-commit hook)
- [ ] Use short-lived tokens wherever possible — refresh > long-lived

### Zero Trust Architecture
- [ ] Implement mTLS between internal services
- [ ] Validate all requests even on internal network — don't trust the perimeter
- [ ] Use short-lived service tokens for inter-service auth
- [ ] Log and audit all service-to-service calls

---

## Severity Quick Reference

Use these during audit reporting:

| Finding | Severity |
|---------|----------|
| Hardcoded secret in source | CRITICAL |
| SQL injection | CRITICAL |
| No auth on protected route | CRITICAL |
| JWT `alg: none` accepted | CRITICAL |
| XSS via innerHTML | HIGH |
| No rate limiting on auth | HIGH |
| Sequential IDs (IDOR risk) | HIGH |
| Stack trace in response | HIGH |
| Missing CSRF on session auth | HIGH |
| No HSTS header | MEDIUM |
| Missing CSP | MEDIUM |
| `X-Powered-By` exposed | LOW |
| Overly verbose error messages | LOW |
