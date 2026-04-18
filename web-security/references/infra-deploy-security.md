# Infrastructure & Deploy Security

Source: OWASP Docker Security Cheat Sheet + cloud security best practices

---

## Scan — Infra Issues in the Codebase

```bash
# Check for hardcoded IPs, internal hostnames
grep -rn "localhost\|127\.0\.0\|192\.168\.\|10\.0\." \
  --include="*.ts" --include="*.js" --include="*.yaml" --include="*.yml" . \
  | grep -v node_modules | grep -v "test\|spec\|mock"

# Check Dockerfile exists and is secure
find . -name "Dockerfile" -o -name "docker-compose*.yml" | grep -v node_modules

# Check for secrets in docker-compose
grep -rn "password\|secret\|api_key" --include="docker-compose*.yml" . | grep -v node_modules

# Check for exposed ports
grep -rn "EXPOSE\|ports:" --include="Dockerfile" --include="docker-compose*.yml" . | grep -v node_modules
```

---

## Docker Security

### Secure Dockerfile

```dockerfile
# ✅ Use specific version tag — never 'latest' (unpredictable, unauditable)
FROM node:20.11.1-alpine3.19

# ✅ Run as non-root user — if container is compromised, attacker has no root
RUN addgroup -g 1001 -S nodejs && adduser -S nodeapp -u 1001 -G nodejs

WORKDIR /app

# ✅ Copy package files first — leverage layer caching
COPY package*.json ./

# ✅ Use npm ci (locked, reproducible) and omit devDependencies
RUN npm ci --only=production --ignore-scripts

# ✅ Copy application code
COPY --chown=nodeapp:nodejs . .

# ✅ Drop all Linux capabilities — app doesn't need any
RUN apk add --no-cache dumb-init

# Switch to non-root
USER nodeapp

# ✅ Use dumb-init for proper signal handling
ENTRYPOINT ["dumb-init", "--"]
CMD ["node", "dist/index.js"]

# ✅ Expose only the port you need
EXPOSE 3000

# ✅ Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
  CMD curl -f http://localhost:3000/health || exit 1
```

### Docker Compose — Never Use for Production Secrets

```yaml
# ❌ Never hardcode secrets in docker-compose
services:
  api:
    environment:
      - DATABASE_URL=postgresql://root:password123@db:5432/mydb  # ← NEVER

# ✅ Use external secrets or env file (never committed)
services:
  api:
    env_file:
      - .env  # in .gitignore
    # OR reference from secrets manager at deploy time
```

### Docker Security Scan

```bash
# Scan image for known CVEs
docker scout cves myapp:latest

# Or use Trivy (open source, excellent CVE database)
trivy image myapp:latest

# Check for secrets baked into image layers
docker history --no-trunc myapp:latest | grep -iE "password|secret|key|token"
```

---

## Kubernetes Security

### Pod Security Context

```yaml
apiVersion: apps/v1
kind: Deployment
spec:
  template:
    spec:
      # Run as non-root at pod level
      securityContext:
        runAsNonRoot: true
        runAsUser: 1001
        runAsGroup: 1001
        fsGroup: 1001
        seccompProfile:
          type: RuntimeDefault

      containers:
        - name: api
          image: myapp:1.2.3  # pinned tag
          securityContext:
            allowPrivilegeEscalation: false
            readOnlyRootFilesystem: true   # container can't write to its own FS
            capabilities:
              drop: ["ALL"]                # drop all Linux capabilities

          # Resource limits prevent DoS via resource exhaustion
          resources:
            requests:
              memory: "128Mi"
              cpu: "100m"
            limits:
              memory: "512Mi"
              cpu: "500m"

          # Liveness / readiness probes
          livenessProbe:
            httpGet:
              path: /health
              port: 3000
            initialDelaySeconds: 30
            periodSeconds: 10
```

### Kubernetes Secrets (Not in YAML)

```bash
# ❌ Never commit Secret manifests with real values
# ❌ Never use stringData with actual secrets in version control

# ✅ Use External Secrets Operator to sync from AWS/GCP/Vault
kubectl apply -f - <<EOF
apiVersion: external-secrets.io/v1beta1
kind: ExternalSecret
metadata:
  name: myapp-secrets
spec:
  refreshInterval: 1h
  secretStoreRef:
    name: aws-secrets-manager
    kind: SecretStore
  target:
    name: myapp-secrets
  data:
    - secretKey: DATABASE_URL
      remoteRef:
        key: myapp/production
        property: database_url
EOF
```

### Network Policies (Zero Trust in Cluster)

```yaml
# Deny all ingress by default, then allow only what's needed
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: api-network-policy
spec:
  podSelector:
    matchLabels:
      app: api
  policyTypes:
    - Ingress
    - Egress
  ingress:
    - from:
        - podSelector:
            matchLabels:
              app: nginx-ingress  # only ingress controller can reach API
      ports:
        - protocol: TCP
          port: 3000
  egress:
    - to:
        - podSelector:
            matchLabels:
              app: postgres       # only talk to DB pod
      ports:
        - protocol: TCP
          port: 5432
```

---

## CI/CD Pipeline Security

```yaml
# .github/workflows/security.yml
name: Security Checks

on: [push, pull_request]

jobs:
  security:
    runs-on: ubuntu-latest
    steps:
      # Secret scanning — catch credentials before they merge
      - uses: actions/checkout@v4
        with:
          fetch-depth: 0  # full history for secret scanning

      - name: Run Gitleaks (secret scanning)
        uses: gitleaks/gitleaks-action@v2
        env:
          GITHUB_TOKEN: ${{ secrets.GITHUB_TOKEN }}

      # SAST — static code analysis
      - name: Run Semgrep
        uses: semgrep/semgrep-action@v1
        with:
          config: >-
            p/nodejs
            p/security-audit
            p/owasp-top-ten
        env:
          SEMGREP_APP_TOKEN: ${{ secrets.SEMGREP_APP_TOKEN }}

      # Dependency audit
      - name: npm audit
        run: npm audit --audit-level=high

      # Container scanning
      - name: Build and scan image
        run: |
          docker build -t myapp:${{ github.sha }} .
          docker run --rm \
            -v /var/run/docker.sock:/var/run/docker.sock \
            aquasec/trivy:latest image \
            --exit-code 1 \
            --severity HIGH,CRITICAL \
            myapp:${{ github.sha }}
```

---

## TLS / HTTPS Configuration

```nginx
# nginx — TLS hardening
server {
    listen 443 ssl http2;
    server_name api.example.com;

    ssl_certificate /etc/ssl/certs/fullchain.pem;
    ssl_certificate_key /etc/ssl/private/privkey.pem;

    # TLS 1.2 minimum — TLS 1.3 preferred
    ssl_protocols TLSv1.2 TLSv1.3;

    # Strong cipher suites only (OWASP recommendation)
    ssl_ciphers 'ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384';
    ssl_prefer_server_ciphers off;  # Let client pick (TLS 1.3 handles this)

    # HSTS (must also be set in app headers via Helmet)
    add_header Strict-Transport-Security "max-age=31536000; includeSubDomains; preload" always;

    # OCSP Stapling — faster cert validation
    ssl_stapling on;
    ssl_stapling_verify on;

    # DH params (for TLS 1.2 key exchange)
    ssl_dhparam /etc/ssl/dhparam.pem;  # generate: openssl dhparam -out dhparam.pem 4096
}

# Redirect all HTTP to HTTPS
server {
    listen 80;
    return 301 https://$host$request_uri;
}
```

---

## Deploy Checklist

### Pre-Deploy
- [ ] `npm audit` passes (no high/critical)
- [ ] Secret scanning passes (Gitleaks/truffleHog clean)
- [ ] Semgrep SAST passes
- [ ] Container image scanned (Trivy clean)
- [ ] No `console.log` with sensitive data
- [ ] `.env` not committed (check with `git ls-files | grep .env`)

### Infrastructure
- [ ] Container runs as non-root user
- [ ] `readOnlyRootFilesystem: true` (or equivalent)
- [ ] Resource limits set (CPU + memory)
- [ ] Network policies restrict inter-service communication
- [ ] Secrets sourced from secret manager (not baked into image or k8s manifest)
- [ ] TLS 1.2+ with strong ciphers
- [ ] WAF in front of public endpoints (CloudFlare, AWS WAF)
- [ ] DDoS protection enabled at CDN level

### Post-Deploy
- [ ] Smoke test auth endpoints (login, token refresh, logout)
- [ ] Verify security headers with `curl -I https://your-api.com`
- [ ] `npm audit` in production image matches local (lockfile integrity)
- [ ] Monitoring alerts configured and tested
