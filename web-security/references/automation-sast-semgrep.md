# Security Automation — SAST, Semgrep, ESLint, CI/CD

## The Automation Philosophy

Manual code review doesn't scale. Automate the mechanical checks so human review can focus on
logic flaws, business context, and architectural risks. The goal: catch 80% of common vulnerabilities
before code reaches review.

---

## Semgrep — SAST (Static Application Security Testing)

Semgrep is the best open-source SAST tool for Node.js/TypeScript. It finds real code patterns,
not just keywords — it understands AST and data flow.

### Quick Setup

```bash
# Install
pip install semgrep
# or
brew install semgrep

# Run against current project
semgrep --config "p/nodejs" --config "p/security-audit" --config "p/owasp-top-ten" .

# Run with auto (Semgrep's recommended ruleset)
semgrep --config "auto" .

# Output formats
semgrep --config "p/nodejs" --json . > semgrep-results.json
semgrep --config "p/nodejs" --sarif . > semgrep-results.sarif  # for GitHub Security tab
```

### Useful Rulesets for Node.js

```bash
# Core security rules
semgrep --config "p/nodejs"              # Node.js-specific patterns
semgrep --config "p/security-audit"      # Generic security audit
semgrep --config "p/owasp-top-ten"       # OWASP Top 10 coverage
semgrep --config "p/typescript"          # TypeScript patterns
semgrep --config "p/express"             # Express.js specific
semgrep --config "p/jwt"                 # JWT misuse patterns
semgrep --config "p/sql-injection"       # SQL injection patterns
semgrep --config "p/xss"                 # XSS patterns

# Run all relevant at once
semgrep \
  --config "p/nodejs" \
  --config "p/security-audit" \
  --config "p/owasp-top-ten" \
  --config "p/express" \
  --config "p/jwt" \
  --exclude "node_modules,dist,build,*.test.ts,*.spec.ts" \
  --error \
  .
```

### Custom Semgrep Rules

Write project-specific rules for patterns you know are dangerous in your codebase:

```yaml
# .semgrep/custom-rules.yaml
rules:
  # Catch raw req.params usage without validation
  - id: unvalidated-route-param
    patterns:
      - pattern: |
          app.$METHOD($ROUTE, ..., async ($REQ, $RES) => {
            ...
            $REQ.params.$PARAM
            ...
          })
      - pattern-not-inside: |
          $SCHEMA.validate(...)
    message: Route parameter $PARAM used without Joi/Zod validation
    severity: WARNING
    languages: [typescript, javascript]
    metadata:
      category: security
      owasp: A03:2021 - Injection

  # Catch direct DB queries with string interpolation
  - id: sql-injection-string-concat
    pattern: $DB.query(`...${...}...`)
    message: SQL query uses template literal interpolation — use parameterized query instead
    severity: ERROR
    languages: [typescript, javascript]

  # Catch JWT decode without verify
  - id: jwt-decode-without-verify
    pattern: jwt.decode($TOKEN)
    pattern-not-inside: jwt.verify(...)
    message: jwt.decode() does not verify signature — use jwt.verify() instead
    severity: ERROR
    languages: [typescript, javascript]

  # Catch eval() usage
  - id: no-eval
    pattern: eval(...)
    message: eval() is a code injection risk — never use with user input
    severity: ERROR
    languages: [typescript, javascript]
```

```bash
# Run custom rules
semgrep --config ".semgrep/custom-rules.yaml" .
```

---

## ESLint Security Plugins

Add security linting to your existing ESLint setup — catches issues at save time in the editor.

```bash
npm install --save-dev \
  eslint-plugin-security \
  eslint-plugin-no-secrets \
  eslint-plugin-node
```

```js
// .eslintrc.js
module.exports = {
  plugins: ['security', 'no-secrets'],
  extends: [
    'plugin:security/recommended',
  ],
  rules: {
    // Detect potential security issues
    'security/detect-object-injection': 'warn',
    'security/detect-non-literal-regexp': 'warn',
    'security/detect-non-literal-require': 'warn',
    'security/detect-possible-timing-attacks': 'error',
    'security/detect-eval-with-expression': 'error',
    'security/detect-new-buffer': 'error',
    'security/detect-unsafe-regex': 'error',       // ReDoS detection
    'security/detect-child-process': 'warn',
    'security/detect-disable-mustache-escape': 'error',

    // Secret detection in code
    'no-secrets/no-secrets': ['error', { tolerance: 4.2 }],

    // No console.log in production (use structured logger)
    'no-console': process.env.NODE_ENV === 'production' ? 'error' : 'warn',
  },
};
```

---

## Pre-Commit Hooks (Gitleaks + lint-staged)

Catch secrets and linting issues before they're committed:

```bash
npm install --save-dev lint-staged husky
npx husky init

# Install Gitleaks for secret scanning
# Mac: brew install gitleaks
# Linux: see https://github.com/gitleaks/gitleaks#installing
```

```json
// package.json
{
  "lint-staged": {
    "*.{ts,tsx,js,jsx}": [
      "eslint --fix --max-warnings=0",
      "semgrep --config p/security-audit --error"
    ]
  }
}
```

```bash
# .husky/pre-commit
#!/bin/sh
# Scan for secrets before every commit
gitleaks protect --staged --config .gitleaks.toml

# Run lint-staged
npx lint-staged
```

```toml
# .gitleaks.toml
[allowlist]
  description = "Global allowlist"
  regexes = [
    "EXAMPLE_KEY",   # add false-positive patterns here
  ]
  paths = [
    ".gitleaks.toml",
    "*.test.ts",
    "*.spec.ts",
    "*.mock.ts",
  ]
```

---

## GitHub Actions — Full Security Pipeline

```yaml
# .github/workflows/security.yml
name: Security

on:
  push:
    branches: [main, develop]
  pull_request:

permissions:
  contents: read
  security-events: write  # for SARIF upload

jobs:
  sast:
    name: Static Analysis
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - uses: actions/setup-node@v4
        with:
          node-version: '20'

      - run: npm ci --frozen-lockfile

      # Dependency audit
      - name: npm audit
        run: npm audit --audit-level=high

      # ESLint security rules
      - name: ESLint
        run: npx eslint . --ext .ts,.tsx,.js --max-warnings=0

      # Semgrep SAST
      - name: Semgrep
        uses: semgrep/semgrep-action@v1
        with:
          config: >-
            p/nodejs
            p/security-audit
            p/owasp-top-ten
            p/express
            p/jwt
          generateSarif: "1"
        env:
          SEMGREP_APP_TOKEN: ${{ secrets.SEMGREP_APP_TOKEN }}

      # Upload to GitHub Security tab
      - name: Upload SARIF
        uses: github/codeql-action/upload-sarif@v3
        with:
          sarif_file: semgrep.sarif
        if: always()

  secrets:
    name: Secret Scanning
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
        with:
          fetch-depth: 0

      - name: Gitleaks
        uses: gitleaks/gitleaks-action@v2
        env:
          GITHUB_TOKEN: ${{ secrets.GITHUB_TOKEN }}

  # Run type-check (catches some security issues via type safety)
  typecheck:
    name: TypeScript Check
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - run: npm ci
      - run: npx tsc --noEmit
```

---

## npm audit — Interpreting Results

```bash
# Basic audit
npm audit

# Only show high and critical
npm audit --audit-level=high

# JSON output for parsing
npm audit --json | jq '.vulnerabilities | to_entries[] | select(.value.severity == "critical")'

# Auto-fix what's safe (non-breaking)
npm audit fix

# Fix including breaking changes (review diff carefully)
npm audit fix --force

# Check specific package
npm audit --json | jq '.vulnerabilities.lodash'
```

**When npm audit finds issues:**

1. **Direct dependency with CVE:** Update or replace it. This is your responsibility.
2. **Transitive dependency:** Check if the vulnerable code path is reachable in your app.
   - If yes: pressure the direct dependency to update, or patch via `npm-force-resolutions`
   - If no: add an override in `package.json` and document why

```json
// package.json — force specific transitive version
{
  "overrides": {
    "vulnerable-package": ">=2.0.0"
  }
}
```

---

## Security Automation Stack — Recommended Setup

| Layer | Tool | When it runs |
|-------|------|-------------|
| Editor | ESLint security plugin | On save / on type |
| Pre-commit | Gitleaks + lint-staged | Before every commit |
| CI (PR) | Semgrep + npm audit | On every PR |
| CI (PR) | Gitleaks (full history) | On every PR |
| CI (merge) | Trivy (container scan) | On merge to main |
| CI (scheduled) | Dependabot / Renovate | Weekly |
| Runtime | Sentry / Datadog | Always in production |

This stack catches:
- Secrets in code (Gitleaks)
- Known CVEs in dependencies (npm audit, Trivy, Dependabot)
- Insecure code patterns (Semgrep, ESLint)
- Runtime errors and anomalies (Sentry, Datadog)
