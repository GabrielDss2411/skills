# Performance Analysis Linked to Security

## Why Performance and Security Overlap

Several attack vectors exploit performance characteristics:
- **ReDoS** — regex that takes exponential time on crafted input
- **DoS via expensive operations** — bcrypt, image processing, XML parsing behind no-auth
- **Memory exhaustion** — unbounded payload sizes, large file uploads
- **Timing attacks** — comparing secrets with non-constant-time functions leaks information
- **N+1 query amplification** — GraphQL or REST that allows triggering hundreds of DB queries

---

## Scan — Performance-Security Vulnerabilities

```bash
# ReDoS: complex regexes with nested quantifiers
grep -rn "\.match(\|\.test(\|\.exec(\|new RegExp(" --include="*.ts" --include="*.js" . \
  | grep -v node_modules | grep -v "\.test\.\|\.spec\."
# Flag any regex with: (.+)+, (.*)+, (.{1,n})+, nested groups with quantifiers

# Expensive operations without auth gate
grep -rn "bcrypt\|sharp\|multer\|pdf\|xml\|jimp\|ffmpeg" \
  --include="*.ts" --include="*.js" . | grep -v node_modules
# Check: is each on a route with requireAuth?

# Missing payload size limits
grep -rn "express\.json\|bodyParser\|multer" --include="*.ts" --include="*.js" . | grep -v node_modules
# Check: is limit set? e.g. express.json({ limit: '1mb' })

# Timing-sensitive comparisons
grep -rn "=== \|== " --include="*.ts" --include="*.js" . | grep -v node_modules \
  | grep -iE "token|secret|hash|password|key|signature"
# Flag: if comparing secret strings with ===, that's a timing attack
```

---

## ReDoS (Regular Expression Denial of Service)

A malicious input can cause a vulnerable regex to run for minutes or forever.

**Vulnerable patterns:**
```ts
// ❌ Catastrophic backtracking — input like "aaaaaaaaaaaaaab" causes exponential time
/^(a+)+$/.test(userInput);
/(.*a){10}/.test(userInput);
/(\w+\s)+$/.test(userInput);

// The pattern: nested quantifiers on groups that can overlap = ReDoS
```

**Fix:**
```ts
// Option 1: Rewrite to linear regex (no nested quantifiers)
// Option 2: Use a safe regex library
npm install re2  // Google's RE2 — linear time guarantee, no catastrophic backtracking

import RE2 from 're2';
const safeRegex = new RE2('^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\\.[a-zA-Z]{2,}$');
safeRegex.test(userInput); // safe

// Option 3: Set a timeout on regex execution
import { setTimeout } from 'timers/promises';

async function safeMatch(pattern: RegExp, input: string, timeoutMs = 100): Promise<boolean> {
  const raceResult = await Promise.race([
    Promise.resolve(pattern.test(input)),
    setTimeout(timeoutMs).then(() => { throw new Error('Regex timeout'); }),
  ]);
  return raceResult as boolean;
}
```

**Check regexes with:**
```bash
# Static analysis tool for ReDoS
npx vuln-regex-detector --check "your-regex-here"
# Or use the safe-regex npm package
npx safe-regex "^(a+)+$"  # returns false if vulnerable
```

---

## Payload Size Limits

```ts
import express from 'express';
import multer from 'multer';

// JSON body: limit to 1MB (default is 100kb in older express)
app.use(express.json({ limit: '1mb' }));
app.use(express.urlencoded({ extended: true, limit: '1mb' }));

// File uploads: strict limits
const upload = multer({
  storage: multer.memoryStorage(),
  limits: {
    fileSize: 10 * 1024 * 1024,   // 10MB max per file
    files: 5,                       // max 5 files per request
    fields: 20,                     // max 20 non-file fields
    fieldSize: 1 * 1024 * 1024,    // 1MB per field value
  },
  fileFilter: (req, file, cb) => {
    const allowed = new Set(['image/jpeg', 'image/png', 'image/webp', 'application/pdf']);
    if (!allowed.has(file.mimetype)) {
      cb(new Error('File type not allowed'));
      return;
    }
    cb(null, true);
  },
});
```

---

## Timing Attacks — Constant-Time Comparison

When comparing secrets, tokens, or MACs, use constant-time comparison. String `===` short-circuits
at the first different character, leaking information about how much of the secret is correct.

```ts
import { timingSafeEqual, createHmac } from 'crypto';

// ❌ Vulnerable — timing leaks secret length and prefix
if (providedToken === expectedToken) { ... }

// ✅ Constant-time comparison — always takes the same time regardless of where mismatch is
function safeCompare(a: string, b: string): boolean {
  const bufA = Buffer.from(a);
  const bufB = Buffer.from(b);
  // Buffers must be same length — pad if needed
  if (bufA.length !== bufB.length) {
    // Still do a comparison to prevent length oracle
    timingSafeEqual(bufA, bufA);
    return false;
  }
  return timingSafeEqual(bufA, bufB);
}

// Use for: API keys, webhook signatures, CSRF tokens, reset tokens
if (!safeCompare(req.headers['x-webhook-signature'], expectedSig)) {
  return res.status(401).json({ error: 'Invalid signature' });
}
```

---

## Expensive Operations — Auth Gate First

Bcrypt, image processing, PDF parsing, and similar are expensive. Always authenticate before
allowing them, or attackers can use them as a free DDoS amplifier.

```ts
// ❌ Password hashing is expensive (that's the point) — but on unauthenticated route
app.post('/api/password-strength-check', async (req, res) => {
  const hash = await bcrypt.hash(req.body.password, 12); // ~100ms CPU per request, no auth
  res.json({ score: evaluateStrength(hash) });
});

// ✅ Either rate-limit heavily or gate with auth
app.post('/api/password-strength-check',
  rateLimit({ windowMs: 60_000, max: 10 }),  // strict rate limit
  async (req, res) => {
    // Use a cheap strength algorithm, not bcrypt
    const score = zxcvbn(req.body.password).score;
    res.json({ score });
  }
);

// File processing: auth + rate limit + async queue
app.post('/api/convert-pdf',
  requireAuth,
  rateLimit({ windowMs: 60_000, max: 5 }),
  upload.single('file'),
  async (req, res) => {
    // Queue the job — don't process synchronously
    const job = await queue.add('convert-pdf', { fileBuffer: req.file.buffer, userId: req.user.id });
    res.json({ jobId: job.id, status: 'queued' });
  }
);
```

---

## N+1 Query Attack (GraphQL / REST)

An endpoint that triggers N DB queries per item in a response can be exploited to amplify DB load.

```bash
# Find potential N+1 in GraphQL resolvers
grep -rn "findUnique\|findFirst\|findMany" --include="*.ts" --include="*.js" . | grep -v node_modules
# In resolvers, check: is this inside a list resolver? If so, it's probably N+1
```

**Fix — DataLoader batching:**

```bash
npm install dataloader
```

```ts
import DataLoader from 'dataloader';

// Create per-request loaders (new loader per request = proper batching)
const userLoader = new DataLoader(async (ids: readonly string[]) => {
  const users = await db.user.findMany({ where: { id: { in: [...ids] } } });
  // Return in same order as input ids
  return ids.map(id => users.find(u => u.id === id) ?? null);
});

// In resolver — DataLoader batches all calls within the same tick
const resolvers = {
  Post: {
    author: (post, _, context) => context.loaders.user.load(post.authorId),
    // All author loads in a single request are batched into ONE DB query
  },
};
```

---

## Request Timeout — Prevent Slow Loris

```ts
import timeout from 'connect-timeout';

// Abort requests that take too long (slow loris attack / hung connections)
app.use(timeout('30s'));

app.use((req, res, next) => {
  if (!req.timedout) next();
});

// Tighter timeout on auth endpoints
app.use('/api/auth', timeout('10s'));
```

---

## Performance-Security Checklist

- [ ] All regex tested for ReDoS (use RE2 or safe-regex check)
- [ ] Payload size limits on all body parsers and file upload handlers
- [ ] Constant-time comparison for all token/secret/signature checks
- [ ] Expensive ops (bcrypt, file processing, heavy computation) behind auth + rate limit
- [ ] DataLoader or equivalent batching for GraphQL resolvers
- [ ] Request timeout configured (prevent slow loris)
- [ ] Database connection pool size limited (prevent pool exhaustion under load)
- [ ] Circuit breaker for external service calls (prevent cascade failures)
