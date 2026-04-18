# Helmet.js Reference

Source: https://helmetjs.github.io/

## Overview

Helmet sets **13 HTTP security headers** with a single middleware call. It's the baseline security
layer for any Express app — apply it before all routes.

```bash
npm install helmet
```

```ts
import helmet from 'helmet';
app.use(helmet()); // applies all 13 headers with safe defaults
```

---

## Headers Set by Default

| Header | Default Value | Purpose |
|--------|---------------|---------|
| `Content-Security-Policy` | `default-src 'self'; ...` | Restricts resource origins — primary XSS mitigation at HTTP layer |
| `Strict-Transport-Security` | `max-age=31536000; includeSubDomains` | Forces HTTPS for 1 year |
| `X-Frame-Options` | `SAMEORIGIN` | Prevents clickjacking |
| `X-Content-Type-Options` | `nosniff` | Prevents MIME sniffing attacks |
| `X-DNS-Prefetch-Control` | `off` | Disables DNS prefetching |
| `Referrer-Policy` | `no-referrer` | Prevents referrer leakage |
| `X-XSS-Protection` | `0` | Disables legacy IE XSS filter (modern browsers use CSP instead) |
| `Origin-Agent-Cluster` | `?1` | Isolates browsing contexts |
| `Cross-Origin-Opener-Policy` | `same-origin` | Prevents cross-origin window access |
| `Cross-Origin-Resource-Policy` | `same-origin` | Blocks cross-origin resource reads |
| `Cross-Origin-Embedder-Policy` | `require-corp` | Requires CORP on embedded resources |
| `X-Permitted-Cross-Domain-Policies` | `none` | Blocks Adobe Flash/PDF cross-domain |
| `X-Download-Options` | `noopen` | Prevents IE from opening downloaded files directly |

---

## Full Configuration Reference

```ts
app.use(helmet({
  // Content Security Policy — customize per your CDN/font/analytics needs
  contentSecurityPolicy: {
    directives: {
      defaultSrc: ["'self'"],
      scriptSrc: ["'self'"],                          // add CDN hashes or nonces here
      scriptSrcAttr: ["'none'"],
      styleSrc: ["'self'", "'unsafe-inline'"],        // remove unsafe-inline if you can use nonces
      imgSrc: ["'self'", "data:", "https:"],
      connectSrc: ["'self'"],
      fontSrc: ["'self'", "https:", "data:"],
      objectSrc: ["'none'"],                          // block plugins
      mediaSrc: ["'self'"],
      frameSrc: ["'none'"],                           // block iframes
      baseUri: ["'self'"],                            // prevent base tag injection
      formAction: ["'self'"],                         // restrict form targets
      frameAncestors: ["'none'"],                     // clickjacking protection
      upgradeInsecureRequests: [],                    // auto-upgrade HTTP→HTTPS
    },
    reportOnly: false, // set true during rollout to monitor without blocking
  },

  // HSTS — once set, hard to undo; test on staging first
  hsts: {
    maxAge: 31536000,       // 1 year in seconds
    includeSubDomains: true,
    preload: true,          // only set if submitting to HSTS preload list
  },

  // Disable individual headers if needed
  xFrameOptions: { action: 'deny' }, // or 'sameorigin'
  xContentTypeOptions: true,         // set false to disable
  referrerPolicy: { policy: 'strict-origin-when-cross-origin' },

  // Cross-origin isolation (required for SharedArrayBuffer, high-res timers)
  crossOriginEmbedderPolicy: { policy: 'require-corp' },
  crossOriginOpenerPolicy: { policy: 'same-origin' },
  crossOriginResourcePolicy: { policy: 'same-origin' },
}));
```

---

## CSP Nonce Pattern (recommended over 'unsafe-inline')

```ts
import { randomBytes } from 'crypto';

app.use((req, res, next) => {
  res.locals.cspNonce = randomBytes(16).toString('hex');
  next();
});

app.use(
  helmet({
    contentSecurityPolicy: {
      directives: {
        scriptSrc: ["'self'", (req, res) => `'nonce-${(res as any).locals.cspNonce}'`],
      },
    },
  })
);

// In your template: <script nonce="<%= cspNonce %>">
```

---

## Development Caveats

Some headers break local development:
- `upgrade-insecure-requests` — blocks HTTP on localhost → disable in dev
- `hsts` — once set, browser enforces HTTPS even after you remove the header → skip on localhost
- `crossOriginEmbedderPolicy` — can break loading external resources like Google Fonts

```ts
app.use(helmet({
  contentSecurityPolicy: process.env.NODE_ENV === 'production'
    ? { directives: { upgradeInsecureRequests: [] } }
    : false,
  hsts: process.env.NODE_ENV === 'production'
    ? { maxAge: 31536000, includeSubDomains: true }
    : false,
}));
```

---

## Using Individual Middleware

Each header has a standalone export if you need granular control:

```ts
import {
  contentSecurityPolicy,
  hsts,
  xFrameOptions,
  xContentTypeOptions,
} from 'helmet';

app.use(contentSecurityPolicy({ directives: { defaultSrc: ["'self'"] } }));
app.use(hsts({ maxAge: 31536000 }));
```
