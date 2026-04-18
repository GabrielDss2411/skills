# Modern Authentication — MFA, Password Policy, Account Lockout, OAuth

## Password Policy (Server-Side Enforcement)

Never enforce password policy only on the frontend. All rules must be validated server-side.

```ts
import Joi from 'joi';
import { createClient } from '@haveibeenpwned/client'; // optional but recommended

const passwordSchema = Joi.string()
  .min(12)                            // 12+ chars minimum (NIST 800-63B recommendation)
  .max(128)                           // avoid DoS from massive bcrypt input
  .pattern(/[A-Z]/, 'uppercase')
  .pattern(/[a-z]/, 'lowercase')
  .pattern(/[0-9]/, 'digit')
  .pattern(/[@$!%*?&^#()_+\-=]/, 'special')
  .required();

// Check against HaveIBeenPwned corpus (k-anonymity API — password never sent in full)
async function isPasswordPwned(password: string): Promise<boolean> {
  const crypto = await import('crypto');
  const hash = crypto.createHash('sha1').update(password).digest('hex').toUpperCase();
  const prefix = hash.slice(0, 5);
  const suffix = hash.slice(5);

  const res = await fetch(`https://api.pwnedpasswords.com/range/${prefix}`);
  const text = await res.text();
  return text.includes(suffix);
}

// In registration handler
const pwned = await isPasswordPwned(password);
if (pwned) {
  return res.status(400).json({
    error: 'This password has appeared in a data breach. Please choose a different one.'
  });
}
```

---

## Account Lockout — Real Implementation

Lockout state must be server-side (DB or Redis). Client-only lockout is bypassed trivially.

```ts
// Schema (Prisma example):
// model LoginAttempt {
//   id        String   @id @default(uuid())
//   userId    String
//   ip        String
//   success   Boolean
//   createdAt DateTime @default(now())
// }
//
// model User {
//   lockedUntil DateTime?
//   failedAttempts Int @default(0)
// }

const MAX_ATTEMPTS = 5;
const LOCKOUT_DURATION_MS = 15 * 60 * 1000; // 15 minutes
const WINDOW_MS = 15 * 60 * 1000;

async function handleLogin(req: Request, res: Response) {
  const { email, password } = req.body;

  const user = await db.user.findUnique({ where: { email } });

  // Always run bcrypt compare even if user not found — prevent timing-based enumeration
  const dummyHash = '$2b$12$invalidhashpadding000000000000000000000000000000000000000';
  const hash = user?.passwordHash ?? dummyHash;

  // Check lockout before attempting compare
  if (user?.lockedUntil && user.lockedUntil > new Date()) {
    return res.status(429).json({
      error: 'Account temporarily locked. Try again later.',
      retryAfter: Math.ceil((user.lockedUntil.getTime() - Date.now()) / 1000),
    });
  }

  const valid = await bcrypt.compare(password, hash);

  // Log attempt regardless of outcome
  await db.loginAttempt.create({
    data: { userId: user?.id ?? 'unknown', ip: req.ip, success: valid && !!user },
  });

  if (!valid || !user) {
    if (user) {
      const newCount = user.failedAttempts + 1;
      await db.user.update({
        where: { id: user.id },
        data: {
          failedAttempts: newCount,
          lockedUntil: newCount >= MAX_ATTEMPTS
            ? new Date(Date.now() + LOCKOUT_DURATION_MS)
            : null,
        },
      });

      // Alert security team on repeated failures
      if (newCount >= MAX_ATTEMPTS) {
        await notifySecurityTeam({ userId: user.id, ip: req.ip, event: 'account_locked' });
      }
    }

    // Constant-time response — don't reveal whether email exists
    return res.status(401).json({ error: 'Invalid credentials' });
  }

  // Successful login — reset counters
  await db.user.update({
    where: { id: user.id },
    data: { failedAttempts: 0, lockedUntil: null },
  });

  const tokens = await issueTokens(user.id);
  res.json(tokens);
}
```

---

## MFA / 2FA — TOTP Implementation

Time-based One-Time Passwords (TOTP) — compatible with Google Authenticator, Authy, 1Password.

```bash
npm install speakeasy qrcode
```

```ts
import speakeasy from 'speakeasy';
import QRCode from 'qrcode';

// Step 1: Generate secret on MFA setup
app.post('/api/auth/mfa/setup', requireAuth, async (req, res) => {
  const secret = speakeasy.generateSecret({
    name: `YourApp (${req.user.email})`,
    length: 32,
  });

  // Store secret temporarily (not confirmed yet)
  await db.user.update({
    where: { id: req.user.userId },
    data: { mfaSecretTemp: secret.base32 }, // confirmed after first successful verify
  });

  const qrCodeUrl = await QRCode.toDataURL(secret.otpauth_url!);
  res.json({ qrCode: qrCodeUrl, secret: secret.base32 }); // show QR + manual entry key
});

// Step 2: Confirm setup by verifying first code
app.post('/api/auth/mfa/confirm', requireAuth, async (req, res) => {
  const { token } = req.body;
  const user = await db.user.findUnique({ where: { id: req.user.userId } });

  const valid = speakeasy.totp.verify({
    secret: user!.mfaSecretTemp!,
    encoding: 'base32',
    token,
    window: 1, // allow 30s clock drift
  });

  if (!valid) return res.status(400).json({ error: 'Invalid code' });

  // Generate backup codes (store hashed)
  const backupCodes = Array.from({ length: 8 }, () =>
    crypto.randomBytes(5).toString('hex')
  );

  await db.user.update({
    where: { id: req.user.userId },
    data: {
      mfaSecret: user!.mfaSecretTemp,
      mfaSecretTemp: null,
      mfaEnabled: true,
      mfaBackupCodes: await Promise.all(backupCodes.map(c => bcrypt.hash(c, 10))),
    },
  });

  res.json({ backupCodes }); // show ONCE — user must save them
});

// Step 3: Verify TOTP on login (after password check)
app.post('/api/auth/mfa/verify', requirePartialAuth, async (req, res) => {
  const { token } = req.body;
  const user = await db.user.findUnique({ where: { id: req.user.userId } });

  if (!user?.mfaEnabled || !user.mfaSecret) {
    return res.status(400).json({ error: 'MFA not configured' });
  }

  const valid = speakeasy.totp.verify({
    secret: user.mfaSecret,
    encoding: 'base32',
    token,
    window: 1,
  });

  if (!valid) {
    // Also check backup codes
    const backupMatch = await Promise.any(
      user.mfaBackupCodes.map(async (hash, index) => {
        if (await bcrypt.compare(token, hash)) return index;
        throw new Error('no match');
      })
    ).catch(() => -1);

    if (backupMatch === -1) {
      return res.status(401).json({ error: 'Invalid MFA code' });
    }

    // Invalidate used backup code
    const newCodes = [...user.mfaBackupCodes];
    newCodes.splice(backupMatch, 1);
    await db.user.update({ where: { id: user.id }, data: { mfaBackupCodes: newCodes } });
  }

  const tokens = await issueTokens(user.id);
  res.json(tokens);
});
```

---

## OAuth 2.0 / Social Login (Google, GitHub, etc.)

Use `passport.js` or a dedicated library — never implement OAuth yourself.

```bash
npm install passport passport-google-oauth20 passport-github2
```

```ts
import passport from 'passport';
import { Strategy as GoogleStrategy } from 'passport-google-oauth20';

passport.use(new GoogleStrategy({
  clientID: process.env.GOOGLE_CLIENT_ID!,
  clientSecret: process.env.GOOGLE_CLIENT_SECRET!,
  callbackURL: process.env.GOOGLE_CALLBACK_URL!, // e.g. https://app.example.com/auth/google/callback
  scope: ['profile', 'email'],
}, async (accessToken, refreshToken, profile, done) => {
  // Never trust the email without verifying it's verified
  const email = profile.emails?.[0];
  if (!email?.verified) return done(new Error('Email not verified by provider'));

  // Upsert user — link Google ID to existing account if email matches
  const user = await db.user.upsert({
    where: { googleId: profile.id },
    update: { lastLoginAt: new Date() },
    create: {
      googleId: profile.id,
      email: email.value,
      name: profile.displayName,
      emailVerified: true, // provider already verified
    },
  });

  done(null, user);
}));

// Routes
app.get('/auth/google', passport.authenticate('google'));

app.get('/auth/google/callback',
  passport.authenticate('google', { session: false, failureRedirect: '/login?error=oauth_failed' }),
  async (req, res) => {
    const user = req.user as User;
    const tokens = await issueTokens(user.id);

    // Redirect with token — use short-lived code exchangeable for token (more secure)
    const code = await createOneTimeCode(user.id);
    res.redirect(`${process.env.FRONTEND_URL}/auth/callback?code=${code}`);
  }
);
```

**Security requirements for OAuth:**
- [ ] `redirect_uri` must be a strict allowlist — never dynamic
- [ ] Use `state` parameter (random, stored in session) to prevent CSRF on OAuth callback
- [ ] Verify email is confirmed by the provider before trusting it
- [ ] Never store provider `accessToken` unless you actually need it for provider API calls
- [ ] Use short-lived one-time codes for the callback redirect (avoid tokens in URLs)

---

## Session Security

```ts
import session from 'express-session';
import connectPgSimple from 'connect-pg-simple';

const PgSession = connectPgSimple(session);

app.use(session({
  store: new PgSession({ conString: process.env.DATABASE_URL }),
  secret: process.env.SESSION_SECRET!,
  name: '__session',          // avoid revealing technology (don't use 'connect.sid')
  resave: false,
  saveUninitialized: false,
  cookie: {
    httpOnly: true,           // JS can't read
    secure: true,             // HTTPS only
    sameSite: 'strict',       // no cross-site requests
    maxAge: 24 * 60 * 60 * 1000, // 24h
  },
}));

// Regenerate session ID after login to prevent session fixation
app.post('/api/auth/login', async (req, res) => {
  // ... validate credentials ...
  req.session.regenerate((err) => {  // new session ID
    if (err) return next(err);
    req.session.userId = user.id;
    res.json({ success: true });
  });
});
```

---

## MFA Audit Checklist

- [ ] TOTP secret stored encrypted in DB (not plaintext)
- [ ] Backup codes generated, shown once, stored hashed
- [ ] Rate limit on MFA verify endpoint (brute-force 6-digit codes is fast)
- [ ] Backup code usage invalidates the used code immediately
- [ ] Account recovery flow requires identity verification (not just email)
- [ ] MFA bypass via account recovery is not possible without additional verification
- [ ] Clock drift tolerance: `window: 1` (±30 seconds) — not more
