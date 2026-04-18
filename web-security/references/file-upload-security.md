# File Upload Security

Source: OWASP File Upload Cheat Sheet

## Why File Uploads Are High Risk

File upload endpoints are among the most dangerous surfaces:
- **RCE** — uploading a `.php`/`.js` file and executing it via direct URL
- **XSS** — uploading an SVG or HTML file served with wrong Content-Type
- **Path traversal** — filename `../../etc/passwd` writing to unexpected locations
- **DoS** — huge files exhausting disk, memory, or processing time
- **Malware hosting** — using your server to distribute malicious files

---

## Scan — Find Upload Endpoints

```bash
# Find multer, busboy, formidable usage
grep -rn "multer\|busboy\|formidable\|multipart\|upload\." \
  --include="*.ts" --include="*.js" . | grep -v node_modules

# Find file serving / static routes
grep -rn "express\.static\|res\.sendFile\|res\.download\|createReadStream" \
  --include="*.ts" --include="*.js" . | grep -v node_modules

# Find direct filename usage from user input
grep -rn "req\.file\|req\.files\|req\.body\.filename\|originalname" \
  --include="*.ts" --include="*.js" . | grep -v node_modules
```

---

## Complete Secure Upload Handler

```ts
import multer from 'multer';
import path from 'path';
import crypto from 'crypto';
import sharp from 'sharp'; // for image validation
import { fromBuffer } from 'file-type'; // magic byte detection

const UPLOAD_DIR = path.resolve(process.env.UPLOAD_DIR ?? './uploads');
const MAX_FILE_SIZE = 10 * 1024 * 1024; // 10MB

// ✅ Store in memory for processing — never write to disk with original filename
const upload = multer({
  storage: multer.memoryStorage(),
  limits: {
    fileSize: MAX_FILE_SIZE,
    files: 1,
  },
  // ❌ DO NOT trust mimetype from client — it's user-controlled
  // Use file-type library instead (magic bytes)
});

// Allowed types: server-side allowlist
const ALLOWED_TYPES = new Map([
  ['image/jpeg', ['.jpg', '.jpeg']],
  ['image/png', ['.png']],
  ['image/webp', ['.webp']],
  ['application/pdf', ['.pdf']],
]);

app.post('/api/upload', requireAuth, upload.single('file'), async (req, res) => {
  if (!req.file) return res.status(400).json({ error: 'No file provided' });

  // Step 1: Detect actual file type from magic bytes (not from client header)
  const detected = await fromBuffer(req.file.buffer);
  if (!detected || !ALLOWED_TYPES.has(detected.mime)) {
    return res.status(400).json({ error: 'File type not allowed' });
  }

  // Step 2: For images — re-encode through Sharp to strip metadata and verify integrity
  // This also defeats polyglot files (e.g., JPEG+PHP)
  let processedBuffer = req.file.buffer;
  if (detected.mime.startsWith('image/')) {
    try {
      processedBuffer = await sharp(req.file.buffer)
        .rotate()          // auto-rotate based on EXIF (strips EXIF in process)
        .toBuffer();       // re-encode — strips any embedded payloads
    } catch {
      return res.status(400).json({ error: 'Invalid image file' });
    }
  }

  // Step 3: Generate a random filename — never use originalname
  const ext = ALLOWED_TYPES.get(detected.mime)![0];
  const filename = `${crypto.randomUUID()}${ext}`;

  // Step 4: Verify path stays within upload directory (defense in depth)
  const dest = path.resolve(UPLOAD_DIR, filename);
  if (!dest.startsWith(UPLOAD_DIR)) {
    return res.status(400).json({ error: 'Invalid path' });
  }

  // Step 5: Upload to object storage (S3/GCS) — NEVER serve from app server
  await s3.putObject({
    Bucket: process.env.S3_BUCKET!,
    Key: `uploads/${req.user.id}/${filename}`,
    Body: processedBuffer,
    ContentType: detected.mime,
    // Prevent browser from executing — always force download or specific type
    ContentDisposition: 'attachment',
    // Never public ACL for user uploads
    ACL: 'private',
    // Server-side encryption
    ServerSideEncryption: 'AES256',
  });

  // Step 6: Store reference in DB (key, not full URL)
  const file = await db.file.create({
    data: {
      key: `uploads/${req.user.id}/${filename}`,
      originalName: sanitizeFilename(req.file.originalname), // for display only
      mimeType: detected.mime,
      size: processedBuffer.length,
      userId: req.user.id,
    },
  });

  res.json({ fileId: file.id });
});

function sanitizeFilename(name: string): string {
  // Strip path separators, null bytes, control characters
  return path.basename(name)
    .replace(/[^\w\s.-]/g, '')
    .replace(/\.\./g, '')
    .slice(0, 255);
}
```

---

## Serving Files Securely

Never serve user uploads from the same origin as your app — XSS via SVG/HTML uploads would have
full access to your cookies and localStorage.

```ts
// ✅ Generate pre-signed URLs (S3) — time-limited, no public access needed
app.get('/api/files/:id/download', requireAuth, async (req, res) => {
  const file = await db.file.findFirst({
    where: { id: req.params.id, userId: req.user.id }, // scope to owner
  });
  if (!file) return res.status(404).json({ error: 'Not found' });

  const url = await s3.getSignedUrlPromise('getObject', {
    Bucket: process.env.S3_BUCKET!,
    Key: file.key,
    Expires: 300, // 5 minutes
    ResponseContentDisposition: `attachment; filename="${encodeURIComponent(file.originalName)}"`,
    ResponseContentType: file.mimeType,
  });

  res.redirect(url);
});

// ❌ Never do this — executes user-uploaded files as your app
app.use('/uploads', express.static('./uploads'));
```

---

## Anti-Virus / Malware Scanning

For apps handling documents from untrusted sources:

```bash
npm install clamscan  # ClamAV Node.js binding
# Requires: apt install clamav clamav-daemon
```

```ts
import NodeClam from 'clamscan';

const clamscan = await new NodeClam().init({
  clamdscan: {
    socket: '/var/run/clamav/clamd.ctl',
    timeout: 60_000,
  },
});

// Scan buffer before storing
const { isInfected, viruses } = await clamscan.scanBuffer(req.file.buffer);
if (isInfected) {
  logger.error({ event: 'upload.malware_detected', viruses, userId: req.user.id });
  return res.status(400).json({ error: 'File failed security scan' });
}
```

---

## SVG Uploads — Special Danger

SVG files are XML that can contain `<script>` tags. If served with `image/svg+xml` from your
origin, they execute as XSS in the browser.

```ts
// Option 1: Don't accept SVG at all
// Option 2: Sanitize SVG before storing
import { optimize } from 'svgo';
import DOMPurify from 'isomorphic-dompurify';

function sanitizeSvg(buffer: Buffer): Buffer {
  const svgString = buffer.toString('utf8');

  // Remove scripts, event handlers, foreign objects
  const clean = DOMPurify.sanitize(svgString, {
    USE_PROFILES: { svg: true, svgFilters: true },
    FORBID_TAGS: ['script', 'foreignObject'],
    FORBID_ATTR: ['onclick', 'onload', 'onerror', 'onmouseover'],
  });

  // Optimize and normalize
  const optimized = optimize(clean, { multipass: true });
  return Buffer.from(optimized.data);
}

// Option 3: Convert SVG to PNG before storing (safest)
const png = await sharp(svgBuffer).png().toBuffer();
```

---

## File Upload Audit Checklist

- [ ] File type validated via magic bytes (not client-provided Content-Type)
- [ ] Images re-encoded through Sharp (strips embedded payloads, EXIF metadata)
- [ ] Random UUID filenames (not originalname)
- [ ] Path traversal protection (resolved path starts with upload dir)
- [ ] Files stored in object storage (S3/GCS), not app server filesystem
- [ ] Files served via pre-signed URLs, not public static routes
- [ ] User uploads served from separate domain/subdomain (prevent XSS)
- [ ] File size limit set in multer AND at CDN/proxy level
- [ ] SVG uploads sanitized or converted to raster
- [ ] Malware scanning for document uploads (optional but recommended for enterprise)
- [ ] Upload endpoint behind auth + rate limiting
- [ ] DB stores file key (not full URL) — URLs can rotate, keys don't
