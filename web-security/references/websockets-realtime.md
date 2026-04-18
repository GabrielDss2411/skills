# WebSocket & Real-Time Security

## Why WebSockets Need Special Attention

WebSockets bypass the standard HTTP request-response model. Once upgraded, the connection is
persistent and bidirectional — standard HTTP middleware (rate limiting, CSRF tokens, auth checks
per-request) does NOT automatically apply. You must explicitly secure the upgrade handshake and
every message handler.

---

## Scan — Find WebSocket Usage

```bash
# Find WebSocket server implementations
grep -rn "WebSocket\|ws\.\|socket\.io\|socketio\|\.on('connection'\|\.on(\"connection\"" \
  --include="*.ts" --include="*.js" . | grep -v node_modules

# Find socket.io event handlers
grep -rn "socket\.on\|io\.on\|socket\.emit\|io\.emit\|socket\.broadcast" \
  --include="*.ts" --include="*.js" . | grep -v node_modules

# Check if auth is verified on connection
grep -rn "socket\.handshake\|socket\.request\|socket\.data" \
  --include="*.ts" --include="*.js" . | grep -v node_modules
```

---

## Authentication on WebSocket Upgrade

The most common vulnerability: WebSocket connections are opened without verifying the JWT/session.
Auth headers aren't available on the upgrade request the same way — you must handle it explicitly.

**With socket.io:**

```ts
import { Server } from 'socket.io';
import jwt from 'jsonwebtoken';

const io = new Server(server, {
  cors: {
    origin: process.env.ALLOWED_ORIGIN, // never '*' for authenticated sockets
    credentials: true,
  },
});

// Auth middleware runs once on connection — reject unauthenticated upgrades here
io.use((socket, next) => {
  const token = socket.handshake.auth.token
    ?? socket.handshake.headers.authorization?.replace('Bearer ', '');

  if (!token) return next(new Error('Authentication required'));

  try {
    const payload = jwt.verify(token, process.env.ACCESS_TOKEN_SECRET!, {
      algorithms: ['HS256'],
    });
    socket.data.user = payload; // attach user to socket for use in handlers
    next();
  } catch {
    next(new Error('Invalid or expired token'));
  }
});

// From here, every handler has access to socket.data.user
io.on('connection', (socket) => {
  console.log('Authenticated user connected:', socket.data.user.userId);

  socket.on('message', (data) => {
    // socket.data.user is always set — safe to use
    handleMessage(socket.data.user.userId, data);
  });
});
```

**With raw ws library:**

```ts
import { WebSocketServer } from 'ws';
import { parse } from 'url';
import jwt from 'jsonwebtoken';

const wss = new WebSocketServer({ noServer: true });

// Intercept the HTTP upgrade request before WebSocket handshake
server.on('upgrade', (request, socket, head) => {
  const { query } = parse(request.url!, true);
  const token = query.token as string; // sent as ?token=xxx in WS URL

  try {
    const user = jwt.verify(token, process.env.ACCESS_TOKEN_SECRET!, { algorithms: ['HS256'] });
    (request as any).user = user;
    wss.handleUpgrade(request, socket, head, (ws) => {
      wss.emit('connection', ws, request);
    });
  } catch {
    socket.write('HTTP/1.1 401 Unauthorized\r\n\r\n');
    socket.destroy();
  }
});
```

---

## Input Validation on WebSocket Messages

Every message from a client is untrusted. Validate shape and content just like HTTP request bodies.

```ts
import Joi from 'joi';

const chatMessageSchema = Joi.object({
  roomId: Joi.string().uuid().required(),
  content: Joi.string().max(2000).required(),
  type: Joi.string().valid('text', 'image').required(),
});

socket.on('chat:send', (data, callback) => {
  const { error, value } = chatMessageSchema.validate(data);
  if (error) {
    callback({ error: 'Invalid message format' });
    return;
  }
  // proceed with validated value
});
```

---

## Rate Limiting WebSocket Messages

HTTP rate limiters don't apply to WebSocket messages. Implement message-level throttling:

```ts
// Simple in-memory token bucket per socket
const MESSAGE_LIMIT = 60;  // messages per minute
const WINDOW_MS = 60_000;

const rateLimitMap = new Map<string, { count: number; resetAt: number }>();

function checkRateLimit(socketId: string): boolean {
  const now = Date.now();
  const bucket = rateLimitMap.get(socketId) ?? { count: 0, resetAt: now + WINDOW_MS };

  if (now > bucket.resetAt) {
    bucket.count = 0;
    bucket.resetAt = now + WINDOW_MS;
  }

  bucket.count++;
  rateLimitMap.set(socketId, bucket);

  return bucket.count <= MESSAGE_LIMIT;
}

socket.on('message', (data) => {
  if (!checkRateLimit(socket.id)) {
    socket.emit('error', { code: 'RATE_LIMIT', message: 'Too many messages' });
    return;
  }
  // process message
});

// Clean up on disconnect
socket.on('disconnect', () => {
  rateLimitMap.delete(socket.id);
});
```

---

## Room / Channel Authorization

Joining a room doesn't mean the user should see everything in it. Verify authorization on join:

```ts
socket.on('room:join', async (roomId: string) => {
  // Verify user has permission to join this room
  const membership = await db.roomMember.findFirst({
    where: { roomId, userId: socket.data.user.userId },
  });

  if (!membership) {
    socket.emit('error', { code: 'FORBIDDEN', message: 'Access denied' });
    return;
  }

  socket.join(roomId);
  socket.emit('room:joined', { roomId });
});

// When emitting to a room, never include data the user shouldn't see
io.to(roomId).emit('message', {
  id: message.id,
  content: message.content,
  authorId: message.authorId,
  // omit: internal fields, other users' PII
});
```

---

## CORS for WebSocket Servers

```ts
const io = new Server(server, {
  cors: {
    origin: (origin, callback) => {
      const allowed = new Set([
        'https://app.example.com',
        'https://staging.example.com',
      ]);
      if (!origin || allowed.has(origin)) {
        callback(null, true);
      } else {
        callback(new Error('CORS: origin not allowed'));
      }
    },
    methods: ['GET', 'POST'],
    credentials: true,
  },
});
```

---

## Audit Checklist

- [ ] JWT verified on WebSocket upgrade (before connection is established)
- [ ] All message handlers validate input with a schema
- [ ] Rate limiting per socket (not just per IP)
- [ ] Room/channel join authorization checks ownership
- [ ] CORS origin allowlist (never `*` for auth sockets)
- [ ] Payload size limits set (`maxHttpBufferSize` in socket.io)
- [ ] XSS-safe: never render raw socket messages as HTML
- [ ] Reconnection tokens rotated, not reused indefinitely
- [ ] Disconnect cleans up any per-socket state/timers
