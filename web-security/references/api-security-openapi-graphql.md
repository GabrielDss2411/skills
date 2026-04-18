# API Security — REST, OpenAPI & GraphQL

Source: OWASP GraphQL Cheat Sheet + API Security Checklist

---

## REST API Security

### Scan — Find Vulnerable REST Patterns

```bash
# Routes that might lack auth middleware
grep -rn "router\.\|app\." --include="*.ts" --include="*.js" . | grep -v node_modules \
  | grep -v "use\|requireAuth\|authenticate\|protect"

# Check for sequential IDs (IDOR risk)
grep -rn "req\.params\.id\|req\.params\.userId\|req\.query\.id" \
  --include="*.ts" --include="*.js" . | grep -v node_modules

# Routes returning excessive data
grep -rn "findMany\|find(\|getAll\|SELECT \*" --include="*.ts" --include="*.js" . | grep -v node_modules
```

### HTTP Method Enforcement

```ts
import { Router } from 'express';

const router = Router();

// Explicitly define allowed methods — reject anything else
router.get('/users', requireAuth, getUsers);
router.post('/users', requireAuth, createUser);
router.get('/users/:id', requireAuth, getUser);
router.patch('/users/:id', requireAuth, updateUser);
router.delete('/users/:id', requireAuth, requireAdmin, deleteUser);

// Catch-all for unsupported methods
router.all('/users', (req, res) => res.status(405).json({ error: 'Method not allowed' }));
```

### Content-Type Validation

```ts
// Middleware to enforce Content-Type on mutating requests
app.use((req, res, next) => {
  if (['POST', 'PUT', 'PATCH'].includes(req.method)) {
    const ct = req.headers['content-type'] ?? '';
    if (!ct.includes('application/json') && !ct.includes('multipart/form-data')) {
      return res.status(415).json({ error: 'Unsupported Media Type' });
    }
  }
  next();
});
```

### Response Filtering — Never Return Raw DB Records

```ts
// ❌ Exposes passwordHash, mfaSecret, internalNotes, etc.
const user = await db.user.findUnique({ where: { id } });
res.json(user);

// ✅ Explicit field selection
const user = await db.user.findUnique({
  where: { id },
  select: {
    id: true,
    email: true,
    name: true,
    role: true,
    createdAt: true,
    // passwordHash: false (implicit — not selected)
    // mfaSecret: false
  },
});
res.json(user);
```

### Pagination & Resource Limits

```ts
// Prevent resource exhaustion — cap all list endpoints
const DEFAULT_LIMIT = 20;
const MAX_LIMIT = 100;

app.get('/api/records', requireAuth, async (req, res) => {
  const limit = Math.min(
    parseInt(req.query.limit as string) || DEFAULT_LIMIT,
    MAX_LIMIT
  );
  const offset = parseInt(req.query.offset as string) || 0;

  const records = await db.record.findMany({
    where: { userId: req.user.id },
    take: limit,
    skip: offset,
    orderBy: { createdAt: 'desc' },
  });

  res.json({ data: records, limit, offset });
});
```

---

## OpenAPI / Swagger Security

### Scan — OpenAPI Issues

```bash
# Find OpenAPI spec files
find . -name "openapi.yaml" -o -name "openapi.json" -o -name "swagger.yaml" -o -name "swagger.json" \
  | grep -v node_modules

# Check if Swagger UI is exposed in production
grep -rn "swagger-ui\|swagger-jsdoc\|SwaggerModule" --include="*.ts" --include="*.js" . | grep -v node_modules
```

### Disable Swagger UI in Production

```ts
// Only expose API docs in non-production environments
if (process.env.NODE_ENV !== 'production') {
  const swaggerUi = await import('swagger-ui-express');
  const swaggerDoc = await import('./openapi.json');
  app.use('/api-docs', swaggerUi.serve, swaggerUi.setup(swaggerDoc));
}
```

### Add Security Schemes to OpenAPI Spec

```yaml
# openapi.yaml
components:
  securitySchemes:
    BearerAuth:
      type: http
      scheme: bearer
      bearerFormat: JWT
    CsrfToken:
      type: apiKey
      in: header
      name: CSRF-Token

security:
  - BearerAuth: []  # apply globally

paths:
  /api/users:
    get:
      security:
        - BearerAuth: []
      responses:
        '401':
          description: Unauthorized
        '403':
          description: Forbidden
```

### Validate Requests Against OpenAPI Schema

```bash
npm install express-openapi-validator
```

```ts
import OpenApiValidator from 'express-openapi-validator';

app.use(
  OpenApiValidator.middleware({
    apiSpec: './openapi.yaml',
    validateRequests: true,   // validates incoming request body, params, headers
    validateResponses: false, // enable in dev to catch response leaks
    validateSecurity: {
      handlers: {
        BearerAuth: async (req, scopes, schema) => {
          // Your JWT verify logic here
          return verifyToken(req.headers.authorization);
        },
      },
    },
  })
);
```

---

## GraphQL Security

GraphQL exposes a flexible query language — attackers can abuse it to extract excessive data,
overload the server with complex queries, or enumerate the schema.

### Scan — GraphQL Setup

```bash
# Find GraphQL setup
grep -rn "ApolloServer\|graphql\|typeDefs\|resolvers\|makeExecutableSchema" \
  --include="*.ts" --include="*.js" . | grep -v node_modules

# Check if introspection is disabled
grep -rn "introspection" --include="*.ts" --include="*.js" . | grep -v node_modules
```

### Disable Introspection in Production

Introspection lets anyone enumerate your entire schema — types, fields, mutations.
In production, this is a reconnaissance gift to attackers.

```ts
import { ApolloServer } from '@apollo/server';

const server = new ApolloServer({
  typeDefs,
  resolvers,
  introspection: process.env.NODE_ENV !== 'production', // disable in prod
});
```

### Query Depth Limiting

A deeply nested query can cause N×N×N DB calls. Limit depth.

```bash
npm install graphql-depth-limit
```

```ts
import depthLimit from 'graphql-depth-limit';

const server = new ApolloServer({
  typeDefs,
  resolvers,
  validationRules: [depthLimit(5)], // reject queries deeper than 5 levels
});
```

### Query Complexity Analysis

```bash
npm install graphql-query-complexity
```

```ts
import { createComplexityLimitRule } from 'graphql-query-complexity';

const server = new ApolloServer({
  typeDefs,
  resolvers,
  validationRules: [
    createComplexityLimitRule(1000, {
      // Assign cost per field — expensive resolvers cost more
      onCost: (cost) => console.log('Query cost:', cost),
      formatErrorMessage: (cost) =>
        `Query too complex (cost: ${cost}). Max allowed: 1000.`,
    }),
  ],
});
```

### Rate Limiting GraphQL

Standard HTTP rate limiters count requests — a single GraphQL request can be arbitrarily expensive.
Rate limit by complexity, not just request count.

```ts
// In resolver or middleware, track per-user complexity budget
const COMPLEXITY_BUDGET_PER_MINUTE = 5000;
const complexityTracker = new Map<string, { used: number; resetAt: number }>();

function checkComplexityBudget(userId: string, cost: number): boolean {
  const now = Date.now();
  const bucket = complexityTracker.get(userId) ?? { used: 0, resetAt: now + 60_000 };

  if (now > bucket.resetAt) {
    bucket.used = 0;
    bucket.resetAt = now + 60_000;
  }

  if (bucket.used + cost > COMPLEXITY_BUDGET_PER_MINUTE) return false;

  bucket.used += cost;
  complexityTracker.set(userId, bucket);
  return true;
}
```

### Resolver-Level Authorization

Every resolver that returns sensitive data must check auth independently.
Don't rely solely on HTTP-level middleware for GraphQL.

```ts
const resolvers = {
  Query: {
    user: async (_, { id }, context) => {
      // context.user is set by auth middleware on the GraphQL server
      if (!context.user) throw new GraphQLError('Unauthorized', { extensions: { code: 'UNAUTHORIZED' } });

      // Still scope to authenticated user — don't trust client-supplied id blindly
      if (id !== context.user.id && context.user.role !== 'admin') {
        throw new GraphQLError('Forbidden', { extensions: { code: 'FORBIDDEN' } });
      }

      return db.user.findUnique({ where: { id } });
    },
  },
  Mutation: {
    deleteUser: async (_, { id }, context) => {
      if (context.user?.role !== 'admin') {
        throw new GraphQLError('Admin only', { extensions: { code: 'FORBIDDEN' } });
      }
      return db.user.delete({ where: { id } });
    },
  },
};
```

### Persisted Queries (Production Hardening)

In production, only allow pre-registered query hashes — prevents arbitrary query execution.

```ts
import { createPersistedQueryLink } from '@apollo/client/link/persisted-queries';

// Client sends hash; server only executes known queries
// Attackers can't send arbitrary GraphQL — only your app's queries work
```

### GraphQL Audit Checklist

- [ ] Introspection disabled in production
- [ ] Query depth limit applied (≤7 recommended)
- [ ] Query complexity analysis configured
- [ ] All resolvers check authentication independently
- [ ] All resolvers check authorization (not just top-level queries)
- [ ] Rate limiting by complexity, not just request count
- [ ] Mutations require auth
- [ ] No sensitive fields exposed without explicit auth check
- [ ] Error messages don't leak internal schema details
- [ ] Persisted queries for production (optional but recommended)
