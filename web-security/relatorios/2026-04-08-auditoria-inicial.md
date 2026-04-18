# Relatório de Segurança — Hunters.IO
**Data:** 08/04/2026
**Tipo:** Auditoria Inicial — Varredura Completa (12 Fases)
**Contexto:** Plataforma operacional de gestão de pessoal offshore. Dados sensíveis: PII de funcionários (nome, CPF, matrícula, função), histórico médico (ASO), dados financeiros (despesas), histórico operacional de embarques. Compliance aplicável: **LGPD**.

---

## Sumário

| Severidade | Qtd |
|------------|-----|
| CRITICAL   | 1   |
| HIGH       | 4   |
| MEDIUM     | 5   |
| LOW        | 3   |
| **Total**  | **13** |

---

## Findings

### [CRITICAL] Senha padrão hardcoded exposta na interface

**Arquivos:**
- `src/pages/Usuarios.tsx:204` — `password: "Hunters@2024"` enviado em plaintext para a Edge Function
- `src/pages/Usuarios.tsx:421` — UI exibe a senha em texto visível para qualquer admin logado
- `supabase/functions/create-user/index.ts:65` — fallback `password || "Hunters@2024"` hardcoded no servidor

**Ameaça:** Qualquer administrador (ou atacante que comprometa uma sessão admin) vê `Hunters@2024` na tela. Como a senha padrão é conhecida, qualquer usuário criado que não troque imediatamente a senha está com credencial trivialmente adivinhável. A lógica de `must_change_password` existe, mas não é enforcement técnico real — basta um usuário contornar o frontend.

**Fix:**
```tsx
// src/pages/Usuarios.tsx — remover o bloco que exibe "Senha padrão: Hunters@2024"
// Na chamada à Edge Function, NÃO enviar password:
body: JSON.stringify({
  email: formEmail.trim(),
  full_name: formName.trim(),
  role: formRole.trim(),
  app_role: formAppRole,
  // password removido — Edge Function gera internamente com crypto.randomUUID()
}),
```

```ts
// supabase/functions/create-user/index.ts
// Gerar senha aleatória no servidor em vez de receber do cliente
const tempPassword = crypto.randomUUID().replace(/-/g, '').slice(0, 16) + "A1!";
const { email, full_name, role, app_role } = await req.json(); // sem password
```

---

### [HIGH] Edge Function `chat` sem verificação de autenticação

**Arquivo:** `supabase/functions/chat/index.ts:20-79`

**Ameaça:** A função não valida o JWT do usuário — só checa se o request chegou com a anon key, que está hardcoded e pública no bundle JS (`src/integrations/supabase/client.ts:6`). Qualquer pessoa que inspecione o código-fonte do browser obtém a anon key e pode chamar a Edge Function diretamente, gerando chamadas ilimitadas ao LLM sem autenticação.

**Prova:** `streamChat.ts:21` usa `VITE_SUPABASE_PUBLISHABLE_KEY` como Authorization — essa é a anon key pública, não o token do usuário.

**Fix:**
```ts
// supabase/functions/chat/index.ts — adicionar validação de usuário
Deno.serve(async (req) => {
  if (req.method === "OPTIONS") return new Response(null, { headers: corsHeaders });

  const authHeader = req.headers.get("Authorization");
  if (!authHeader) {
    return new Response(JSON.stringify({ error: "Não autorizado" }), { status: 401, headers: corsHeaders });
  }

  const supabase = createClient(
    Deno.env.get("SUPABASE_URL")!,
    Deno.env.get("SUPABASE_ANON_KEY")!,
    { global: { headers: { Authorization: authHeader } } }
  );

  const { data: { user }, error } = await supabase.auth.getUser();
  if (error || !user) {
    return new Response(JSON.stringify({ error: "Sessão inválida" }), { status: 401, headers: corsHeaders });
  }
  // resto do código...
});
```

```ts
// src/lib/streamChat.ts — usar o access_token do usuário, não a anon key
const { data: { session } } = await supabase.auth.getSession();
const resp = await fetch(CHAT_URL, {
  method: "POST",
  headers: {
    "Content-Type": "application/json",
    Authorization: `Bearer ${session?.access_token}`, // token do usuário
  },
  body: JSON.stringify({ messages, systemContext }),
});
```

---

### [HIGH] Edge Function `send-report` sem autenticação

**Arquivo:** `supabase/functions/send-report/index.ts:17-28`

**Ameaça:** A função usa `SUPABASE_SERVICE_ROLE_KEY` para buscar todos os dados (profiles, audit logs, tasks, embarques, despesas, ASO) mas não verifica se o chamador é autenticado nem se é admin. Qualquer pessoa com a URL da função pode acionar o relatório e receber dados operacionais completos via webhook.

**Fix:**
```ts
// supabase/functions/send-report/index.ts — adicionar auth check logo no início
const authHeader = req.headers.get("Authorization");
if (!authHeader) return new Response(JSON.stringify({ error: "Não autorizado" }), { status: 401, headers: corsHeaders });

const anonClient = createClient(Deno.env.get("SUPABASE_URL")!, Deno.env.get("SUPABASE_ANON_KEY")!, {
  global: { headers: { Authorization: authHeader } },
});
const { data: { user } } = await anonClient.auth.getUser();
if (!user) return new Response(JSON.stringify({ error: "Não autorizado" }), { status: 401, headers: corsHeaders });

const { data: roles } = await anonClient.from("user_roles").select("role").eq("user_id", user.id).eq("role", "admin");
if (!roles?.length) return new Response(JSON.stringify({ error: "Acesso restrito a administradores" }), { status: 403, headers: corsHeaders });
```

---

### [HIGH] CORS `Access-Control-Allow-Origin: "*"` em todas as Edge Functions

**Arquivos:**
- `supabase/functions/chat/index.ts:4`
- `supabase/functions/create-user/index.ts:4`
- `supabase/functions/send-report/index.ts:4`

**Ameaça:** Qualquer origem pode fazer cross-origin requests para essas funções. Para `create-user` (que usa service role internamente) e `send-report` (que retorna dados operacionais), isso amplia desnecessariamente a superfície de ataque.

**Fix:**
```ts
const ALLOWED_ORIGINS = [
  "https://seu-dominio.com",
  "https://staging.seu-dominio.com",
  "http://localhost:5173",
];

function getCorsHeaders(req: Request) {
  const origin = req.headers.get("Origin") || "";
  const allowed = ALLOWED_ORIGINS.includes(origin) ? origin : ALLOWED_ORIGINS[0];
  return {
    "Access-Control-Allow-Origin": allowed,
    "Access-Control-Allow-Headers": "authorization, x-client-info, apikey, content-type",
    "Vary": "Origin",
  };
}
```

---

### [HIGH] Política de senha fraca — mínimo de 6 caracteres

**Arquivos:**
- `src/pages/AlterarSenha.tsx:25` — `if (password.length < 6)`
- `src/pages/Login.tsx:39` — `if (password.length < 6)`

**Ameaça:** 6 caracteres são trivialmente quebráveis por força bruta. A aplicação lida com dados de saúde (ASO) e PII de funcionários — LGPD exige proteção proporcional.

**Fix:**
```ts
const PASSWORD_RULES = { minLength: 8, hasUpper: /[A-Z]/, hasLower: /[a-z]/, hasNumber: /[0-9]/ };

function validatePassword(password: string): string | null {
  if (password.length < PASSWORD_RULES.minLength) return "A senha deve ter pelo menos 8 caracteres.";
  if (!PASSWORD_RULES.hasUpper.test(password)) return "A senha deve conter ao menos uma letra maiúscula.";
  if (!PASSWORD_RULES.hasLower.test(password)) return "A senha deve conter ao menos uma letra minúscula.";
  if (!PASSWORD_RULES.hasNumber.test(password)) return "A senha deve conter ao menos um número.";
  return null;
}
```

---

### [MEDIUM] URL da Edge Function hardcoded com Project ID

**Arquivo:** `src/pages/Usuarios.tsx:192`

**Prova:** `` `https://qtxxoftgwssxavvzhwco.supabase.co/functions/v1/create-user` ``

**Fix:**
```ts
`${import.meta.env.VITE_SUPABASE_URL}/functions/v1/create-user`
```

---

### [MEDIUM] Conteúdo de comentários gravado no audit log

**Arquivo:** `src/hooks/useSupabaseData.ts:374`

**Prova:** `logAudit("tarefas", "comentario_adicionado", taskId, { conteudo: content })`

**Ameaça:** Texto completo dos comentários vai para `system_audit_log`, que é consultado pela Edge Function `send-report` e exposto ao chat de IA. Comentários podem conter dados sensíveis.

**Fix:**
```ts
logAudit("tarefas", "comentario_adicionado", taskId, {
  comprimento: content.length,
  // não gravar o conteúdo em si
}).catch(console.error);
```

---

### [MEDIUM] `useProfiles` retorna todos os campos de todos os usuários

**Arquivo:** `src/hooks/useSupabaseData.ts:38`

**Prova:** `supabase.from("profiles").select("*")`

**Fix:**
```ts
supabase.from("profiles").select("id, full_name, initials, avatar_color, avatar_url")
```

---

### [MEDIUM] `innerHTML` para toast de atualização do PWA

**Arquivo:** `src/main.tsx:11-19`

**Ameaça:** Conteúdo atual é estático e seguro, mas é um padrão de `innerHTML` que, se replicado com dados variáveis, resulta em XSS.

**Fix:**
```ts
const toast = document.createElement("div");
toast.style.cssText = "position:fixed;bottom:24px;left:50%;...";
const span = document.createElement("span");
span.textContent = "🔄 Nova versão disponível! Atualizando...";
toast.appendChild(span);
document.body.appendChild(toast);
```

---

### [MEDIUM] Chat sem rate limiting por usuário

**Arquivo:** `supabase/functions/chat/index.ts`

**Ameaça:** Usuário autenticado pode fazer flood de chamadas ao LLM, gerando custo financeiro ilimitado.

**Fix:** Verificar contador de mensagens do usuário nos últimos 60 segundos via tabela `chat_rate_limit` antes de processar (max 20 msgs/min).

---

### [LOW] `console.error` expõe erros internos no DevTools

**Arquivo:** `src/utils/auditLog.ts:24` — `console.error("Audit log error:", e)`

Facilita fingerprinting por atacantes que abrem DevTools. Silenciar em produção.

---

### [LOW] `console.log` e `console.error` em páginas de produção

**Arquivos:** `src/main.tsx:24`, `src/pages/NotFound.tsx:8`

O log de 404 expõe rotas tentadas: `console.error("404 Error: ...", location.pathname)`. Condicionar a `import.meta.env.DEV`.

---

### [LOW] Sessão Supabase em localStorage

**Arquivo:** `src/integrations/supabase/client.ts:12`

`storage: localStorage` — tokens JWT ficam acessíveis via JavaScript. Aceitável para aplicação interna. Migrar para cookie `httpOnly` quando o Supabase Auth suportar SSR/cookies.

---

## Sprints de Remediação

### Sprint 1 — Esta Semana (risco ativo)
- `[CRITICAL]` Remover senha padrão da UI e não aceitar `password` do frontend em `create-user` — **2h**
- `[HIGH]` Adicionar verificação de usuário na Edge Function `chat` + corrigir `streamChat.ts` para usar `access_token` — **1h**
- `[HIGH]` Adicionar auth + check de admin na Edge Function `send-report` — **30min**

### Sprint 2 — Este Mês
- `[HIGH]` Restringir CORS para origem específica nas 3 Edge Functions — **1h**
- `[HIGH]` Aumentar mínimo de senha para 8 chars com complexidade — **30min**
- `[MEDIUM]` Trocar URL hardcoded por `VITE_SUPABASE_URL` em `Usuarios.tsx` — **5min**
- `[MEDIUM]` Remover conteúdo dos comentários do audit log — **15min**
- `[MEDIUM]` Substituir `innerHTML` por `createElement` em `main.tsx` — **15min**

### Sprint 3 — Próximo Trimestre
- `[MEDIUM]` Rate limiting no chat por usuário — **2h**
- `[MEDIUM]` Restringir `select("*")` em `useProfiles` — **30min**
- `[LOW]` Remover/condicionar `console.log` e `console.error` de produção — **30min**

---

## O que está bem implementado

- `ProtectedRoute` cobre todas as rotas autenticadas corretamente
- `create-user` Edge Function verifica autenticação **e** role de admin antes de agir
- `must_change_password` forçado no primeiro login
- Audit log registrando todas as mutações nos módulos (embarque, EPI, ASO, tarefas, despesas, medições)
- `useIsAdmin` consulta o banco (não o JWT) — correta separação de papéis
- Supabase Auth com `autoRefreshToken: true` e `persistSession: true`
- Dados sensíveis de EPIs (CPF, matrícula) apenas no PDF gerado localmente, não trafegados desnecessariamente

---

## Status de Correções

| Finding | Severidade | Status |
|---------|-----------|--------|
| Senha padrão hardcoded | CRITICAL | ✅ Corrigido |
| Chat sem auth | HIGH | ✅ Corrigido |
| send-report sem auth | HIGH | ✅ Corrigido |
| CORS wildcard | HIGH | ✅ Corrigido |
| Senha mínima fraca | HIGH | ✅ Corrigido |
| URL hardcoded | MEDIUM | ✅ Corrigido |
| Conteúdo de comentários no log | MEDIUM | ✅ Corrigido |
| profiles select * | MEDIUM | ✅ Corrigido |
| innerHTML no toast | MEDIUM | ✅ Corrigido |
| Chat sem rate limit | MEDIUM | ⏳ Pendente (Sprint 3) |
| console.error em produção | LOW | ✅ Corrigido |
| console.log em produção | LOW | ✅ Corrigido |
| Sessão em localStorage | LOW | ✅ Aceito (aguarda SSR) |
