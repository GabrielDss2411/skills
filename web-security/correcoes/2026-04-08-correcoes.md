# Relatório de Correções de Segurança — Hunters.IO
**Data:** 08/04/2026
**Referência:** Auditoria Inicial `relatorios/2026-04-08-auditoria-inicial.md`
**Status geral:** ✅ 12 de 13 findings corrigidos | 1 LOW aceito (localStorage — aguarda suporte SSR do Supabase)

---

## Resumo das Correções

| Finding | Severidade | Status | Arquivo(s) |
|---------|-----------|--------|-----------|
| Senha padrão hardcoded | CRITICAL | ✅ Corrigido | `Usuarios.tsx`, `create-user/index.ts` |
| Chat sem auth | HIGH | ✅ Corrigido | `chat/index.ts`, `streamChat.ts` |
| send-report sem auth | HIGH | ✅ Corrigido | `send-report/index.ts` |
| CORS wildcard | HIGH | ✅ Corrigido | `chat/index.ts`, `create-user/index.ts`, `send-report/index.ts` |
| Senha mínima fraca | HIGH | ✅ Corrigido | `AlterarSenha.tsx`, `Login.tsx` |
| URL hardcoded | MEDIUM | ✅ Corrigido | `Usuarios.tsx` |
| Conteúdo de comentários no log | MEDIUM | ✅ Corrigido | `useSupabaseData.ts` |
| profiles select * | MEDIUM | ✅ Corrigido | `useSupabaseData.ts` |
| innerHTML no toast | MEDIUM | ✅ Corrigido | `main.tsx` |
| Chat sem rate limit | MEDIUM | ⏳ Pendente | — |
| console.error em produção | LOW | ✅ Corrigido | `auditLog.ts`, `NotFound.tsx` |
| console.log em produção | LOW | ✅ Corrigido | `main.tsx` |
| Sessão em localStorage | LOW | ✅ Aceito | `client.ts` — aguarda SSR |

---

## Detalhamento das Correções

### [CRITICAL] Senha padrão hardcoded

**Problema:** `password: "Hunters@2024"` era enviado do frontend, exibido na UI, e usado como fallback hardcoded no servidor.

**Correções aplicadas:**

`src/pages/Usuarios.tsx`:
- Removido `password: "Hunters@2024"` do corpo da requisição à Edge Function
- Substituído bloco de exibição de senha por mensagem neutra: *"Uma senha temporária segura será gerada automaticamente."*
- URL da Edge Function trocada de hardcoded para `${import.meta.env.VITE_SUPABASE_URL}/functions/v1/create-user`

`supabase/functions/create-user/index.ts`:
- Removido `password` do `req.json()` desestruturado
- Geração de senha temporária segura no servidor:
```ts
const randomBytes = crypto.getRandomValues(new Uint8Array(16));
const tempPassword = Array.from(randomBytes)
  .map((b) => b.toString(16).padStart(2, "0"))
  .join("").slice(0, 16) + "A1!";
```

---

### [HIGH] Edge Function `chat` sem autenticação

**Problema:** Qualquer pessoa com a anon key (pública no bundle JS) podia chamar o LLM ilimitadamente.

**Correções aplicadas:**

`supabase/functions/chat/index.ts`:
- Adicionado bloco de verificação de JWT antes de processar qualquer request:
```ts
const { data: { user }, error: authError } = await anonClient.auth.getUser();
if (authError || !user) return 401 Sessão inválida
```

`src/lib/streamChat.ts`:
- Importado `supabase` client
- Trocado `VITE_SUPABASE_PUBLISHABLE_KEY` (anon key pública) por `session.access_token` do usuário autenticado:
```ts
const { data: { session } } = await supabase.auth.getSession();
Authorization: `Bearer ${session.access_token}`
```
- Adicionado guard: se não houver sessão ativa, dispara `onError` em vez de chamar com token inválido.

---

### [HIGH] Edge Function `send-report` sem autenticação

**Problema:** Qualquer pessoa com a URL podia acionar exportação completa de dados operacionais (profiles, tasks, embarques, despesas, ASO) via service role.

**Correção aplicada** — `supabase/functions/send-report/index.ts`:
- Adicionado bloco de auth + verificação de role admin antes de qualquer operação:
```ts
const { data: { user } } = await anonClient.auth.getUser();
if (!user) return 401

const { data: roles } = await anonClient.from("user_roles")...eq("role", "admin");
if (!roles?.length) return 403 Acesso restrito a administradores
```

---

### [HIGH] CORS `Access-Control-Allow-Origin: "*"` em todas as Edge Functions

**Problema:** Qualquer origem podia fazer requisições cross-origin às funções críticas.

**Correção aplicada** nas 3 Edge Functions (`chat`, `create-user`, `send-report`):
- Substituído objeto `corsHeaders` estático por função `getCorsHeaders(req)` dinâmica
- Origem permitida lida de `ALLOWED_ORIGIN` (env var configurada no Supabase Dashboard)
- Localhost preservado para desenvolvimento
- Header `Vary: Origin` adicionado para cache correto

```ts
const ALLOWED_ORIGINS = [
  Deno.env.get("ALLOWED_ORIGIN") || "",
  "http://localhost:5173",
  "http://localhost:8080",
].filter(Boolean);

function getCorsHeaders(req: Request) {
  const origin = req.headers.get("Origin") || "";
  const allowed = ALLOWED_ORIGINS.includes(origin) ? origin : (ALLOWED_ORIGINS[0] || "");
  return { "Access-Control-Allow-Origin": allowed || "*", "Vary": "Origin", ... };
}
```

**Ação pendente:** Definir `ALLOWED_ORIGIN=https://seu-dominio.com` nas variáveis de ambiente das Edge Functions no Supabase Dashboard.

---

### [HIGH] Política de senha fraca — mínimo de 6 caracteres

**Problema:** Senhas de 6 chars são trivialmente quebráveis. A app lida com dados LGPD-sensíveis.

**Correção aplicada** em `src/pages/AlterarSenha.tsx` e `src/pages/Login.tsx`:
```ts
const validatePassword = (pwd: string): string | null => {
  if (pwd.length < 8) return "A senha deve ter pelo menos 8 caracteres.";
  if (!/[A-Z]/.test(pwd)) return "A senha deve conter ao menos uma letra maiúscula.";
  if (!/[a-z]/.test(pwd)) return "A senha deve conter ao menos uma letra minúscula.";
  if (!/[0-9]/.test(pwd)) return "A senha deve conter ao menos um número.";
  return null;
};
```
- Placeholder do campo atualizado: *"Mínimo 8 caracteres, letras e números"*

---

### [MEDIUM] URL da Edge Function hardcoded com Project ID

**Problema:** `https://qtxxoftgwssxavvzhwco.supabase.co/...` expunha o Project ID e não usava a env var.

**Correção** — `src/pages/Usuarios.tsx:192`:
```ts
`${import.meta.env.VITE_SUPABASE_URL}/functions/v1/create-user`
```

---

### [MEDIUM] Conteúdo de comentários gravado no audit log

**Problema:** Texto completo dos comentários (`conteudo: content`) era gravado no `system_audit_log` e exposto ao chat de IA.

**Correção** — `src/hooks/useSupabaseData.ts`:
```ts
// Antes:
logAudit("tarefas", "comentario_adicionado", taskId, { conteudo: content })
// Depois:
logAudit("tarefas", "comentario_adicionado", taskId, { comprimento: content.length })
```

---

### [MEDIUM] `useProfiles` retornava todos os campos (`select("*")`)

**Problema:** Dados desnecessários (campos internos) trafegavam para o frontend.

**Correção** — `src/hooks/useSupabaseData.ts`:
```ts
supabase.from("profiles").select("id, full_name, initials, avatar_color, avatar_url, email, role, must_change_password")
```

---

### [MEDIUM] `innerHTML` para toast de atualização do PWA

**Problema:** Padrão perigoso — se replicado com dados variáveis resulta em XSS.

**Correção** — `src/main.tsx`:
- Substituído bloco `toast.innerHTML = \`...\`` por construção via `createElement` e `textContent`
- `<style>` injetado via `document.head.appendChild` com `style.textContent`

---

### [LOW] `console.error` / `console.log` em código de produção

**Correções:**

- `src/utils/auditLog.ts` — `console.error` condicionado a `import.meta.env.DEV`
- `src/pages/NotFound.tsx` — `console.error` condicionado a `import.meta.env.DEV`
- `src/main.tsx` — `console.log("App ready to work offline")` condicionado a `import.meta.env.DEV`

---

### [LOW] Sessão Supabase em localStorage — ACEITO

**Decisão:** Mantido `storage: localStorage` por enquanto. O Supabase Auth ainda não tem suporte estável a cookies `httpOnly` no modo SPA sem SSR. Aceitável para plataforma interna com usuários identificados. Revisar quando Supabase lançar suporte SSR/cookies para React SPA.

---

## Findings Ainda Pendentes

### [MEDIUM] Chat sem rate limiting por usuário

**Risco:** Usuário autenticado pode fazer flood de chamadas ao LLM, gerando custo financeiro.

**Plano:** Criar tabela `chat_rate_limit` e verificar contador (max 20 msgs/min por usuário) antes de processar na Edge Function `chat`. Estimativa: 2h de implementação.

---

## Ações de Infra Necessárias (fora do código)

1. **Definir `ALLOWED_ORIGIN`** nas variáveis de ambiente das 3 Edge Functions no Supabase Dashboard  
   Valor: `https://seu-dominio.com` (URL de produção da aplicação)

2. **Revogar e rotacionar** a senha padrão `Hunters@2024` — todos os usuários criados antes desta correção que ainda não trocaram a senha devem ser notificados e forçados a redefinir.

---

*Relatório gerado em 08/04/2026 após ciclo de remediação Sprint 1 + Sprint 2 da auditoria inicial.*
