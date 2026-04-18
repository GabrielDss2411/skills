# Skills — Hunters.IO

Coleção de skills instaladas no projeto Hunters.IO para estender as capacidades do Claude Code. Cada skill é um módulo especializado que adiciona conhecimento, fluxos de trabalho e ferramentas ao agente.

---

## Sumário

| Skill | Descrição |
|---|---|
| [find-skills](#find-skills) | Descobre e instala skills do ecossistema open agent |
| [frontend-design](#frontend-design) | Cria interfaces frontend de nível produção |
| [skill-creator](#skill-creator) | Cria e itera sobre novas skills |
| [supabase-postgres-best-practices](#supabase-postgres-best-practices) | Boas práticas de Postgres no Supabase |
| [ui-ux-pro-max](#ui-ux-pro-max) | Design intelligence completo para web e mobile |
| [web-design-guidelines](#web-design-guidelines) | Revisão de UI contra diretrizes da Vercel |
| [web-security](#web-security) | Auditoria e hardening de segurança web |

---

## find-skills

**Invoke:** `/find-skills`

Ajuda a descobrir e instalar skills do ecossistema open agent. Use quando quiser estender as capacidades do agente para uma tarefa específica.

**Quando usar:**
- "existe uma skill para X?"
- "como eu faço X com o agente?"
- Quer explorar novas capacidades além das já instaladas

**Como funciona:** executa `npx skills find [query]` para pesquisar skills disponíveis por palavra-chave e recomenda as mais relevantes com base em contagem de instalações e reputação da fonte.

---

## frontend-design

**Invoke:** `/frontend-design`

Guia a criação de interfaces frontend distintivas e de nível produção, evitando a estética genérica de IA. Define uma direção estética forte antes de gerar código.

**Quando usar:**
- Construir componentes, páginas, dashboards ou aplicações web
- Estilizar ou embelezar qualquer UI
- Criar posters, landing pages ou artefatos visuais

**O que entrega:**
- Código funcional e production-grade (HTML/CSS/JS, React, Vue, etc.)
- Escolhas tipográficas distintivas — evita fontes genéricas como Arial/Inter
- Direção visual clara: minimalismo extremo, maximalismo, brutalismo, retro-futurista, etc.
- Atenção meticulosa a detalhes: sombras, gradientes, espaçamento, estados de interação

---

## skill-creator

**Invoke:** `/skill-creator`

Cria novas skills do zero, melhora skills existentes e mede performance via evals. Conduz o fluxo completo de criação: rascunho → testes → avaliação → iteração.

**Quando usar:**
- Criar uma skill nova para uma capacidade ainda não coberta
- Otimizar o `description` de uma skill para melhorar o rate de ativação
- Rodar benchmarks e analisar variância de performance
- Iterar sobre uma skill com base em resultados de avaliação

**Fluxo:**
1. Define o objetivo da skill e escreve um rascunho
2. Cria casos de teste e roda o agente com a skill
3. Avalia resultados qualitativamente e quantitativamente
4. Reescreve com base no feedback e repete até satisfatório

---

## supabase-postgres-best-practices

**Invoke:** `/supabase-postgres-best-practices`

Guia completo de otimização de performance para Postgres no Supabase, cobrindo 8 categorias priorizadas por impacto.

**Quando usar:**
- Escrever queries SQL ou projetar schemas
- Implementar índices ou otimizar consultas lentas
- Configurar connection pooling ou escalar o banco
- Revisar problemas de performance no banco
- Trabalhar com Row-Level Security (RLS)

**Categorias cobertas:**

| Prioridade | Categoria |
|---|---|
| Crítico | Query performance, Connection management |
| Alto | Indexing, Schema design |
| Médio | Monitoring, Lock management |
| Incremental | Advanced features, Security |

Cada regra inclui exemplos SQL correto/incorreto, análise de query plan e métricas de performance.

---

## ui-ux-pro-max

**Invoke:** `/ui-ux-pro-max`

Design intelligence abrangente para web e mobile. Base de dados pesquisável com recomendações priorizadas para decisões de design sistemáticas.

**Quando usar:**
- Projetar novas páginas (Landing Page, Dashboard, Admin, SaaS, Mobile App)
- Criar ou refatorar componentes UI (botões, modais, formulários, tabelas, gráficos)
- Escolher paletas de cores, tipografia, espaçamento ou sistemas de layout
- Revisar UI para experiência do usuário, acessibilidade ou consistência visual
- Implementar navegação, animações ou comportamento responsivo

**O que inclui:**
- 50+ estilos de design (glassmorphism, claymorphism, brutalism, neumorphism, bento grid...)
- 161 paletas de cores
- 57 combinações de fontes
- 161 tipos de produto com regras de raciocínio
- 99 diretrizes de UX
- 25 tipos de gráfico
- Suporte a 10 stacks: React, Next.js, Vue, Svelte, SwiftUI, React Native, Flutter, Tailwind, shadcn/ui, HTML/CSS

---

## web-design-guidelines

**Invoke:** `/web-design-guidelines <arquivo-ou-padrão>`

Revisa código de UI contra as Web Interface Guidelines mantidas pela Vercel, buscando a versão mais recente das regras antes de cada auditoria.

**Quando usar:**
- "revise minha UI"
- "verifique acessibilidade"
- "audite o design"
- "valide contra boas práticas"

**Como funciona:**
1. Busca as guidelines atualizadas do repositório da Vercel via `WebFetch`
2. Lê os arquivos especificados (ou pede um padrão glob ao usuário)
3. Verifica cada regra das guidelines
4. Reporta findings no formato `arquivo:linha`

---

## web-security

**Invoke:** `/web-security`

Auditor e hardener de segurança full-spectrum para aplicações Node.js/Express/TypeScript. Entra em modo de varredura ativa ao ser invocado: lê o código, caça vulnerabilidades reais e produz um relatório priorizado com localizações exatas e correções concretas.

**Quando usar:**
- Auditoria de segurança ou varredura de vulnerabilidades
- Qualquer menção a: OWASP, XSS, SQL injection, CSRF, JWT, rate limiting, Helmet, validação de input, credenciais hardcoded, CVE de dependências, controle de acesso quebrado, headers inseguros, upload de arquivo, WebSocket, threat modeling, SAST
- Ao encontrar no código: SQL concatenado raw, `innerHTML` com dados do usuário, API keys hardcoded, middleware de auth ausente, rotas admin desprotegidas, `console.log` com dados sensíveis

**Formato do relatório:**
```
## Relatório de Segurança — [data]
### Sumário (CRITICAL / HIGH / MEDIUM / LOW com contagem)
### Findings (arquivo:linha, ameaça, prova, fix)
### O que foi corrigido nesta sessão
### Sprints de remediação priorizados
```

**Biblioteca de referência incluída:**
- `references/owasp-top10-2025.md` — OWASP A01–A10
- `references/threat-modeling.md` — STRIDE, IDOR, entry points
- `references/api-security-openapi-graphql.md` — REST, OpenAPI, GraphQL
- `references/file-upload-security.md` — uploads seguros
- `references/helmet.md` — headers HTTP seguros
- `references/modern-auth-mfa-oauth.md` — autenticação moderna
- E mais 6 referências especializadas

---

## Instalação

Estas skills fazem parte do projeto Hunters.IO e estão configuradas em `.claude/skills/`. Para usar em outro projeto:

```sh
npx skills add <nome-da-skill>
```

Ou copie a pasta da skill desejada para `.claude/skills/` no seu projeto.
