# Console web do FM-RMM — SPA (`web/`)

SPA em React + TypeScript + Vite do console web. Escopo do T6 (scaffold):
login WebAuthn, grid de agentes e (T7) o **autenticador de assinatura**: o
operador assina grants/jobs NO NAVEGADOR com Ed25519 não exportável e o SPA envia
a `POST /api/acoes`. O servidor não assina nada.

Spec de segurança (lei): `docs/console-seguranca.md`. Plano de execução:
`docs/console-handoff-agentes.md` (T6).

## Requisitos

- Node.js 18+ (testado com 18.19.1 neste ambiente). **Recomendado: Node 22 LTS**
  (ver "Dependências e segurança").
- npm (o `package-lock.json` é versionado; use `npm ci`).

## Como rodar

```bash
cd web
npm ci                 # instala exatamente o package-lock.json
npm run dev            # Vite em http://127.0.0.1:5173 (só para a UI)
npm run typecheck      # tsc --noEmit
npm test               # vitest (56 testes, ambiente node)
npm run build          # tsc + vite build + guarda de CSP -> web/dist/
```

- `npm run dev` serve a UI, mas **não** valida a CSP (o Vite injeta CSS por
  `<style>` em JS em modo dev) e **não** tem o backend (login mTLS exige o
  backend na mesma origem). Para validar, use o build servido pelo backend.
- `npm run preview` serve `dist/` sem os cabeçalhos de segurança do backend:
  **não serve para validar a CSP**.
- Para apontar a API em outra origem (não recomendado; a CSP tem `connect-src 'self'`):
  `VITE_API_BASE=https://... npm run build`. Vazio = mesma origem (padrão).

### Teste de navegador (CSP + WebAuthn ponta a ponta)

`e2e/csp-webauthn.mjs` abre o `dist/` sob a CSP lida de
`internal/console/console.go`, simula `/api/*` no servidor e usa um
**autenticador virtual do Chromium** (CDP) para a cerimônia WebAuthn real.

```bash
npm run build
npm i --no-save playwright-core            # não entra no package.json
CHROMIUM_EXE=/caminho/chrome-headless-shell node e2e/csp-webauthn.mjs
```

Resultado da última execução: **22/22 PASS**, incluindo um controle negativo
(um `<script>` inline sob a mesma CSP é bloqueado pelo navegador, provando que a
checagem tem poder de detecção).

Limite: o e2e usa API simulada. A validação com o backend real e um autenticador
FIDO2 físico é do T8 (VM).

## Conformidade com a CSP

Cabeçalho do backend (`internal/console/console.go`, `contentSecurityPolicy`):

```
default-src 'none'; script-src 'self'; style-src 'self'; img-src 'self' data:;
font-src 'self'; connect-src 'self'; manifest-src 'self'; frame-ancestors 'none';
base-uri 'none'; form-action 'self'
```

O SPA cumpre assim:

| Regra | Como é garantido |
|---|---|
| Sem `<script>` inline | `index.html` só tem `<script type="module" src>`; o plugin `cspGuard` (em `vite.config.ts`) reprova o build se houver |
| Sem `<style>` nem `style="..."` | CSS só em `src/styles.css` (arquivo externo); o guarda reprova o contrário |
| Sem handlers `onclick=` etc. | Eventos só via React; o guarda varre o HTML |
| Sem `eval` / `new Function` | Guarda varre o JS de saída; o build não gera nenhum |
| Sem recursos remotos | Sem fontes/imagens externas; favicon é `data:` (permitido por `img-src`) |
| Só mesma origem para API | `fetch` com `mode: 'same-origin'` e `redirect: 'error'` |
| Sem `dangerouslySetInnerHTML` / `v-html` | Dado do agente só como texto do React (testado em `TabelaAgentes.test.tsx`) |

Evidência de build (saída real de `npm run build`):

```
[csp-guard] OK: sem script/style inline nem eval no build.
```

Evidência no `dist/index.html` (única tag de script é externa):

```html
<script type="module" crossorigin src="/assets/index-*.js"></script>
<link rel="stylesheet" crossorigin href="/assets/style-*.css">
```

## Segurança do cliente (regras de implementação)

- **Token de sessão**: só o cookie `__Host-fmrmm_sessao` (HttpOnly, Secure,
  SameSite=Strict, gerado pelo servidor). O código **nunca** lê cookie.
- **CSRF**: vem de `/api/sessao` ou do `/api/login/fim` e fica **só em memória**
  (`src/api/cliente.ts`). Vai no header `X-FMRMM-CSRF` apenas em métodos de escrita.
  Nunca em `localStorage`/`sessionStorage`/cookie (testado no e2e e no unitário).
- **Erros**: mensagens de tela são fixas por status; o corpo da resposta do
  servidor **nunca** é exibido (sem info-leak).
- **WebAuthn fail-closed**: sem `allowCredentials` no servidor, o login é recusado
  e `/fim` não é chamado.
- **Clique duplo** no login é bloqueado por trava síncrona (`useRef`).

## Contrato consumido

| Método | Caminho | Entrada | Saída usada |
|---|---|---|---|
| POST | `/api/login/inicio` | cert mTLS (navegador) | `{cerimonia, opcoes:{publicKey:{…}}}` |
| POST | `/api/login/fim` | header `X-FMRMM-Cerimonia` + credencial WebAuthn (JSON base64url) | `{operador, csrf}` + cookie |
| GET | `/api/sessao` | cookie | `{operador, nome, csrf}` ou 401 |
| POST | `/api/logout` | cookie + `X-FMRMM-CSRF` | `{ok:true}` |
| GET | `/api/agentes` | cookie | `{agentes:[{id,hostname,os,status,grupo,online,ultimo_contato}]}` (RBAC no servidor) |
| POST | `/api/acoes` | cookie + CSRF + step-up; `{tipo,payload,sig,key_id}` | 202 `{job|sessao, estado}` |
| POST | `/api/operador/chave-assinatura` | cookie + CSRF + step-up; `{signing_pub,prova}` | 201 `{key_id}` |
| POST | `/api/stepup/inicio` e `/fim` | **PENDENTE no backend** (ver abaixo) | como o login |

Validação de forma em `src/api/endpoints.ts`. Tipos em `src/api/tipos.ts`.

**Pendências de contrato (backend; o T7 não mexe em Go):**

1. **Rotas de step-up HTTP não existem.** `Autenticador.IniciaStepUp/FinalizaStepUp`
   existem em `internal/console/webauthn.go`, mas `rotas.go` não as expõe. O SPA
   assume `/api/stepup/inicio` e `/api/stepup/fim` (constantes em
   `src/api/endpoints.ts`), espelhando `/api/login/*`. Sem elas, cadastro de chave
   e ações recebem 403 `step_up_necessario`.
2. **`/api/sessao` não devolve `tecnico` (TechName) nem `relay_url`.** O RemoteGrant
   precisa dos dois (o servidor exige technician = TechName do operador e relay =
   relay configurado). O SPA lê `tecnico` e `relay_url` OPCIONAIS da sessão; se
   faltarem, o "Conectar" falha fechado sem enviar nada. O job de exemplo ("Coletar
   info") não depende disso.
3. Escape de `\b` e `\f`: o serializador emite `\b`/`\f` (Go >= 1.22); o doc só
   cita `\u00XX`. Irrelevante no catálogo atual (só `[A-Za-z0-9._-]`), mas confirmar
   com um vetor Go que contenha esses controles se um dia entrarem em campos livres.

## Assinatura de ações (T7)

Código: `src/auth/canonico.ts` (bytes canônicos), `src/auth/assinatura.ts`
(autenticador), `src/auth/armazem.ts` (IndexedDB), `src/auth/stepup.ts`,
`src/acoes/{executar,conectar}.ts`. Lei: `docs/console-assinatura-acao.md`.

- Chave: `crypto.subtle.generateKey({name:'Ed25519'}, false, ['sign','verify'])`.
  A privada é `extractable:false` e é guardada no IndexedDB por structured clone
  (os bytes nunca passam pelo JS). Nada de lib JS de Ed25519 como fallback.
- Fluxo: bytes canônicos (idênticos ao `json.Marshal` do Go) -> re-serializa e
  confere igual -> `h1 = SHA-256` -> step-up WebAuthn -> o autenticador recomputa
  `h1'` e aborta se divergir -> assina os bytes -> **verifica a assinatura na volta**
  -> `POST /api/acoes` com `payload`/`sig` em base64 dos BYTES.
- Cadastro: botão "Cadastrar chave de assinatura" (step-up, gera, grava, assina a
  prova `fmrmm-signing-pub-v1\n<op>\n<pub>` e registra). Se o registro falhar, a
  chave local é descartada. Trocar chave é com o admin (servidor devolve 409).
- Testes (`src/auth/assinatura.test.ts`) importam a **seed do vetor do doc**
  (chave extraível SÓ no teste) e conferem byte a byte bytes, SHA-256, assinatura e
  `key_id` de job e grant, e a prova de posse.

### Suporte a Ed25519 no WebCrypto

Ed25519 no `SubtleCrypto` (algoritmo `"Ed25519"`) existe em: Chrome/Edge 137+,
Firefox 129+, Safari 17+ (Safari 16.4 com flag). Navegadores mais antigos lançam
`NotSupportedError` em `generateKey`. O SPA faz feature-detect
(`ed25519Disponivel()`), e sem suporte **para** com a mensagem
"Este navegador não suporta Ed25519 no WebCrypto" — não há fallback.

Se faltar: atualize o navegador (não há outra via segura). **Não** troque por
biblioteca JS que gere/exporte a chave: isso quebra a premissa de chave não
exportável. Contexto seguro (HTTPS) também é obrigatório. No Node 18 (testes) o
Ed25519 existe como experimental e os testes rodam com ele.

## Servir o build atrás do backend

O build usa caminhos absolutos a partir de `/` (`base: '/'`):

- `web/dist/index.html` → rota `GET /`
- `web/dist/assets/*` → rota `GET /assets/…` (nomes com hash, cacheáveis)

Requisitos para o backend Go (não alterado neste T6; é trabalho do T3/T4):

1. Servir esses arquivos **com** `SecurityHeaders` (CSP e demais cabeçalhos
   já existem em `console.go`). Nada de página sem CSP.
2. `index.html` com `Cache-Control: no-store`; `assets/*` podem ser cacheados.
3. Não colocar os estáticos sob `/api/`. A SPA não tem roteamento no cliente,
   então não precisa de fallback para outras rotas.
4. Mesma origem para SPA e API (cookie `__Host-` exige `Path=/` e sem `Domain`).
5. O listener do console deve pedir cert de cliente do operador (já previsto no T3).

## Dependências e segurança

Versões fixadas com `--save-exact` (`react 19.1.10`, `vite 6.4.4`,
`@vitejs/plugin-react 4.7.0`, `vitest 3.2.7`, `typescript 5.9.3`, `@types/*` 18/19).

Escolhas condicionadas ao Node 18:

- **Vite 6.4.4** (não 7/8): Vite 7+ exige Node 20.19+.
- **Vitest 3.2.7** (não 4/5): vitest 4 exige Node 20+.

**Vulnerabilidades conhecidas (apenas ferramentas de teste, dev-only):**

`npm audit` acusa 3 (1 moderada, 2 críticas) em `vitest` →
`@vitest/mocker` e `tinypool` (prototype pollution → RCE em opções do worker).
- Não entram no `dist/` nem no servidor; só rodam `npm test`.
- A correção só existe em Node 20+: `vitest 4.1.12` + `tinypool 2.2.0`.
- **Decisão pendente (Eduardo):** atualizar o Node para 22 LTS e aplicar a
  correção. Até lá, não rodar `npm test` com arquivos de teste não confiáveis.

`npm audit --omit=dev` (o que vai para produção): **0 vulnerabilidades**.

## Estrutura

```
web/
├── index.html              entrada (sem script/style inline)
├── vite.config.ts          build + plugin cspGuard + config de teste
├── tsconfig.json
├── package.json            scripts e versões fixadas
├── package-lock.json
├── e2e/
│   ├── servir.mjs          servidor de teste com a CSP do console.go
│   └── csp-webauthn.mjs    teste de navegador (CSP + WebAuthn virtual)
└── src/
    ├── main.tsx            ponto de entrada
    ├── App.tsx             casca: login ou console
    ├── styles.css          único CSS (arquivo externo)
    ├── api/
    │   ├── cliente.ts      fetch com credentials, CSRF em memória, erros seguros
    │   ├── endpoints.ts    funções por endpoint + validação de forma
    │   ├── tipos.ts        contrato da API
    │   └── *.test.ts
    ├── auth/
    │   ├── sessao.tsx      contexto de sessão (sem cookie, CSRF em memória)
    │   ├── webauthn.ts     base64url + cerimônia de login (fail-closed)
    │   ├── Login.tsx       tela de login
    │   └── webauthn.test.ts
    ├── agentes/
    │   ├── GridAgentes.tsx grid com busca
    │   ├── TabelaAgentes.tsx  tabela pura (escape do React)
    │   ├── filtro.ts       busca e formatação de data (puros)
    │   └── *.test.ts(x)
    └── acoes/
        ├── conectar.ts     "Conectar" (grant) e job de exemplo -> autenticador
        └── executar.ts     step-up -> assina -> POST /api/acoes
```

## Fora deste escopo (próximos tickets)

- Rotas HTTP de step-up e `tecnico`/`relay_url` em `/api/sessao` (backend, ver pendências).
- Colunas do handoff ainda não exibidas (nº de vulnerabilidades, updates pendentes, saúde).
- Validação ponta a ponta com o backend real e autenticador FIDO2 físico (T8, VM).
