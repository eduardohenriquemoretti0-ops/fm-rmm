# Console web do FM-RMM — handoff para os agentes

> Regra (Eduardo, 2026-10-19): o orquestrador só comanda e planeja; **quem
> executa são os agentes especialistas**; o **pentest é dos agentes de
> segurança**. Este documento é o plano de execução. Spec de segurança (lei):
> `docs/console-seguranca.md` — qualquer divergência dela é bug.

## O que já existe (base pronta, verificada no Linux)
- `internal/console/console.go` — `SecurityHeaders` (CSP estrito sem inline/eval,
  HSTS, nosniff, frame DENY, COOP/CORP/COEP, no-store), `SessionCookie`
  (HttpOnly+Secure+SameSite=Strict), `Handler` com `/healthz`.
- `internal/console/session.go` — `SessionManager`: token só como SHA-256
  (constant-time), binding ao thumbprint do cert mTLS do operador
  (`CertThumbprint`), TTL absoluto+inatividade, `CSRF` por sessão, `Revoke`/`GC`.
- Testes: `console_test.go`, `session_test.go` (8 no total).
- Catálogo read-only já tem `hardware`, `saude`, `inventario`, `software`,
  `atualizacoes`; servidor tem `Agent.Online`, RBAC por grupo, auditoria
  encadeada, assinatura Ed25519 e `CreateSession`.

Toolchain: Go em `~/go-sdk/go` (`export GOROOT=~/go-sdk/go
PATH=~/go-sdk/go/bin:$PATH GOPATH=~/go GOFLAGS=-mod=mod`). Validar sempre com
`go vet ./...`, `go test -race ./...`, cross-build 3 SO. `go-webauthn/webauthn`
disponível no proxy.

## Tarefas (cada uma: código + teste + validação; não marcar pronto sem evidência)

### T1 — Store de operadores (agente: dev-golang / Otávio)
- `internal/server/store.go`: tabelas `operators` (id, nome, display_name,
  cert_thumbprint, criado_em, status) e `operator_credentials` (webauthn: id,
  operator_id, credential_id, public_key, sign_count, aaguid, criado_em).
  Reusar o mecanismo de grupos (RBAC) que os agentes já usam para ligar operador↔grupos.
- Métodos: `CreateOperator`, `GetOperator`, `AddCredential`, `Credentials(opID)`,
  `UpdateSignCount`, `SetOperatorThumbprint`.
- **Aceite:** testes de CRUD + unicidade de credential_id; `go test -race`.

### T2 — WebAuthn (agente: dev-golang / Otávio)
- `internal/console/webauthn.go` com `go-webauthn/webauthn`: adapter `webauthn.User`
  sobre o operador, `BeginRegistration/FinishRegistration`,
  `BeginLogin/FinishLogin`. RPID/RPOrigin por config (domínio do console).
  Challenge store em memória com TTL curto. No sucesso do login, emite sessão via
  `SessionManager.New(opID, thumbprint)` e seta o `SessionCookie`.
- **Step-up:** endpoint que exige nova asserção WebAuthn para ações sensíveis;
  marca na sessão um "step-up válido até T+curto".
- **Recuperação:** exigir 2 credenciais por operador; sem canal e-mail/SMS.
- **Aceite:** teste do fluxo com o virtual authenticator do go-webauthn (ou mock);
  `go test -race`. Ceremony real valida no navegador/VM (T8).

### T3 — Middleware mTLS do operador + CSRF (agente: dev-golang / Otávio)
- Exigir cert de cliente do operador no handshake, verificar contra a NOSSA CA
  (reusar o pool do servidor), extrair `CertThumbprint`, pôr no contexto.
- Encadear: `SecurityHeaders` → auth (sessão + thumbprint via `SessionManager.Validate`)
  → nas rotas de ESCRITA, exigir header CSRF conferido com `Session.CheckCSRF`.
- **Aceite:** teste com `tls.ConnectionState` forjado (cert da nossa pki) provando
  que cert de outra CA é recusado e que token sem o cert certo cai em
  `ErrClienteDiferente`.

### T4 — Endpoints read-only (agente: dev-golang / Otávio)
- `GET /api/agents` (lista + `Online` + últimos `hardware`/`saude`/`atualizacoes`),
  **filtrado por RBAC** aos grupos do operador. `GET /api/agents/{id}` detalhe.
- Toda leitura entra na auditoria. Sem dado de outro grupo (testar IDOR).
- **Aceite:** teste de RBAC (operador do grupo A não vê agente do grupo B) + shape JSON.

### T5 — Fila de escrita assinada no cliente (agente: dev-golang / Otávio)
- `POST /api/acoes`: recebe payload canônico + assinatura Ed25519 do operador.
  **Re-verificar** a assinatura com a pub do operador sobre os MESMOS bytes
  canônicos (função de canonicalização ÚNICA, compartilhada com o SPA), conferir
  `nonce` (anti-replay persistente), `expira_em`, RBAC e step-up; então
  **enfileirar** (reusar o caminho de `CreateSession`/jobs). O agente re-verifica
  antes de executar (defesa em profundidade).
- **Nunca** aceitar payload com serialização divergente "mesmo assim".
- **Aceite:** teste de assinatura válida/ inválida, replay de nonce recusado,
  payload adulterado recusado.

### T6 — SPA (agentes: dev-typescript / dev-javascript + builder-beta)
- React/Svelte + Vite. Login WebAuthn; grid de agentes (online/offline, nº de
  vulnerabilidades, updates pendentes, saúde); botão "Conectar" (view por padrão,
  control só com RBAC+step-up). Sem inline script/style (CSP); token só no cookie
  HttpOnly (NUNCA localStorage). Escapar todo dado vindo do agente (sem
  `dangerouslySetInnerHTML`/`v-html`).
- **Aceite:** build Vite; a página carrega sob a CSP de `console.go` sem violação
  no console do navegador (validar na VM/navegador).

### T7 — Autenticador WebCrypto (agente: dev-typescript / Daniela)
- Módulo que gera/importa a chave Ed25519 do operador **não-exportável**
  (`extractable:false`); canonicaliza o payload (igual ao servidor), calcula
  `h1=SHA-256`, confere `h1'` do que recebeu ANTES de assinar, assina os bytes
  canônicos, e **na volta verifica a assinatura** contra os mesmos bytes (prova
  "entrou e voltou igual"). Step-up WebAuthn antes de cada uso da chave.
- **Aceite:** teste no navegador: payload adulterado entre passos aborta; só o
  payload íntegro produz assinatura que o servidor (T5) aceita.

### T8 — Pentest (agentes de segurança: israel coordena; marcos/paulo + sec-typescript/sec-golang)
- **Só os agentes de segurança fazem o pentest.** Atacar a lista de superfície do
  `docs/console-seguranca.md`: bypass de WebAuthn/step-up, roubo/replay/fixação de
  sessão, token em outra máquina (binding mTLS), XSS/CSP bypass/clickjacking, CSRF
  por rota, adulteração do payload sem invalidar assinatura, canonicalização
  divergente, IDOR/RBAC, injeção no backend, rate-limit/lockout, info-leak.
- Rodar com o app em pé na VM. Reportar achados por severidade; correções voltam
  aos agentes dev. **Repetir até blindado.**
- **Aceite:** relatório de pentest + achados corrigidos e re-testados.

## Ordem sugerida
T1 → T2 → T3 → T4 → (T6 em paralelo) → T5 ↔ T7 → T8.

## Fechamento (skill fechar-ciclo)
Cada tarefa verificada: fonte única + escola (erros/lições/historico) + eduardo-dp
(erros/acertos/playbook + INDICE) + script/skill reutilizável. Só reportar pronto
após validar no artefato real (navegador/VM), nunca só no Linux.
