# Console web do FM-RMM — design de segurança (spec para construção e pentest)

> Decidido com o Eduardo (2026-10-19): front **SPA (React/Svelte + Vite)**,
> assinatura do operador no **navegador (WebCrypto)** com autenticador robusto e
> verificação de integridade do payload na ida e na volta. Meta: nenhum protocolo
> vazado, nenhum erro comum; o app será atacado pesadamente (pentest interno)
> antes de "pronto". Este documento é o alvo do pentest — se o código divergir
> daqui, é bug.

## Princípios herdados (não se cruza)
- **Chave de assinatura do admin/operador SEMPRE fora do servidor.** O servidor
  só **enfileira** jobs/sessões; quem assina é o cliente.
- **Indicador de sessão sempre visível, nada de captura oculta** (Parte 1).
- **Toda escrita é item de catálogo assinado** — nunca comando livre.
- Separação **leitura × escrita**: o dashboard inteiro (inventário, estado,
  vulnerabilidades, grid) é read-only e não assina nada. Só "rodar ação, instalar,
  abrir sessão" exige assinatura no cliente.

## Modelo de ameaça (quem queremos barrar)
1. **Phishing / AitM (Evilginx)** roubando credencial ou código → eliminado por
   WebAuthn ligado à origem (sem código para interceptar).
2. **Roubo de token de sessão** (XSS, malware local, extensão) → token de vida
   curta, ligado ao cliente (mTLS/DPoP), step-up por ação sensível.
3. **XSS / injeção no SPA** → CSP estrito sem inline, escape por framework,
   sanitização; nenhum `dangerouslySetInnerHTML`/`v-html` com dado de agente.
4. **CSRF** → cookie `SameSite=Strict` + token anti-CSRF por requisição de escrita.
5. **Adulteração do payload a assinar** (console comprometido, MITM no cliente) →
   verificação de integridade na ida e na volta (ver §Assinatura).
6. **Operador sem permissão / escalonamento** → RBAC do servidor reaproveitado;
   o console só mostra e só deixa agir sobre os grupos concedidos.
7. **Replay** → anti-replay persistente já existe no agente; o console nunca é a
   autoridade de replay.

## Autenticação do operador (sem código interceptável)
- **WebAuthn/FIDO2** (passkey ou chave física), lib `go-webauthn/webauthn`.
  Desafio-resposta por chave pública, assinatura ligada à **origem** (RPID = o
  domínio do console). Sem segredo na rede. Proxy de phishing em outro domínio
  não valida.
- **+ mTLS do operador:** além do agente, o operador recebe um cert de cliente da
  nossa CA (chave no keystore do SO, de preferência não-exportável). Dois fatores,
  os dois sem código.
- **Step-up** (re-toque WebAuthn no momento) em: abrir sessão remota,
  instalar/desinstalar, remediar, lock/wipe. Não basta o login.
- **Recuperação:** sem e-mail/SMS. Cada operador registra **duas** chaves (uma de
  backup). Perda → re-provisionamento pelo admin, fora de banda.
- **Limite honesto:** WebAuthn blinda o login, não a máquina do operador; malware
  local pode roubar o token já autenticado. Mitigação: TTL curto + step-up +
  token ligado ao cliente.

## Sessão web
- Token de sessão com **TTL curto** (ex.: 15 min) + inatividade (ex.: 10 min).
- **Ligado ao cliente**: o token só vale apresentado junto do cert mTLS do
  operador (ou DPoP com chave do dispositivo) — não vale copiado para outra
  máquina.
- Cookie `HttpOnly; Secure; SameSite=Strict; Path=/`. Nada de token em
  `localStorage` (XSS lê localStorage).
- **CSRF**: toda escrita exige header anti-CSRF (double-submit ou token por
  sessão); `SameSite=Strict` é a 1ª camada.

## Assinatura no cliente (WebCrypto) com integridade ida-e-volta
Fluxo de uma ação de escrita (ex.: abrir sessão, instalar item N no grupo G):
1. Console (SPA) monta o **payload canônico** (JSON canônico, campos ordenados,
   com `nonce`, `operador`, `expira_em`, `acao`, `alvo`). Calcula `h1 =
   SHA-256(canônico)`.
2. SPA chama o **autenticador** (camada WebCrypto): a chave privada Ed25519 é
   **não-exportável** (`extractable:false`), gerada/importada no WebCrypto e,
   quando possível, protegida por step-up WebAuthn antes de cada uso.
3. **Antes de assinar**, o autenticador **recomputa `h1'` do payload que recebeu**
   e compara com o `h1` anunciado; divergência = aborta (payload adulterado a
   caminho da assinatura).
4. Assina os **bytes canônicos exatos** (não um resumo fornecido por terceiro).
5. **Na volta**, antes de enviar ao servidor, o SPA **verifica a assinatura**
   contra os mesmos bytes canônicos e `h1` (prova de que o que voltou do
   autenticador corresponde ao que entrou — "entrou e voltou igual").
6. Servidor **re-verifica** a assinatura com a pub do operador, confere `nonce`
   (anti-replay), `expira_em`, RBAC e **enfileira**. O agente re-verifica de novo
   antes de executar (defesa em profundidade; a verificação final é no endpoint).
- **Canonicalização** é obrigatória e única em todo o caminho (mesma função no
  SPA e no servidor) — divergência de serialização = assinatura inválida, nunca
  "aceita mesmo assim".

## Endurecimento HTTP (servidor)
- **CSP** estrito: `default-src 'none'; script-src 'self'; style-src 'self';
  img-src 'self' data:; connect-src 'self'; frame-ancestors 'none';
  base-uri 'none'; form-action 'self'`. Sem `unsafe-inline`/`unsafe-eval`; o SPA
  usa nonce/hash se precisar de bootstrap inline.
- **HSTS** `max-age=63072000; includeSubDomains; preload`.
- `X-Content-Type-Options: nosniff`, `X-Frame-Options: DENY`,
  `Referrer-Policy: no-referrer`, `Permissions-Policy` negando câmera/mic/geo/usb
  que o console não usa, `Cross-Origin-Opener-Policy: same-origin`,
  `Cross-Origin-Resource-Policy: same-origin`.
- TLS só 1.2+; pinning da nossa CA onde o cliente permite.
- Cada clique que vira ação entra na **auditoria encadeada** (já existe).

## Superfície para o pentest (lista a atacar)
- Bypass de WebAuthn/step-up; fixação/roubo/replay de token de sessão; token
  válido em outra máquina (quebra do binding mTLS/DPoP).
- XSS (refletido/armazenado via nome de host/campos de inventário do agente),
  CSP bypass, clickjacking.
- CSRF em cada rota de escrita.
- Adulteração do payload entre passos 1–6 sem invalidar a assinatura;
  canonicalização divergente; downgrade de assinatura.
- IDOR/RBAC: operador agindo sobre grupo não concedido; enumeração de agentes.
- Injeção no backend Go (os parâmetros ainda passam por catalog.Validate, lista
  fechada — confirmar que o console não abre caminho fora disso).
- Rate-limit/lockout; info-leak em erros; headers ausentes.

## Onde isso valida
Browser real + autenticador FIDO2 + VM. O servidor Go é testável em unidade
(headers, sessão, RBAC, re-verificação de assinatura). O SPA e o WebCrypto
validam no navegador. Pentest interno (time de segurança) antes de "pronto".

---

## Modelo de confiança da assinatura do operador (decidido 2026-10-19: opção A)

O operador assina jobs/sessões no navegador (WebCrypto, Ed25519 não-exportável).
O endpoint passa a confiar num **CONJUNTO** de chaves, não mais numa só. A chave
de admin (raiz) continua **100% offline**.

### Lista de signers assinada e versionada
- Formato (JSON canônico): `{ "version": N, "issued_at": "<RFC3339>", "signers":
  [ { "key_id", "pub" (base64), "role": "admin"|"operator", "not_after"?:"<RFC3339>" } ] }`.
- A lista é assinada (Ed25519 destacada) pela **chave raiz offline** — a mesma cujo
  pub já vem no `bundle.SignerPub`. Adicionar/remover operador = gerar nova lista e
  assiná-la **offline** (passo de admin fora de banda; casa com o re-provisionamento
  por admin da recuperação).
- O agente ancora a confiança na chave raiz (bundle). Verifica a assinatura da
  lista contra a raiz; o **trust-set** passa a ser: chave raiz + todos os `pub` da
  lista válida mais recente.
- **Anti-downgrade:** o agente guarda a maior `version` já vista e **recusa** lista
  com `version` menor ou igual (impede replay de lista antiga que re-habilita um
  operador revogado). Rejeita também `not_after` vencido.
- **Revogação de operador:** nova lista (version+1) sem aquele signer; ao chegar no
  agente, o operador some do trust-set. (A revogação é tão rápida quanto a
  distribuição da lista.)

### Fluxo de uma ação do operador
1. Operador autenticado (WebAuthn+mTLS) + step-up monta o grant/job canônico e
   **assina com a chave de operador** (browser). Integridade ida-e-volta (§Assinatura).
2. `POST /api/acoes`: o servidor **verifica a assinatura do operador** (pub do
   operador no store), confere nonce (anti-replay persistente), `expira_em`, RBAC
   (`CanAccess(op.TechName, alvo)`) e step-up; então **enfileira o objeto assinado
   pelo operador** (o servidor NÃO re-assina, NÃO tem chave de assinatura).
3. O agente recebe e **verifica contra o trust-set** (raiz + operadores da lista),
   exatamente como já verifica hoje — anti-replay `seen.json`, `expira_em`, agentID.

### Decomposição de tarefas (adendo ao handoff)
- **T5a (dev-golang):** agente deixa de confiar em 1 pub e passa a um trust-set
  ancorado na raiz; parse+verificação da lista de signers assinada + anti-downgrade
  (persistir a maior version); `VerifyGrant`/`VerifyJob` aceitam qualquer pub do
  trust-set. Testes: lista forjada recusada, downgrade recusado, operador revogado
  deixa de valer, grant de operador no trust-set é aceito.
- **T5b (dev-golang):** store guarda a pub de assinatura do operador; ferramenta de
  admin **offline** que monta e assina a lista (não no servidor); endpoint que serve
  a lista corrente para os agentes puxarem no check-in.
- **T5c (dev-golang):** `POST /api/acoes` — verificação da assinatura do operador +
  nonce + `expira_em` + RBAC + step-up + enfileirar. Canonicalização ÚNICA,
  idêntica à do SPA (T7).
- **T7 (dev-typescript):** autenticador WebCrypto no SPA — chave Ed25519
  não-exportável, canonicalização idêntica à do servidor, assina, verifica
  ida-e-volta, envia a `/api/acoes`. Também alinhar a rota para `/api/agentes` e os
  campos ao JSON real do T4.
