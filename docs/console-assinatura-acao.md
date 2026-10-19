# Formato canônico da ação assinada pelo operador (T5c, contrato para o T7)

> Lei: `docs/console-seguranca.md` (§Assinatura no cliente, §Modelo de confiança).
> O operador assina NO NAVEGADOR (WebCrypto, Ed25519 não-exportável). O servidor
> NÃO assina e NÃO guarda chave de assinatura: `POST /api/acoes` confere e
> enfileira o objeto com a assinatura ORIGINAL do operador. O agente verifica
> contra o trust-set (raiz + lista de signers publicada).
> Implementação: `internal/console/acoes.go`. Vetor de teste: `TestVetorCanonicoDocumentado`
> (se a struct mudar, o teste quebra e este documento tem de mudar junto).

## Regra de ouro

Os bytes assinados são o `json.Marshal` da struct Go (`proto.JobPayload` /
`proto.RemoteGrant`), a MESMA forma que `sign.SignJob` / `sign.SignGrant` usam
e que o agente verifica hoje. O servidor:

1. verifica a assinatura sobre os bytes recebidos (nada é re-serializado antes);
2. decodifica com campos desconhecidos RECUSADOS;
3. exige que `json.Marshal(struct decodificada)` seja IGUAL, byte a byte, aos
   bytes recebidos (`payload_nao_canonico` / 400 caso contrário).

Logo: o SPA tem de produzir exatamente esta serialização. Divergência = recusa,
nunca "aceita mesmo assim".

## Regras de serialização (valem para os dois payloads)

- JSON compacto: sem espaços, sem quebra de linha, UTF-8.
- Chaves NA ORDEM DA STRUCT (tabelas abaixo), nunca ordenadas alfabeticamente.
  Única exceção: `params` (mapa), cujas chaves vão em ordem alfabética (bytes UTF-8).
- Todas as chaves obrigatórias sempre presentes. Opcionais com `omitempty`
  (`params`, `media_secret`) são OMITIDAS quando vazias; `"params":{}` e
  `"params":null` NÃO são canônicos.
- Inteiros sem sinal/expoente: `"v":1`.
- Instantes: RFC 3339 em UTC, sufixo `Z`, SEM fração de segundo quando o
  segundo é inteiro (o SPA deve truncar para segundos): `2026-10-19T12:00:00Z`.
  Offset `+00:00`, fração `.000Z` ou outro fuso NÃO são canônicos.
- Escapes de string iguais ao `encoding/json` do Go: `"`, `\`, controles
  (`\n`, `\r`, `\t`, demais `\u00XX`) e, ADICIONALMENTE, `<`, `>`, `&`, U+2028,
  U+2029 viram `<`, `>`, `&`, ` `, ` ` (minúsculas). O
  catálogo só aceita `[A-Za-z0-9._-]` nos parâmetros, então na prática isso só
  importa em `relay_url`; recomenda-se não usar esses caracteres.
- Sem `/` escapado (`wss://x/r` fica literal).

## JobPayload (`tipo: "job"`)

Ordem e tipos:

| # | chave        | tipo                 | regra                                                          |
|---|--------------|----------------------|----------------------------------------------------------------|
| 1 | `v`          | número               | sempre `1`                                                     |
| 2 | `job_id`     | string               | NONCE do anti-replay: `^[A-Za-z0-9_-]{8,64}$`, único por operador (sugestão: `job-` + 16 hex aleatórios) |
| 3 | `agent_id`   | string               | agente alvo (RBAC do técnico do operador)                      |
| 4 | `action`     | string               | item do catálogo (`catalog.Validate` para o SO do agente)      |
| 5 | `params`     | objeto string->string| OMITIR se vazio; chaves em ordem alfabética                     |
| 6 | `issued_at`  | string RFC 3339 `Z`  | não pode estar no futuro (+5 min de tolerância)                |
| 7 | `expires_at` | string RFC 3339 `Z`  | > `issued_at`; `expires_at - issued_at` <= 24 h; não vencido   |
| 8 | `issuer`     | string               | OBRIGATORIAMENTE o `id` do operador (`/api/sessao` -> `operador`) |

## RemoteGrant (`tipo: "grant"`)

| #  | chave          | tipo                | regra                                                        |
|----|----------------|---------------------|--------------------------------------------------------------|
| 1  | `v`            | número              | sempre `1`                                                   |
| 2  | `session_id`   | string              | NONCE: `^[A-Za-z0-9_-]{8,64}$` (sugestão: `ses-` + 16 hex)   |
| 3  | `agent_id`     | string              | agente alvo (RBAC)                                           |
| 4  | `technician`   | string              | OBRIGATORIAMENTE o técnico do operador (`TechName`)          |
| 5  | `mode`         | string              | `view` ou `control` (não existe modo oculto)                 |
| 6  | `engine`       | string              | `screenshot` ou `rustdesk`                                   |
| 7  | `media_secret` | string              | OMITIR se vazio; obrigatório (não vazio) com `rustdesk`      |
| 8  | `relay_url`    | string              | IGUAL ao relay configurado no servidor (o operador não escolhe) |
| 9  | `relay_token`  | string              | >= 32 caracteres, aleatório (32 bytes em base64url)          |
| 10 | `issued_at`    | string RFC 3339 `Z` | como no job                                                  |
| 11 | `expires_at`   | string RFC 3339 `Z` | > `issued_at`; duração <= 30 min                             |
| 12 | `issuer`       | string              | OBRIGATORIAMENTE o `id` do operador                          |

`relay_token` e `media_secret` são segredos: o servidor NUNCA os grava na
auditoria nem em log; no banco guarda só o hash SHA-256 do `relay_token`.

## Assinatura e encoding dos bytes

- Algoritmo: Ed25519 (RFC 8032), puro, sobre os bytes UTF-8 do JSON canônico
  (não sobre um resumo). `h1 = SHA-256(bytes)` é só para a verificação de
  integridade ida-e-volta do SPA.
- `key_id` = hex minúsculo dos 8 primeiros bytes de `SHA-256(pub de 32 bytes)` (16 hex).
- Chave pública: base64 PADRÃO com padding (`+`, `/`, `=`), 32 bytes -> 44 caracteres.
- No corpo da requisição, `payload` e `sig` são base64 PADRÃO com padding
  (é o que o `[]byte` do Go lê). `payload` é o base64 dos bytes canônicos
  (NÃO o objeto JSON embutido: o servidor precisa dos bytes exatos).
- Ed25519 no WebCrypto: `crypto.subtle.sign("Ed25519", chave, bytes)` devolve
  64 bytes. A chave precisa ser gerada com `generateKey({name:"Ed25519"}, false, ["sign","verify"])`.

## POST /api/acoes

Atrás de mTLS + cookie de sessão + header `X-FMRMM-CSRF`; exige step-up
WebAuthn recente na sessão (sem ele: 403 `{"erro":"step_up_necessario","step_up":true}`).

```json
{"tipo":"job","payload":"<base64 dos bytes canônicos>","sig":"<base64 64 bytes>","key_id":"<16 hex>"}
```

Campos desconhecidos no corpo são recusados (400). Teto do corpo: 64 KiB.

Respostas (corpo sempre `{"erro":"<codigo>"}` nas falhas):

| HTTP | código                              | significado |
|------|-------------------------------------|-------------|
| 202  | (corpo `{"job":id,"estado":"enfileirado"}` ou `{"sessao":id,...}`) | enfileirado |
| 400  | `requisicao_invalida`, `payload_nao_canonico` | corpo/forma fora do contrato |
| 401  | `assinatura_invalida`               | `key_id` != chave registrada do operador, ou assinatura não confere |
| 403  | `operador_sem_chave_de_assinatura`, `emissor_ou_nonce_invalido`, `step_up_necessario` | |
| 404  | `agente_nao_encontrado`             | sem RBAC OU inexistente (respostas idênticas) |
| 409  | `nonce_repetido`, `agente_indisponivel` | replay / agente não aprovado |
| 410  | `acao_expirada`                     | `expires_at` vencido (tolerância 5 min) |
| 422  | `acao_fora_do_catalogo`, `relay_invalido`, `validade_acima_do_maximo`, `acao_emitida_no_futuro`, `payload_invalido` | |

Ordem das checagens: cert+sessão+CSRF -> chave/`key_id` -> assinatura -> forma
canônica -> regras do payload -> issuer/technician -> RBAC -> catálogo/relay ->
step-up -> nonce + enfileirar (uma transação). Recusas ANTES do nonce não o
queimam. Cada recusa e cada enfileiramento vão para a auditoria encadeada
(`console.acao.recusada` / `console.acao.enfileirada`).

Nonce: `job_id` / `session_id`, único por operador, lembrado até
`expires_at + 6 min`; depois a própria expiração barra o replay. O mesmo id
usado por outro operador também é recusado (chave primária da fila).

## Registro da chave de assinatura: POST /api/operador/chave-assinatura

Quem registra: o PRÓPRIO operador ativo (mTLS + sessão + CSRF + step-up). Só a
PRIMEIRA vez; se já existe chave, 409 `chave_ja_definida` (troca/rotação é do
admin, fora de banda — uma sessão roubada não consegue substituir a chave).
Registrar não concede confiança no agente: a chave só vale para o agente depois
que o admin a inclui na lista de signers assinada offline pela raiz.

```json
{"signing_pub":"<base64 padrão, 44 chars>","prova":"<base64 da assinatura, 64 bytes>"}
```

`prova` = Ed25519 da própria chave sobre os bytes UTF-8 de
`"fmrmm-signing-pub-v1\n" + operator_id + "\n" + signing_pub` (prova de posse).
Resposta 201 `{"key_id":"..."}`. Erros: 400 `chave_invalida`, 401
`prova_de_posse_invalida`, 403 `step_up_necessario`, 409 `chave_ja_definida` /
`chave_indisponivel` (pública já usada por outro operador).

## Vetor de teste (reproduzir byte a byte no WebCrypto)

Seed Ed25519 (hex): `000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f`
Pública (base64): `A6EHv/POEL4dcN0Y50vAmWfk1jCbpQ1fHdyGZBJVMbg=`
`key_id`: `56475aa75463474c`

Job (`params` informado como `{b:"2", a:"1"}` -> saem ordenados):

```
{"v":1,"job_id":"job-0123456789abcdef","agent_id":"agt-0001","action":"info","params":{"a":"1","b":"2"},"issued_at":"2026-10-19T12:00:00Z","expires_at":"2026-10-19T13:00:00Z","issuer":"op-joao"}
```
- SHA-256: `8df364fb508ca9f2601e53b8b86c0aa7e995a1f9141ee4943eee2c9066689ea5`
- `sig` (base64): `7uImsymUQOmFO5OTjcMLRnISRRBfhQxabqAIbPb+XY6nk4p8Ktju1m6gaPfSBjnJpTZL3k4ekpE5EfFIUNxNBA==`

Grant:

```
{"v":1,"session_id":"ses-0123456789abcdef","agent_id":"agt-0001","technician":"joao","mode":"view","engine":"screenshot","relay_url":"wss://relay.exemplo:8443/r","relay_token":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA","issued_at":"2026-10-19T12:00:00Z","expires_at":"2026-10-19T12:10:00Z","issuer":"op-joao"}
```
- SHA-256: `4a5834875b2093aea1c42597fedf2f8f850f68044a22892896b7da5da333ace4`
- `sig` (base64): `PHu0ceiydCnUJyVTZ85iQqjsec7ZDoX66hne75JTpjBB5Gv1sPfV43NQocIE55L6jvcWD46248VMdWgyYQfhBA==`

Prova de posse (operador `op-joao`, mesma chave):
`ZQ1045ka3+2cDB2qhfuSua9cLAxBh+nUXJr81W1lcy+/ZFdNcUQB6e28qiQxClFIpAbsIBsgTsZUr2Oqe97vBA==`

(Os valores do relay/IDs acima são só do vetor; o `relay_url` real tem de ser
o configurado no servidor.)

## Entrega e verificação no agente

O servidor, no check-in, entrega o `SignedJob`/`SignedGrant` guardado (com a
assinatura do operador) após conferi-lo contra {admins em `signers.json`} U
{operadores aptos: ativos, com chave, de técnico habilitado}. A decisão final é
do agente: trust-set = raiz + lista de signers publicada (anti-downgrade),
`seen.json` (replay), `expires_at`, `agent_id`. Operador não publicado na lista
-> o agente recusa, mesmo com o servidor tendo entregue.

## Limites conhecidos (para o pentest)

- O step-up vale por janela (<= 5 min, `StepUpMaxTTL`), não é consumido por ação.
- O servidor confia que o operador gerou o nonce com entropia; unicidade é
  garantida, imprevisibilidade não (não é segredo).
- Revogação de operador no servidor (status/técnico) barra a entrega
  imediatamente; no agente só quando a nova lista (version+1) chegar.
