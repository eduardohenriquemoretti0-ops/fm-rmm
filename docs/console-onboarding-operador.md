# Onboarding de operador do console — runbook do admin

Provisiona um operador do console (FM-RMM) do zero até o agente aceitar as ações
assinadas por ele. Serve para o pentest (T8) e para uso real. Referências:
`console-seguranca.md` (modelo de ameaça, recuperação) e
`console-handoff-agentes.md`.

Convenções: `D` = diretório do servidor (`/var/lib/fmrmm-server`), `OPID` = id do
operador (ex.: `op-d3c854c58337688b`). Os passos 1-3, 6 e 7 (export/publish) rodam
no servidor; **o passo 7 (build) roda OFFLINE** com a chave raiz.

## Regras que o runbook respeita
- O **grupo/acesso do operador é o do técnico** ao qual ele está ligado (sem RBAC novo).
- Recuperação = **duas chaves WebAuthn** por operador (principal + backup), sem
  e-mail/SMS. Troca de chave de assinatura é **só do admin**, fora de banda.
- A **raiz nunca fica no servidor**. Cadastrar a chave de assinatura NÃO dá
  confiança ao agente: só a lista assinada offline (passo 7) dá.

## Ordem real (importante)
O login exige operador **ativo**, e a rota `POST /api/operador/chave-assinatura`
exige sessão (login + step-up). Logo a **ativação vem ANTES do cadastro da chave
de assinatura** (um operador `pendente` não consegue logar nem cadastrar a
chave). A ordem abaixo já reflete isso.

## 1. Técnico e grupo
```bash
fmrmm-server techs --dir D list
fmrmm-server techs --dir D add joao              # se ainda não existe
fmrmm-server techs --dir D grant joao lab        # grupo(s) que o operador poderá ver/agir ('*' = todos)
```

## 2. Criar o operador (status `pendente`)
```bash
fmrmm-server operadores create --dir D --tech joao --nome "Maria Silva" [--display "Maria S."]
# imprime o id: op-xxxxxxxxxxxxxxxx   (anote como OPID)
```

## 3. Emitir o cert de cliente (mTLS) por CSR (PRODUÇÃO) e importar no navegador
A chave privada do operador **nunca sai da máquina dele**.

```bash
# (a) NA MÁQUINA DO OPERADOR (basta o binário fmrmm-server; não precisa de --dir):
fmrmm-server operadores csr --nome "Maria Silva" --out ./meu-cert
#   grava operador.key (0600, FICA AQUI) e operador.csr -> envie SÓ o operador.csr ao admin

# (b) NO SERVIDOR/ADMIN (recebeu operador.csr):
fmrmm-server operadores assinar-csr --dir D --id OPID --csr operador.csr --out ./cert-OPID
#   valida o CSR (assinatura, P-256/Ed25519), emite operador.crt + ca.crt, registra o thumbprint.
#   Recusa se o operador já tem cert (use --reemitir; invalida o anterior).
#   Devolva operador.crt e ca.crt (públicos) ao operador.

# (c) NA MÁQUINA DO OPERADOR, com a operador.key local:
openssl pkcs12 -export -inkey ./meu-cert/operador.key -in operador.crt \
  -certfile ca.crt -out operador.p12        # pede uma senha de exportação
```
O CN do CSR é ignorado: o servidor impõe o id do operador e o perfil de operador
no cert. Importe `operador.p12` no navegador (Configurações > Certificados >
Seus certificados) e `ca.crt` como autoridade confiável. Depois apague o `.p12`
(a `operador.key` fica só na máquina do operador, protegida).

> **`operadores cert` (modo direto) é SÓ PARA LAB.** Ele gera a chave privada no
> servidor e a grava em disco para entrega; não use em produção. Reemitir
> (`--reemitir`, em ambos os modos) invalida o cert anterior.

Subir o console (se ainda não está no ar):
```bash
fmrmm-server serve --dir D --console-addr :9443 --rp-id rmm.exemplo.com \
  --rp-origin https://rmm.exemplo.com:9443 --web-dist web/dist --relay-url wss://rmm.exemplo.com:8443
```

## 4. Registro WebAuthn com DUAS chaves (operador, no console)
No navegador com o cert importado, abra `https://rmm.exemplo.com:9443`, informe o
OPID e registre **a chave principal e a de backup** (rotas `/api/registro/inicio`
e `/api/registro/fim`, que só funcionam com o operador `pendente`). Verifique:
```bash
fmrmm-server operadores list --dir D     # CREDENCIAIS deve ser 2, TEM_CERT true
```

## 5. Ativar o operador (admin)
```bash
fmrmm-server operadores activate --dir D --id OPID
# recusa se não houver cert ou se houver menos de 2 credenciais WebAuthn
```

## 6. Cadastrar a chave de assinatura (operador, no console)
Agora o operador loga (WebAuthn + mTLS). No SPA, o navegador gera o par Ed25519
**não exportável** e chama `POST /api/operador/chave-assinatura` (sessão + CSRF +
step-up + prova de posse). Só a **primeira** vez; troca é do admin. Verifique:
```bash
fmrmm-server operadores list --dir D     # TEM_SIGNING_PUB true
```

## 7. Lista de signers (admin, chave raiz OFFLINE)
```bash
# no servidor:
fmrmm-server signers --dir D export --out export.json
# na máquina OFFLINE da raiz (leve export.json por mídia):
fmrmm-server signers build --key admin.key --export export.json --out ./lista
#   gera ./lista/trust-list.json e ./lista/trust-list.sig
# de volta ao servidor (SignerID = o do bundle, ver `bundle`/bundle.json):
fmrmm-server signers --dir D publish --raiz KEYID_RAIZ \
  --lista ./lista/trust-list.json --sig ./lista/trust-list.sig
```
Só entram na lista operadores **ativos, com chave de assinatura e de técnico não
desabilitado**. O publish confere a raiz e só aceita versão maior.

## 8. Agentes
Cada agente recebe a lista no próximo check-in (intervalo `--interval`, padrão
60 s), valida a assinatura da raiz e passa a aceitar as ações assinadas pelo
operador. Teste: o operador cria uma ação de baixo risco no console e confira
`fmrmm-server jobs --dir D list` e `audit --dir D list --tail 20`.

## Operações do dia a dia
- Estado de todos: `fmrmm-server operadores list --dir D`
  (colunas: ID, TÉCNICO, NOME, STATUS, TEM_CERT, CREDENCIAIS, TEM_SIGNING_PUB).
- Desligar um operador: `techs disable NOME` (sai da lista no próximo `export`/publish).
- Perdeu as duas chaves ou a chave de assinatura: re-provisionamento pelo admin,
  fora de banda (novo operador ou intervenção no banco); não existe recuperação por e-mail/SMS.
- Toda etapa do admin é registrada na auditoria encadeada
  (`operador.criado`, `operador.cert.emitido` (campo `modo`: csr), `operador.ativado`).
