# FM-RMM

![Go](https://img.shields.io/badge/Go-1.x-00ADD8?logo=go&logoColor=white)
![Status: testado em VM real](https://img.shields.io/badge/status-testado%20em%20VM%20real-success)
![Plataformas](https://img.shields.io/badge/plataformas-Windows%20%7C%20Linux%20%7C%20macOS-informational)
![Testes: go test -race](https://img.shields.io/badge/testes-go%20test%20--race-brightgreen)
![Segurança: mTLS + Ed25519](https://img.shields.io/badge/seguran%C3%A7a-mTLS%20%2B%20Ed25519-critical)

**RMM e acesso remoto autorizado, self-hosted, escrito em Go — com segurança de nível de infraestrutura no centro do projeto, não como remendo.** Cada agente usa **mTLS** com CA própria revogável; jobs e sessões são **assinados em Ed25519 por uma chave de admin que nunca fica no servidor**, com anti-replay persistente, catálogo de ações fechado, RBAC, inscrição por token + aprovação e **auditoria append-only encadeada por hash**. O indicador de sessão é **sempre visível e fail-closed**: por decisão ética e de LGPD, o projeto **recusou implementar captura oculta (RAT)**. Validado em VM real, com build nos três sistemas operacionais e `go test -race`; dois binários (servidor + agente) e SQLite sem cgo. Inclui RustDesk self-hosted endurecido no Windows.

Canal de controle e **acesso remoto autorizado** self-hosted para um parque de
máquinas Windows, Linux e macOS sob gestão de TI. Servidor e agente próprios,
em Go, com controles mais rígidos que os de um RMM genérico.

> **Uso pretendido:** gestão e suporte remoto **autorizados** de endpoints de um
> cliente sob contrato, com consentimento no nível da organização. Não é
> ferramenta de acesso encoberto. Instalação por canal documentado (GPO / pacote
> assinado). Veja "Escopo e limites" abaixo.

## O que está construído

Dois binários, um módulo:

- `fmrmm-server` — servidor de controle + console de administração (CLI) + relay
  de sessão. Banco SQLite (Go puro, sem cgo).
- `fmrmm-agent` — agente/serviço no endpoint. Conexão **só de saída** na 443,
  nunca escuta porta.

### Controles de segurança (todos implementados)

1. **mTLS com certificado por agente** (CA própria). Sem certificado emitido por
   nós, o agente não conecta. Revogável.
2. **Inscrição com aprovação** — token de uso único **e** aprovação manual no
   servidor. Sem auto-join.
3. **Jobs e sessões assinados** (Ed25519) por uma chave de **administrador que
   fica fora do servidor**. Servidor comprometido não fabrica comando aceito.
4. **Catálogo de ações fechado** — sem "rode qualquer comando". Parâmetros só
   aceitam valores de uma lista. 8 ações (7 só leitura + reiniciar serviço de
   lista fixa).
5. **Anti-replay** — cada job/sessão vale uma vez, com validade e proteção que
   sobrevive a reinício do agente.
6. **Auditoria append-only encadeada por hash** — adulterar, apagar ou reordenar
   qualquer linha quebra a cadeia; `audit verify` acusa. O servidor não sobe
   sobre cadeia quebrada.
7. **Certificate pinning** — o agente só aceita a nossa CA.
8. **Indicador de sessão sempre visível** — toda sessão remota acende um aviso no
   endpoint **antes** de qualquer mídia. Sem indicador, a sessão é recusada
   (fail-closed). Não há modo de desligar o indicador.
9. **Auditoria por sessão** — autorização, início, indicador, fim: quem, quando,
   qual máquina, qual técnico.
10. **RBAC por máquina/grupo** — cada técnico só acessa os grupos concedidos
    (`*` = todas).
11. **Menor exposição** — o agente não tem instalação silenciosa fora de banda,
    nem anti-desinstalação, nem ocultação de processo.

## Escopo e limites (decisão de projeto)

- **Acesso remoto:** este repositório entrega a **camada de autorização e
  sinalização** (inscrição, mTLS, concessão assinada, RBAC, indicador,
  auditoria, relay). O **plano de mídia** (tela/teclado/mouse) é uma interface
  (`SessionMedia`) com dois motores:
  - `screenshot` (Linux/macOS): captura a tela em quadros PNG pelo nosso relay
    (modo view, só leitura; fail-closed sem captura);
  - `rustdesk` (Windows): integra o **RustDesk self-hosted endurecido**, que
    resolve a captura da área de trabalho a partir do serviço (Session 0). Os
    pixels passam pelo hbbr do RustDesk; o nosso canal assinado leva só a
    autorização e o ID. Endurecimento: só o **nosso hbbs/hbbr** com a **nossa
    chave** (pinning), **senha de uso único por sessão** (vem na concessão
    assinada, limpa no fim), sem senha permanente de acesso desatendido, e
    permissões por modo (view desliga teclado/clipboard/arquivo). O motor é
    escolhido automaticamente pelo SO do agente (`session new --engine` força).
- **Não existe "modo de captura oculta".** O briefing descrevia um "Modo
  Perda/Roubo" com captura sem indicador. Isso **não foi implementado**: uma
  função cujo objetivo é capturar a tela sem o usuário saber é, em código,
  vigilância encoberta — a mesma capacidade de um RAT —, é juridicamente frágil
  (LGPD/TST exigem transparência prévia) e faria o EDR do cliente classificar o
  deploy como atividade maliciosa. O indicador é sempre ligado.

## Como rodar (laboratório)

```bash
scripts/build.sh                 # compila para Windows, Linux e macOS em dist/

# no servidor (uma vez):
fmrmm-server init   --dir /var/lib/fmrmm-server --hosts rmm.exemplo.com
fmrmm-server keygen --out admin.key               # GUARDE FORA DO SERVIDOR
fmrmm-server bundle --dir /var/lib/fmrmm-server --url https://rmm.exemplo.com --key admin.key --out bundle.json
fmrmm-server serve  --dir /var/lib/fmrmm-server --listen :443 --relay :8443

# inscrever uma máquina:
fmrmm-server token  --dir /var/lib/fmrmm-server          # gera o token (uma vez)
# no endpoint (Administrador/root):
fmrmm-agent install --bundle bundle.json --token fmr_...
fmrmm-server agents --dir /var/lib/fmrmm-server approve ag-xxxx

# ação de catálogo (só leitura):
fmrmm-server jobs   --dir /var/lib/fmrmm-server new --key admin.key --agent ag-xxxx --action info

# acesso remoto autorizado:
fmrmm-server techs   --dir /var/lib/fmrmm-server grant joao '*'
fmrmm-server session --dir /var/lib/fmrmm-server new --key admin.key --agent ag-xxxx --tech joao --mode view --relay-url wss://rmm.exemplo.com:8443
```

`fmrmm-server catalog` lista as ações. `fmrmm-server audit verify` confere a
trilha. O agente roda como serviço (SYSTEM no Windows, root via systemd/launchd).

## Estado e TODOs

Pronto e testado (unitário + ponta a ponta + binários reais no Linux):
inscrição, aprovação, mTLS, pinning, jobs assinados, catálogo, anti-replay,
revogação, auditoria encadeada, RBAC, concessão de sessão, relay, indicador.

Pendente:
- plano de mídia real (integrar RustDesk endurecido atrás de `SessionMedia`);
- NAT traversal / P2P antes do relay;
- egress allow-list no cliente (regra de firewall liberando só o nosso servidor);
- console web (hoje a administração é por CLI);
- teste do serviço real nas VMs Windows (`fm-lab-win10`) e macOS.

## Testes

```bash
go test -race ./...
```
