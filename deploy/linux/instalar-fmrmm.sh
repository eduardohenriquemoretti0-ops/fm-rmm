#!/usr/bin/env bash
#
# instalar-fmrmm.sh — instalador do agente FM-RMM em Linux.
#
# Instala (ou atualiza) o agente como serviço systemd. Pensado para rodar por
# canal autorizado (Ansible, SSH em massa, imagem base). NÃO é instalação
# encoberta: cria serviço nomeado, com logs, e o agente mostra indicador em
# toda sessão remota.
#
# Uso:
#   sudo ./instalar-fmrmm.sh --kit URL_OU_ARQUIVO --sha256 HASH --token fmr_... \
#        [--server https://rmm.exemplo.com]
#
# O kit é o zip gerado por scripts/montar-kit.sh (binário do agente + bundle.json).
set -euo pipefail

# ---- valores que o chamador preenche (ou passa por flag) --------------------
KIT=""          # URL https do kit .zip, ou caminho de um .zip local
SHA256=""       # SHA-256 do kit (OBRIGATÓRIO quando o kit vem por URL)
TOKEN=""        # token de inscrição de uso único (só na 1ª instalação)
SERVER=""       # opcional: sobrescreve a URL do servidor (normalmente vem no bundle)

# ---- lê as flags ------------------------------------------------------------
while [ $# -gt 0 ]; do
  case "$1" in
    --kit)     KIT="$2"; shift 2 ;;      # de onde baixar/copiar o kit
    --sha256)  SHA256="$2"; shift 2 ;;   # hash esperado do kit
    --token)   TOKEN="$2"; shift 2 ;;    # token de inscrição
    --server)  SERVER="$2"; shift 2 ;;   # URL alternativa do servidor
    *) echo "flag desconhecida: $1" >&2; exit 2 ;;
  esac
done

# ---- precisa ser root (instala serviço em /etc/systemd e binário em /usr/local)
[ "$(id -u)" -eq 0 ] || { echo "rode como root (sudo)"; exit 1; }
[ -n "$KIT" ] || { echo "informe --kit"; exit 1; }

# ---- pasta de trabalho temporária, apagada ao sair --------------------------
TMP="$(mktemp -d)"                       # pasta isolada para o download
trap 'rm -rf "$TMP"' EXIT                # limpa ao terminar (sucesso ou erro)
ZIP="$TMP/kit.zip"

# ---- obtém o kit: URL https (com verificação de hash) ou arquivo local ------
case "$KIT" in
  https://*)
    # baixa por TLS; -f falha em erro HTTP, -S mostra erro, -L segue redirecionamento
    curl -fSL --proto '=https' --tlsv1.2 -o "$ZIP" "$KIT"
    [ -n "$SHA256" ] || { echo "SHA-256 é obrigatório para kit por URL"; exit 1; }
    ;;
  http://*)
    echo "HTTP sem TLS recusado; use HTTPS"; exit 1 ;;
  *)
    cp "$KIT" "$ZIP" ;;                   # kit local já confiável
esac

# ---- confere a integridade do kit antes de executar qualquer coisa ----------
if [ -n "$SHA256" ]; then
  echo "${SHA256}  ${ZIP}" | sha256sum -c -   # aborta se o hash não bater
fi

# ---- extrai e localiza o binário do agente ----------------------------------
unzip -o -q "$ZIP" -d "$TMP/kit"         # -o sobrescreve, -q silencioso
AGENT="$(find "$TMP/kit" -name 'fmrmm-agent' -type f | head -1)"
[ -n "$AGENT" ] || { echo "fmrmm-agent não encontrado no kit"; exit 1; }
chmod +x "$AGENT"
BUNDLE="$(find "$TMP/kit" -name 'bundle.json' | head -1)"
[ -n "$BUNDLE" ] || { echo "bundle.json não encontrado no kit"; exit 1; }

# ---- instala/atualiza o serviço ---------------------------------------------
# O próprio binário sabe criar a unit systemd, a pasta de dados com permissão
# restrita e iniciar o serviço (ver internal/agent/install.go). O token só é
# usado na primeira instalação; nas atualizações ele é ignorado.
ARGS=(install --bundle "$BUNDLE")
[ -n "$TOKEN" ]  && ARGS+=(--token "$TOKEN")
"$AGENT" "${ARGS[@]}"

# ---- resumo -----------------------------------------------------------------
echo
echo "FM-RMM instalado. Estado do serviço:"
systemctl --no-pager status fmrmm-agent.service | sed -n '1,4p' || true
echo
echo "Próximo passo: aprovar este agente no servidor:"
echo "  fmrmm-server agents approve <ID>   (veja 'fmrmm-server agents list')"
