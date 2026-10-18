#!/usr/bin/env bash
# montar-kit.sh — monta os pacotes de instalação do agente para UM servidor.
#
# Cada kit = binário do agente + bundle.json (CA + chave pública do admin + URL).
# O bundle é público (não tem segredo). O token de inscrição NÃO vai no kit:
# ele é informado na implantação (Action1 ou linha de comando).
#
# Uso: scripts/montar-kit.sh bundle.json [dist]
set -euo pipefail
BUNDLE=$(realpath "${1:?uso: montar-kit.sh bundle.json [dist]}")
DIST=$(realpath "${2:-dist}")
[[ -f $DIST/SHA256SUMS ]] || { echo "rode scripts/build.sh antes" >&2; exit 1; }
KIT=$DIST/kits
mkdir -p "$KIT"
find "$KIT" -maxdepth 1 -type f -name 'fmrmm-kit-*.zip' -delete
TMP=$(mktemp -d)
trap 'find "$TMP" -mindepth 1 -delete; rmdir "$TMP"' EXIT
for f in "$DIST"/fmrmm-agent-*; do
  nome=$(basename "$f"); plat=${nome#fmrmm-agent-}; plat=${plat%.exe}
  ext=""; [[ $nome == *.exe ]] && ext=".exe"
  d="$TMP/$plat"; mkdir -p "$d"
  cp "$f" "$d/fmrmm-agent$ext"
  cp "$BUNDLE" "$d/bundle.json"
  (cd "$d" && zip -q -X "$KIT/fmrmm-kit-$plat.zip" "fmrmm-agent$ext" bundle.json)
done
(cd "$KIT" && sha256sum fmrmm-kit-*.zip | tee SHA256SUMS)
