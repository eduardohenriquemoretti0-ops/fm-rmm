#!/usr/bin/env bash
# build.sh — compila servidor e agente para todos os sistemas em dist/.
# Uso: scripts/build.sh [versão]      (padrão: git describe)
set -euo pipefail
cd "$(dirname "$0")/.."
VER=${1:-$(git describe --tags --always --dirty 2>/dev/null || echo dev)}
GO=${GO:-go}
OUT=dist
mkdir -p "$OUT"
find "$OUT" -maxdepth 1 -type f -name 'fmrmm-*' -delete
LD="-s -w -X github.com/eduardohenriquemoretti0-ops/fm-rmm/internal/agent.Version=$VER -X main.Version=$VER"
for t in windows/amd64 windows/arm64 linux/amd64 linux/arm64 darwin/amd64 darwin/arm64; do
  os=${t%/*}; arch=${t#*/}; ext=""; [[ $os == windows ]] && ext=".exe"
  CGO_ENABLED=0 GOOS=$os GOARCH=$arch $GO build -trimpath -ldflags "$LD" -o "$OUT/fmrmm-agent-$os-$arch$ext" ./cmd/fmrmm-agent
done
# helper do indicador (só Windows; subsistema GUI = sem janela de console).
# O `fmrmm-agent install` exige fmrmm-indicator.exe na mesma pasta do instalador.
for arch in amd64 arm64; do
  CGO_ENABLED=0 GOOS=windows GOARCH=$arch $GO build -trimpath -ldflags "$LD -H=windowsgui" -o "$OUT/fmrmm-indicator-windows-$arch.exe" ./cmd/fmrmm-indicator
done
# servidor: Linux (produção) e Windows (laboratório)
for t in linux/amd64 linux/arm64 windows/amd64; do
  os=${t%/*}; arch=${t#*/}; ext=""; [[ $os == windows ]] && ext=".exe"
  CGO_ENABLED=0 GOOS=$os GOARCH=$arch $GO build -trimpath -ldflags "$LD" -o "$OUT/fmrmm-server-$os-$arch$ext" ./cmd/fmrmm-server
done
(cd "$OUT" && sha256sum fmrmm-* > SHA256SUMS)
echo "versão $VER -> $OUT/"
cat "$OUT/SHA256SUMS"
