//go:build !windows

package main

import (
	"fmt"
	"os"
)

// O helper de indicador só existe no Windows (bandeja + balão na sessão do
// usuário). Nos outros SOs o indicador é um toast do próprio SO (ver
// internal/agent/indicator_unix.go), sem helper separado.
func main() {
	fmt.Fprintln(os.Stderr, "fmrmm-indicator: só suportado no Windows")
	os.Exit(1)
}
