//go:build linux || darwin

package agent

import (
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
)

// captureScreen fotografa a tela e devolve os bytes PNG. Tenta as ferramentas
// comuns de cada sistema; se nenhuma existir ou não houver sessão gráfica,
// devolve erro (a sessão então encerra com motivo claro — nunca quadro falso).
func captureScreen() ([]byte, error) {
	tmp := filepath.Join(os.TempDir(), "fmrmm-frame.png")
	defer os.Remove(tmp)
	var tries [][]string
	if runtime.GOOS == "darwin" {
		tries = [][]string{{"screencapture", "-x", "-t", "png", tmp}}
	} else { // linux: wayland (grim), GNOME, ImageMagick, scrot
		tries = [][]string{
			{"grim", tmp},
			{"gnome-screenshot", "-f", tmp},
			{"import", "-window", "root", tmp},
			{"scrot", "-o", tmp},
		}
	}
	var last error
	for _, t := range tries {
		bin, err := exec.LookPath(t[0])
		if err != nil {
			last = err
			continue
		}
		if err := exec.Command(bin, t[1:]...).Run(); err != nil {
			last = err
			continue
		}
		b, err := os.ReadFile(tmp)
		if err == nil && len(b) > 0 {
			return b, nil
		}
		last = err
	}
	if last == nil {
		last = errors.New("nenhuma ferramenta de captura encontrada")
	}
	return nil, last
}
