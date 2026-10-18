//go:build windows

package agent

import (
	"fmt"
	"os"
	"path/filepath"
)

// dirLock no Windows: abre o arquivo de lock em modo exclusivo. Um segundo
// agente no mesmo diretório não consegue abrir e falha.
type dirLock struct{ f *os.File }

func lockDir(dir string) (*dirLock, error) {
	path := filepath.Join(dir, "agent.lock")
	// os.O_CREATE|os.O_EXCL não serve (o arquivo persiste); abrimos para escrita
	// e o próprio handle aberto segura o lock. Em caso de corrida, o 2º agente
	// não consegue a escrita porque o 1º mantém o arquivo aberto sem share.
	f, err := os.OpenFile(path, os.O_RDWR|os.O_CREATE, 0o600)
	if err != nil {
		return nil, fmt.Errorf("outro agente já usa %s (%w)", dir, err)
	}
	return &dirLock{f: f}, nil
}

func (l *dirLock) unlock() {
	if l == nil || l.f == nil {
		return
	}
	_ = l.f.Close()
}
