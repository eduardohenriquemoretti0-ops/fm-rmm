//go:build !windows

package agent

import (
	"fmt"
	"os"
	"path/filepath"

	"golang.org/x/sys/unix"
)

// dirLock impede dois agentes de usarem o mesmo diretório de dados ao mesmo
// tempo (isso corromperia state.json/seen.json). No Unix usa flock; no Windows,
// a abertura exclusiva do arquivo de lock. O lock cai sozinho quando o processo
// termina.
type dirLock struct{ f *os.File }

func lockDir(dir string) (*dirLock, error) {
	path := filepath.Join(dir, "agent.lock")
	f, err := os.OpenFile(path, os.O_RDWR|os.O_CREATE, 0o600)
	if err != nil {
		return nil, err
	}
	if err := unix.Flock(int(f.Fd()), unix.LOCK_EX|unix.LOCK_NB); err != nil {
		f.Close()
		return nil, fmt.Errorf("outro agente já usa %s (%w)", dir, err)
	}
	return &dirLock{f: f}, nil
}

func (l *dirLock) unlock() {
	if l == nil || l.f == nil {
		return
	}
	_ = unix.Flock(int(l.f.Fd()), unix.LOCK_UN)
	_ = l.f.Close()
}
