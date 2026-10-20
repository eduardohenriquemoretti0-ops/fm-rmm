//go:build windows

package agent

import (
	"encoding/base64"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"

	"golang.org/x/sys/windows"
)

// No Windows o indicador roda num HELPER na sessão interativa do usuário (ícone
// de bandeja + balão), não via msg.exe. O serviço (SYSTEM, Session 0) não
// consegue desenhar na sessão do usuário; por isso lança o helper com
// CreateProcessAsUser no token da sessão de console ativa. O helper confirma
// visibilidade (HELLO) e manda heartbeat; sem heartbeat, a sessão encerra.

const (
	hbTimeout = 10 * time.Second // janela sem heartbeat antes de considerar perdido
	ackWait   = 8 * time.Second  // tempo para o helper confirmar visibilidade
)

type windowsNotifier struct {
	hb   *hbServer
	proc windows.Handle
	once sync.Once
}

func startNotifier(msg string) (notifier, error) {
	helper, err := helperPath()
	if err != nil {
		return nil, err // sem helper não há como avisar: fail-closed
	}
	s, err := newHBServer(hbTimeout)
	if err != nil {
		return nil, err
	}
	proc, err := launchInUserSession(helper, s.addr(), s.token(), msg)
	if err != nil {
		s.Stop()
		return nil, fmt.Errorf("lançar indicador na sessão do usuário: %w", err)
	}
	wn := &windowsNotifier{hb: s, proc: proc}
	if err := s.waitAck(ackWait); err != nil {
		wn.Stop()
		return nil, err
	}
	return wn, nil
}

func (w *windowsNotifier) Lost() <-chan struct{} { return w.hb.Lost() }

func (w *windowsNotifier) Stop() {
	w.once.Do(func() {
		w.hb.Stop() // manda QUIT: o helper retira a bandeja e sai sozinho
		// dá um tempo para a saída limpa; se não sair, derruba
		if w.proc != 0 {
			_, _ = windows.WaitForSingleObject(w.proc, 3000)
			_ = windows.TerminateProcess(w.proc, 0)
			_ = windows.CloseHandle(w.proc)
		}
	})
}

func helperPath() (string, error) {
	exe, err := os.Executable()
	if err != nil {
		return "", err
	}
	p := filepath.Join(filepath.Dir(exe), "fmrmm-indicator.exe")
	if _, err := os.Stat(p); err != nil {
		return "", fmt.Errorf("helper de indicador ausente (%s): %w", p, err)
	}
	return p, nil
}

// launchInUserSession roda exe na sessão de console ativa (a do usuário logado),
// passando addr/token/msg. Devolve o handle do processo para Stop derrubá-lo.
func launchInUserSession(exe, addr, token, msg string) (windows.Handle, error) {
	// msg vai em base64 para não brigar com aspas na linha de comando
	msgB64 := base64.StdEncoding.EncodeToString([]byte(msg))
	cmdline := windows.ComposeCommandLine([]string{exe, addr, token, msgB64})

	var proc windows.Handle
	err := withUserSession(func(primary windows.Token, envBlock *uint16) error {
		var err error
		proc, err = createProcessInSession(primary, envBlock, exe, cmdline, 0, false)
		return err
	})
	return proc, err
}
