//go:build !windows

package agent

import (
	"fmt"
	"runtime"
	"sync"
	"time"
)

// No Linux/macOS o aviso é um toast crítico do SO. Não há helper de sessão como
// no Windows; a "prova de visibilidade" é o próprio disparo do toast (fail-closed
// se não há como avisar). A liveness é reafirmada a cada 30s — se a reafirmação
// falhar, perdemos a garantia de aviso e sinalizamos Lost (a sessão encerra).
type unixNotifier struct {
	lost chan struct{}
	done chan struct{}
	once sync.Once
}

func startNotifier(msg string) (notifier, error) {
	if err := notifyOnce(msg); err != nil {
		return nil, err
	}
	n := &unixNotifier{lost: make(chan struct{}), done: make(chan struct{})}
	go n.reassert(msg)
	return n, nil
}

func (n *unixNotifier) reassert(msg string) {
	t := time.NewTicker(30 * time.Second)
	defer t.Stop()
	for {
		select {
		case <-n.done:
			return
		case <-t.C:
			if err := notifyOnce(msg); err != nil {
				n.once.Do(func() { close(n.lost) })
				return
			}
		}
	}
}

func (n *unixNotifier) Lost() <-chan struct{} { return n.lost }

func (n *unixNotifier) Stop() { close(n.done) }

// notifyOnce dispara um aviso visível. Erro = não há como exibir (fail-closed).
func notifyOnce(msg string) error {
	switch runtime.GOOS {
	case "darwin":
		scr := fmt.Sprintf(`display notification %q with title "FM-RMM" subtitle "Sessão remota ativa"`, msg)
		if err := run("osascript", "-e", scr); err != nil {
			return fmt.Errorf("osascript falhou: %v", err)
		}
		return nil
	default: // linux e afins: exige sessão gráfica; sem DISPLAY, notify-send falha
		if err := run("notify-send", "-u", "critical", "-t", "35000", "FM-RMM", msg); err != nil {
			if err2 := run("wall", msg); err2 != nil {
				return fmt.Errorf("sem meio de avisar o usuário: %v", err)
			}
		}
		return nil
	}
}
