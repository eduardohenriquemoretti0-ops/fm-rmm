package agent

import (
	"fmt"
	"log/slog"
	"os/exec"
	"runtime"
	"time"
)

// osIndicator é o indicador de sessão padrão: mostra um aviso visível no
// endpoint enquanto a sessão dura. Fail-closed: se não há como avisar o
// usuário (ex.: sem sessão gráfica), Show devolve erro e a sessão é recusada.
type osIndicator struct{ log *slog.Logger }

// NewOSIndicator cria o indicador padrão do sistema.
func NewOSIndicator(log *slog.Logger) Indicator { return &osIndicator{log: log} }

func (o *osIndicator) Show(sessionID, technician, mode string) (func(), error) {
	msg := fmt.Sprintf("Sessão de suporte remoto ATIVA — técnico %s (%s). Sessão %s.", technician, mode, sessionID)
	notify, err := startNotifier(msg)
	if err != nil {
		return nil, err
	}
	o.log.Info("indicador de sessão visível aceso", "sessao", sessionID, "tecnico", technician)
	stopped := make(chan struct{})
	// reafirma o aviso periodicamente (um toast some sozinho)
	go func() {
		t := time.NewTicker(30 * time.Second)
		defer t.Stop()
		for {
			select {
			case <-stopped:
				return
			case <-t.C:
				if n, err := startNotifier(msg); err == nil {
					_ = n
				}
			}
		}
	}()
	return func() {
		close(stopped)
		notify()
		o.log.Info("indicador de sessão apagado", "sessao", sessionID)
	}, nil
}

// startNotifier dispara o aviso visível do SO. Retorna uma função que o retira
// (quando aplicável). Erro = não há como exibir -> sessão recusada.
func startNotifier(msg string) (func(), error) {
	switch runtime.GOOS {
	case "linux":
		// exige uma sessão gráfica; sem DISPLAY, notify-send falha (fail-closed)
		if err := run("notify-send", "-u", "critical", "-t", "35000", "FM-RMM", msg); err != nil {
			if err2 := run("wall", msg); err2 != nil {
				return nil, fmt.Errorf("sem meio de avisar o usuário: %v", err)
			}
		}
		return func() {}, nil
	case "darwin":
		scr := fmt.Sprintf(`display notification %q with title "FM-RMM" subtitle "Sessão remota ativa"`, msg)
		if err := run("osascript", "-e", scr); err != nil {
			return nil, fmt.Errorf("osascript falhou: %v", err)
		}
		return func() {}, nil
	case "windows":
		// aviso visível na sessão interativa; msg.exe existe no Windows cliente
		if err := run("msg", "*", "/TIME:0", msg); err != nil {
			return nil, fmt.Errorf("msg.exe falhou (sem usuário interativo?): %v", err)
		}
		return func() {}, nil
	}
	return nil, fmt.Errorf("sistema sem indicador de sessão: %s", runtime.GOOS)
}

func run(name string, args ...string) error {
	p, err := exec.LookPath(name)
	if err != nil {
		return err
	}
	return exec.Command(p, args...).Run()
}
