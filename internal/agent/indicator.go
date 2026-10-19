package agent

import (
	"fmt"
	"log/slog"
	"os/exec"
)

// osIndicator é o indicador de sessão padrão: mostra um aviso visível no
// endpoint enquanto a sessão dura. Fail-closed: se não há como avisar o usuário
// (sem sessão gráfica, sem helper), Show devolve erro e a sessão é recusada.
//
// O trabalho específico de cada SO vive num notifier (ver indicator_unix.go e
// indicator_windows.go). O notifier confirma visibilidade (ack) e sinaliza em
// Lost() quando o aviso deixa de estar comprovadamente visível.
type osIndicator struct{ log *slog.Logger }

// NewOSIndicator cria o indicador padrão do sistema.
func NewOSIndicator(log *slog.Logger) Indicator { return &osIndicator{log: log} }

func (o *osIndicator) Show(sessionID, technician, mode string) (func(), <-chan struct{}, error) {
	msg := fmt.Sprintf("Sessão de suporte remoto ATIVA — técnico %s (%s). Sessão %s.", technician, mode, sessionID)
	n, err := startNotifier(msg)
	if err != nil {
		return nil, nil, err
	}
	o.log.Info("indicador de sessão visível aceso", "sessao", sessionID, "tecnico", technician)
	stop := func() {
		n.Stop()
		o.log.Info("indicador de sessão apagado", "sessao", sessionID)
	}
	return stop, n.Lost(), nil
}

// notifier é o backend do indicador por SO. startNotifier só retorna sem erro
// após confirmar que o aviso está visível. Lost() emite/fecha quando o aviso
// deixa de estar comprovadamente visível.
type notifier interface {
	Lost() <-chan struct{}
	Stop()
}

func run(name string, args ...string) error {
	p, err := exec.LookPath(name)
	if err != nil {
		return err
	}
	return exec.Command(p, args...).Run()
}
