//go:build windows

package agent

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"os/exec"
	"path/filepath"
	"time"

	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/svc"
	"golang.org/x/sys/windows/svc/mgr"
)

func DataDir() string {
	pd := os.Getenv("ProgramData")
	if pd == "" {
		pd = `C:\ProgramData`
	}
	return filepath.Join(pd, "FM-RMM")
}

func BinaryPath() string {
	pf := os.Getenv("ProgramFiles")
	if pf == "" {
		pf = `C:\Program Files`
	}
	return filepath.Join(pf, "FM-RMM", "fmrmm-agent.exe")
}

func uptimeSeconds() int64 { return int64(windows.DurationSinceBoot() / time.Second) }

func isAdmin() bool {
	tok := windows.GetCurrentProcessToken()
	return tok.IsElevated()
}

// secureDir: só SYSTEM (S-1-5-18) e Administradores (S-1-5-32-544), sem herança.
// SIDs em vez de nomes: funciona em Windows de qualquer idioma.
func secureDir(dir string) error {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	out, err := exec.Command(filepath.Join(os.Getenv("SystemRoot"), "System32", "icacls.exe"), dir,
		"/inheritance:r", "/grant:r", "*S-1-5-18:(OI)(CI)F", "*S-1-5-32-544:(OI)(CI)F").CombinedOutput()
	if err != nil {
		return fmt.Errorf("icacls: %v: %s", err, out)
	}
	return nil
}

func installService(bin string) error {
	m, err := mgr.Connect()
	if err != nil {
		return err
	}
	defer m.Disconnect()
	cfg := mgr.Config{
		DisplayName:  "FM-RMM Agente",
		Description:  "Agente de gestão FM-RMM (Fratelli Moretti). Conexão só de saída, ações de catálogo assinadas.",
		StartType:    mgr.StartAutomatic,
		ErrorControl: mgr.ErrorNormal,
		// ServiceStartName vazio = LocalSystem
	}
	s, err := m.OpenService(ServiceName)
	if err == nil {
		defer s.Close()
		cur, err := s.Config()
		if err != nil {
			return err
		}
		cur.BinaryPathName = `"` + bin + `" service`
		cur.DisplayName, cur.Description, cur.StartType = cfg.DisplayName, cfg.Description, cfg.StartType
		if err := s.UpdateConfig(cur); err != nil {
			return err
		}
	} else {
		s, err = m.CreateService(ServiceName, bin, cfg, "service")
		if err != nil {
			return err
		}
		defer s.Close()
	}
	// reinicia sozinho se cair: 3 tentativas com 1 min, zera em 1 dia
	return s.SetRecoveryActions([]mgr.RecoveryAction{
		{Type: mgr.ServiceRestart, Delay: time.Minute},
		{Type: mgr.ServiceRestart, Delay: time.Minute},
		{Type: mgr.ServiceRestart, Delay: 5 * time.Minute},
	}, 86400)
}

func withService(f func(*mgr.Service) error) error {
	m, err := mgr.Connect()
	if err != nil {
		return err
	}
	defer m.Disconnect()
	s, err := m.OpenService(ServiceName)
	if err != nil {
		return err
	}
	defer s.Close()
	return f(s)
}

func startService() error {
	return withService(func(s *mgr.Service) error {
		if err := s.Start(); err != nil && !errors.Is(err, windows.ERROR_SERVICE_ALREADY_RUNNING) {
			return err
		}
		return nil
	})
}

func stopService() error {
	return withService(func(s *mgr.Service) error {
		st, err := s.Control(svc.Stop)
		if err != nil {
			return err
		}
		for i := 0; i < 30 && st.State != svc.Stopped; i++ {
			time.Sleep(time.Second)
			if st, err = s.Query(); err != nil {
				return err
			}
		}
		if st.State != svc.Stopped {
			return errors.New("serviço não parou em 30 s")
		}
		return nil
	})
}

func removeService() error {
	err := withService(func(s *mgr.Service) error { return s.Delete() })
	if errors.Is(err, windows.ERROR_SERVICE_DOES_NOT_EXIST) {
		return nil
	}
	return err
}

func indicatorHelperPath() string {
	return filepath.Join(filepath.Dir(BinaryPath()), "fmrmm-indicator.exe")
}

// installHelper copia o fmrmm-indicator.exe que veio junto do instalador para o
// lado do agente. Obrigatório no Windows: o serviço o lança na sessão do usuário.
func installHelper(srcExe string) error {
	src := filepath.Join(filepath.Dir(srcExe), "fmrmm-indicator.exe")
	if _, err := os.Stat(src); err != nil {
		return fmt.Errorf("fmrmm-indicator.exe precisa estar junto do instalador (%s): %w", src, err)
	}
	return copyBinary(src, indicatorHelperPath())
}

func removeHelper() { _ = os.Remove(indicatorHelperPath()) }

func removeBinary(bin string) {
	_ = os.Remove(bin)
	_ = os.Remove(filepath.Dir(bin)) // só some se estiver vazia
}

// IsService diz se o processo foi iniciado pelo Gerenciador de Serviços.
func IsService() bool {
	ok, err := svc.IsWindowsService()
	return err == nil && ok
}

type winService struct {
	run func(ctx context.Context)
	log *slog.Logger
}

func (w *winService) Execute(_ []string, req <-chan svc.ChangeRequest, st chan<- svc.Status) (bool, uint32) {
	st <- svc.Status{State: svc.StartPending}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan struct{})
	go func() { w.run(ctx); close(done) }()
	st <- svc.Status{State: svc.Running, Accepts: svc.AcceptStop | svc.AcceptShutdown}
	for {
		select {
		case c := <-req:
			switch c.Cmd {
			case svc.Interrogate:
				st <- c.CurrentStatus
			case svc.Stop, svc.Shutdown:
				st <- svc.Status{State: svc.StopPending}
				cancel()
				select {
				case <-done:
				case <-time.After(20 * time.Second):
				}
				return false, 0
			}
		case <-done:
			return false, 0
		}
	}
}

// RunService entrega o loop ao Gerenciador de Serviços do Windows.
func RunService(run func(ctx context.Context), log *slog.Logger) error {
	return svc.Run(ServiceName, &winService{run: run, log: log})
}
