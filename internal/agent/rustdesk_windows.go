//go:build windows

package agent

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"
)

// rustdeskMedia integra o RustDesk self-hosted ENDURECIDO como plano de mídia
// no Windows. Resolve o problema de Session 0: o serviço do RustDesk captura a
// área de trabalho do usuário (o nosso agente em SYSTEM não consegue sozinho).
//
// O serviço do RustDesk roda como LocalService e guarda config e ID no PERFIL
// do LocalService. Nosso agente roda como SYSTEM (outro perfil). Por isso as
// chamadas ao rustdesk.exe (--option, --password, --get-id) são executadas NA
// CONTA LocalService, via tarefa agendada, para acertarem o perfil do serviço.
//
// Endurecimento por sessão:
//   - aponta o RustDesk só para o NOSSO hbbs/hbbr, com a NOSSA chave (pinning);
//   - senha de USO ÚNICO por sessão (vem na concessão assinada), limpa no fim;
//   - sem senha permanente de acesso desatendido fora da sessão autorizada;
//   - permissões por modo (view desliga teclado/clipboard/arquivo);
//   - indicador do RustDesk e o nosso ficam visíveis; nada é ocultado.
//
// Os pixels passam pelo hbbr do RustDesk; o nosso canal (conn) leva só o
// controle: informa ao console o ID do RustDesk desta máquina.
type rustdeskMedia struct {
	log     *slog.Logger
	exe     string
	host    string
	key     string
	workDir string // onde gravar a saída capturada das chamadas LocalService
}

func NewRustDeskMedia(log *slog.Logger, host, key string) SessionMedia {
	return &rustdeskMedia{log: log, exe: rustdeskExe(), host: host, key: key, workDir: DataDir()}
}

func rustdeskExe() string {
	for _, p := range []string{
		filepath.Join(os.Getenv("ProgramFiles"), "RustDesk", "RustDesk.exe"),
		filepath.Join(os.Getenv("ProgramW6432"), "RustDesk", "RustDesk.exe"),
	} {
		if p != "" {
			if _, err := os.Stat(p); err == nil {
				return p
			}
		}
	}
	return `C:\Program Files\RustDesk\RustDesk.exe`
}

const rdTask = "FMRMM-RustDesk-cfg"

// rdLocalService roda `rustdesk.exe <args>` NA CONTA LocalService (mesma do
// serviço) via tarefa agendada e devolve o que o RustDesk escreveu no stdout.
func (m *rustdeskMedia) rdLocalService(ctx context.Context, args ...string) (string, error) {
	outFile := filepath.Join(m.workDir, "rd-out.txt")
	_ = os.Remove(outFile)
	// cmd /c " "exe" args > out 2>&1 "  — aspas internas dobradas para o schtasks
	inner := fmt.Sprintf(`cmd /c ""%s" %s > "%s" 2>&1"`, m.exe, strings.Join(args, " "), outFile)
	run := func(a ...string) error {
		cctx, cancel := context.WithTimeout(ctx, 20*time.Second)
		defer cancel()
		out, err := exec.CommandContext(cctx, "schtasks", a...).CombinedOutput()
		if err != nil {
			return fmt.Errorf("schtasks %s: %v: %s", a[0], err, strings.TrimSpace(string(out)))
		}
		return nil
	}
	if err := run("/Create", "/TN", rdTask, "/TR", inner, "/SC", "ONCE", "/ST", "00:00",
		"/RU", "NT AUTHORITY\\LocalService", "/RL", "LIMITED", "/F"); err != nil {
		return "", err
	}
	defer run("/Delete", "/TN", rdTask, "/F") //nolint:errcheck
	if err := run("/Run", "/TN", rdTask); err != nil {
		return "", err
	}
	// a tarefa roda assíncrona; espera o arquivo de saída aparecer/estabilizar
	deadline := time.Now().Add(15 * time.Second)
	for time.Now().Before(deadline) {
		if b, err := os.ReadFile(outFile); err == nil {
			time.Sleep(400 * time.Millisecond) // deixa terminar de escrever
			b2, _ := os.ReadFile(outFile)
			if len(b2) >= len(b) {
				return strings.TrimSpace(string(b2)), nil
			}
		}
		select {
		case <-ctx.Done():
			return "", ctx.Err()
		case <-time.After(500 * time.Millisecond):
		}
	}
	return "", errors.New("rustdesk (LocalService) não respondeu no tempo limite")
}

func (m *rustdeskMedia) Serve(ctx context.Context, conn net.Conn, mode, secret string) error {
	if secret == "" {
		return errors.New("rustdesk: sessão sem senha de uso único")
	}
	if m.host == "" || m.key == "" {
		return errors.New("rustdesk: bundle sem host/chave do servidor (rustdesk_host/rustdesk_key)")
	}
	if _, err := os.Stat(m.exe); err != nil {
		return fmt.Errorf("rustdesk não instalado (%s): use o instalador do RustDesk", m.exe)
	}

	// 1) pinning: só o nosso servidor, com a nossa chave (config do serviço)
	if out, err := m.rdLocalService(ctx, "--option", "custom-rendezvous-server", m.host); err != nil {
		return fmt.Errorf("rustdesk config servidor: %v: %s", err, out)
	}
	if _, err := m.rdLocalService(ctx, "--option", "key", m.key); err != nil {
		return fmt.Errorf("rustdesk config chave: %w", err)
	}
	// 2) permissões por modo
	enableInput := "N"
	if mode == "control" {
		enableInput = "Y"
	}
	_, _ = m.rdLocalService(ctx, "--option", "enable-keyboard", enableInput)
	_, _ = m.rdLocalService(ctx, "--option", "enable-clipboard", "N")
	_, _ = m.rdLocalService(ctx, "--option", "enable-file-transfer", "N")

	// 3) senha de USO ÚNICO desta sessão; limpa no fim (sem acesso depois)
	if _, err := m.rdLocalService(ctx, "--password", secret); err != nil {
		return fmt.Errorf("rustdesk senha da sessão: %w", err)
	}
	defer func() {
		cctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
		defer cancel()
		_, _ = m.rdLocalService(cctx, "--password", `""`)
	}()

	// 4) ID desta máquina no nosso rendezvous (lido no perfil do LocalService)
	id, err := m.rdLocalService(ctx, "--get-id")
	if err != nil || lastLine(id) == "" {
		return fmt.Errorf("rustdesk get-id: %v (saída: %q)", err, id)
	}
	id = lastLine(id)

	// 5) informa o console pelo canal de controle; pixels vão pelo hbbr
	msg, _ := json.Marshal(map[string]string{"engine": "rustdesk", "id": id, "host": m.host})
	if err := writeFrame(conn, msg); err != nil {
		return err
	}
	m.log.Info("sessão RustDesk armada", "id", id, "modo", mode)

	<-ctx.Done()
	return ctx.Err()
}

func lastLine(s string) string {
	ls := strings.Split(strings.TrimSpace(s), "\n")
	return strings.TrimSpace(ls[len(ls)-1])
}
