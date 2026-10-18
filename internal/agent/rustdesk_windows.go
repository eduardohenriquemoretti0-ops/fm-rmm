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
// Endurecimento aplicado a cada sessão:
//   - aponta o RustDesk só para o NOSSO hbbs/hbbr, com a NOSSA chave (pinning);
//   - senha de USO ÚNICO por sessão (vem na concessão assinada), limpa no fim;
//   - sem senha permanente de acesso desatendido fora da sessão autorizada;
//   - o indicador do RustDesk (e o nosso) fica visível; nada é ocultado.
//
// Os pixels passam pelo hbbr do RustDesk, não pelo nosso relay. O nosso canal
// (conn) leva só o controle: informa ao console o ID do RustDesk desta máquina.
type rustdeskMedia struct {
	log  *slog.Logger
	exe  string // caminho do rustdesk.exe
	host string // hbbs (ex.: 10.0.2.2)
	key  string // chave pública do hbbs (base64)
}

// NewRustDeskMedia cria o motor. host/key vêm do bundle (pinning do servidor).
func NewRustDeskMedia(log *slog.Logger, host, key string) SessionMedia {
	return &rustdeskMedia{log: log, exe: rustdeskExe(), host: host, key: key}
}

func rustdeskExe() string {
	// instalação padrão do RustDesk no Windows
	for _, p := range []string{
		filepath.Join(os.Getenv("ProgramFiles"), "RustDesk", "rustdesk.exe"),
		filepath.Join(os.Getenv("ProgramW6432"), "RustDesk", "rustdesk.exe"),
	} {
		if p != "" {
			if _, err := os.Stat(p); err == nil {
				return p
			}
		}
	}
	return "rustdesk.exe" // tenta no PATH
}

func (m *rustdeskMedia) rd(ctx context.Context, args ...string) (string, error) {
	cctx, cancel := context.WithTimeout(ctx, 20*time.Second)
	defer cancel()
	out, err := exec.CommandContext(cctx, m.exe, args...).CombinedOutput()
	return strings.TrimSpace(string(out)), err
}

func (m *rustdeskMedia) Serve(ctx context.Context, conn net.Conn, mode, secret string) error {
	if secret == "" {
		return errors.New("rustdesk: sessão sem senha de uso único")
	}
	if m.host == "" || m.key == "" {
		return errors.New("rustdesk: bundle sem host/chave do servidor (rustdesk_host/rustdesk_key)")
	}
	if _, err := os.Stat(m.exe); err != nil && !filepath.IsAbs(m.exe) {
		// deixa seguir se for nome no PATH; só avisa quando é caminho absoluto ausente
	} else if err != nil {
		return fmt.Errorf("rustdesk não instalado (%s): integrar via instalador", m.exe)
	}

	// 1) pinning: aponta SÓ para o nosso servidor, com a nossa chave
	if out, err := m.rd(ctx, "--option", "custom-rendezvous-server", m.host); err != nil {
		return fmt.Errorf("rustdesk config servidor: %v: %s", err, out)
	}
	if out, err := m.rd(ctx, "--option", "key", m.key); err != nil {
		return fmt.Errorf("rustdesk config chave: %v: %s", err, out)
	}
	// 2) permissões por modo: view = só ver; control = teclado/mouse
	enableInput := "N"
	if mode == "control" {
		enableInput = "Y"
	}
	_, _ = m.rd(ctx, "--option", "enable-keyboard", enableInput)
	_, _ = m.rd(ctx, "--option", "enable-clipboard", "N")   // sem área de transferência
	_, _ = m.rd(ctx, "--option", "enable-file-transfer", "N") // sem transferência de arquivo neste PoC

	// 3) senha de USO ÚNICO desta sessão
	if out, err := m.rd(ctx, "--password", secret); err != nil {
		return fmt.Errorf("rustdesk senha da sessão: %v: %s", err, out)
	}
	// limpa a senha no fim, aconteça o que acontecer (sem acesso desatendido depois)
	defer func() {
		cctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		_ = exec.CommandContext(cctx, m.exe, "--password", "").Run()
	}()

	// 4) ID desta máquina no nosso rendezvous
	id, err := m.rd(ctx, "--get-id")
	if err != nil || id == "" {
		return fmt.Errorf("rustdesk get-id: %v", err)
	}
	id = lastLine(id)

	// 5) informa o console pelo canal de controle (ID; a senha o console já tem
	//    da concessão). Os pixels vão pelo hbbr do RustDesk.
	msg, _ := json.Marshal(map[string]string{"engine": "rustdesk", "id": id, "host": m.host})
	if err := writeFrame(conn, msg); err != nil {
		return err
	}
	m.log.Info("sessão RustDesk armada", "id", id, "modo", mode)

	// mantém a sessão até expirar/cancelar; a senha é limpa no defer
	<-ctx.Done()
	return ctx.Err()
}

func lastLine(s string) string {
	ls := strings.Split(strings.TrimSpace(s), "\n")
	return strings.TrimSpace(ls[len(ls)-1])
}
