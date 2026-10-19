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
	"regexp"
	"strings"
	"time"
)

// rustdeskMedia integra o RustDesk self-hosted ENDURECIDO como plano de mídia
// no Windows. Resolve o Session 0: o serviço do RustDesk (conta LocalService)
// captura a área de trabalho do usuário — o nosso agente em SYSTEM não consegue.
//
// No RustDesk 1.5.0 OSS as flags de CLI (--get-id/--password/--option) NÃO
// funcionam headless (app Flutter sem console). O que funciona, e é
// determinístico, é escrever a CONFIG do perfil do LocalService e reiniciar o
// serviço. Comprovado na VM fm-lab-win10: o serviço passa a registrar só no
// nosso hbbs, com o ID e a senha que definimos.
//
// Endurecimento por sessão:
//   - pinning: custom-rendezvous-server = nosso hbbs; key = nossa chave;
//   - ID determinístico por máquina (sabemos sem depender de --get-id);
//   - senha = senha de USO ÚNICO da concessão assinada; LIMPA no fim da sessão
//     (sem acesso desatendido depois);
//   - permissões por modo (view desliga teclado/clipboard/arquivo);
//   - indicador do RustDesk e o nosso ficam visíveis; nada é ocultado.
//
// Os pixels passam pelo hbbr do RustDesk; o nosso canal (conn) leva só o ID.
type rustdeskMedia struct {
	log     *slog.Logger
	host    string
	key     string
	cfgDir  string // config do perfil do LocalService (serviço)
	service string
}

func NewRustDeskMedia(log *slog.Logger, host, key string) SessionMedia {
	root := os.Getenv("SystemRoot")
	if root == "" {
		root = `C:\Windows`
	}
	cfg := filepath.Join(root, "ServiceProfiles", "LocalService", "AppData", "Roaming", "RustDesk", "config")
	return &rustdeskMedia{log: log, host: host, key: key, cfgDir: cfg, service: "RustDesk"}
}

var rdIDClean = regexp.MustCompile(`[^a-z0-9]+`)

// rdSecretOK aceita só o alfabeto hex/base64url da senha de uso único.
var rdSecretOK = regexp.MustCompile(`^[A-Za-z0-9_-]+$`)

// deterministicID deriva um ID estável por máquina (sabemos sem --get-id).
func deterministicID() string {
	h, _ := os.Hostname()
	id := "fm" + rdIDClean.ReplaceAllString(strings.ToLower(h), "")
	if len(id) > 16 {
		id = id[:16]
	}
	return id
}

func (m *rustdeskMedia) sc(ctx context.Context, args ...string) error {
	cctx, cancel := context.WithTimeout(ctx, 25*time.Second)
	defer cancel()
	out, err := exec.CommandContext(cctx, "sc", args...).CombinedOutput()
	if err != nil {
		return fmt.Errorf("sc %s: %v: %s", args[0], err, strings.TrimSpace(string(out)))
	}
	return nil
}

func (m *rustdeskMedia) restartService(ctx context.Context) error {
	_ = m.sc(ctx, "stop", m.service)
	time.Sleep(2 * time.Second)
	if err := m.sc(ctx, "start", m.service); err != nil {
		return err
	}
	time.Sleep(4 * time.Second)
	return nil
}

func (m *rustdeskMedia) Serve(ctx context.Context, conn net.Conn, mode, secret string) error {
	if secret == "" {
		return errors.New("rustdesk: sessão sem senha de uso único")
	}
	// A senha vai para uma string literal de TOML (sem escape). Exigimos alfabeto
	// hex/base64url — é o que randHex/randSecret produzem — para que nenhum
	// caractere problemático chegue ao arquivo de config.
	if !rdSecretOK.MatchString(secret) {
		return errors.New("rustdesk: senha de sessão com caractere inválido (esperado hex/base64url)")
	}
	if m.host == "" || m.key == "" {
		return errors.New("rustdesk: bundle sem host/chave do servidor (rustdesk_host/rustdesk_key)")
	}
	cfg1 := filepath.Join(m.cfgDir, "RustDesk.toml")  // id, senha
	cfg2 := filepath.Join(m.cfgDir, "RustDesk2.toml") // servidor, chave, permissões
	if _, err := os.Stat(cfg2); err != nil {
		return fmt.Errorf("rustdesk não instalado ou sem config do serviço (%s)", m.cfgDir)
	}

	id := deterministicID()
	// 1) config principal: nosso ID + senha de uso único (remove enc_id p/ o ID valer)
	if err := editTOML(cfg1, map[string]string{"id": id, "password": secret}, []string{"enc_id"}); err != nil {
		return fmt.Errorf("rustdesk config id/senha: %w", err)
	}
	// senha de uso único em TEXTO no arquivo: tranca já, antes do restart, para
	// proteger essa janela (o restart do RustDesk depois cifra a senha).
	if err := m.lockConfigs(ctx, cfg1, cfg2); err != nil {
		return fmt.Errorf("rustdesk tranca config (pré-restart): %w", err)
	}
	// 2) config de opções: pinning do nosso servidor + chave + permissões por modo
	enableKbd := "N"
	if mode == "control" {
		enableKbd = "Y"
	}
	if err := editTOMLOptions(cfg2, map[string]string{
		"custom-rendezvous-server": m.host,
		"key":                      m.key,
		"enable-keyboard":          enableKbd,
		"enable-clipboard":         "N",
		"enable-file-transfer":     "N",
	}); err != nil {
		return fmt.Errorf("rustdesk config servidor: %w", err)
	}
	if err := m.restartService(ctx); err != nil {
		return fmt.Errorf("rustdesk restart: %w", err)
	}
	// o restart REESCREVE os .toml e recria a ACL herdada: reaplica a restrição.
	if err := m.lockConfigs(ctx, cfg1, cfg2); err != nil {
		return fmt.Errorf("rustdesk tranca config (pós-restart): %w", err)
	}
	// limpa a senha no fim: sem acesso desatendido depois da sessão
	defer func() {
		cctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		_ = editTOML(cfg1, map[string]string{"password": ""}, nil)
		_ = m.restartService(cctx)
		_ = m.lockConfigs(cctx, cfg1, cfg2) // o restart final também reescreve: trava de novo
	}()

	// 3) informa o console o ID; os pixels vão pelo hbbr do RustDesk
	msg, _ := json.Marshal(map[string]string{"engine": "rustdesk", "id": id, "host": m.host})
	if err := writeFrame(conn, msg); err != nil {
		return err
	}
	m.log.Info("sessão RustDesk armada", "id", id, "modo", mode)

	<-ctx.Done()
	return ctx.Err()
}

// restrictACL tira a herança e deixa só SYSTEM, Administradores e LOCAL SERVICE
// com o arquivo. LOCAL SERVICE é obrigatório: o RustDesk roda nessa conta e
// precisa ler a própria config — tirá-la quebraria a sessão. A ACL default já
// nega usuário comum; o ganho aqui é remover herança (sem ACE amplo herdado) e
// travar a janela em que a senha de uso único está em texto. O modo 0o600 do Go
// não vira ACL no Windows, por isso o icacls.
func (m *rustdeskMedia) restrictACL(ctx context.Context, path string) error {
	cctx, cancel := context.WithTimeout(ctx, 20*time.Second)
	defer cancel()
	out, err := exec.CommandContext(cctx, "icacls", path,
		"/inheritance:r",
		"/grant:r", "*S-1-5-18:F", // SYSTEM
		"/grant:r", "*S-1-5-32-544:F", // Administradores (BUILTIN\Administrators)
		"/grant:r", "*S-1-5-19:F", // LOCAL SERVICE (conta do serviço RustDesk)
	).CombinedOutput()
	if err != nil {
		return fmt.Errorf("icacls %s: %v: %s", path, err, strings.TrimSpace(string(out)))
	}
	return nil
}

// lockConfigs reaplica a ACL restrita nos dois .toml. Tem de rodar DEPOIS de cada
// restart do RustDesk: o restart reescreve os arquivos e recria a ACL herdada.
func (m *rustdeskMedia) lockConfigs(ctx context.Context, cfg1, cfg2 string) error {
	if err := m.restrictACL(ctx, cfg1); err != nil {
		return err
	}
	return m.restrictACL(ctx, cfg2)
}
