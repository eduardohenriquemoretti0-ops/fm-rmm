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
	// limpa a senha no fim: sem acesso desatendido depois da sessão
	defer func() {
		cctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		_ = editTOML(cfg1, map[string]string{"password": ""}, nil)
		_ = m.restartService(cctx)
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

// editTOML regrava chaves de topo (key = 'valor') e remove as de `drop`.
func editTOML(path string, set map[string]string, drop []string) error {
	b, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	lines := strings.Split(string(b), "\n")
	var out []string
	seen := map[string]bool{}
	skip := func(k string) bool {
		for _, d := range drop {
			if k == d {
				return true
			}
		}
		return false
	}
	for _, ln := range lines {
		t := strings.TrimSpace(ln)
		if i := strings.Index(t, "="); i > 0 && !strings.HasPrefix(t, "[") {
			k := strings.TrimSpace(t[:i])
			if skip(k) {
				continue
			}
			if v, ok := set[k]; ok {
				out = append(out, fmt.Sprintf("%s = '%s'", k, tomlEsc(v)))
				seen[k] = true
				continue
			}
		}
		out = append(out, ln)
	}
	// chaves novas vão no topo (antes de qualquer [secao])
	var head []string
	for k, v := range set {
		if !seen[k] {
			head = append(head, fmt.Sprintf("%s = '%s'", k, tomlEsc(v)))
		}
	}
	final := append(head, out...)
	return os.WriteFile(path, []byte(strings.Join(final, "\n")), 0o644)
}

// editTOMLOptions grava chaves sob a seção [options].
func editTOMLOptions(path string, set map[string]string) error {
	b, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	lines := strings.Split(string(b), "\n")
	var out []string
	inOpts := false
	seen := map[string]bool{}
	flush := func() {
		for k, v := range set {
			if !seen[k] {
				out = append(out, fmt.Sprintf("%s = '%s'", k, tomlEsc(v)))
				seen[k] = true
			}
		}
	}
	for _, ln := range lines {
		t := strings.TrimSpace(ln)
		if strings.HasPrefix(t, "[") {
			if inOpts {
				flush() // fim da [options]: grava as que faltaram
			}
			inOpts = t == "[options]"
			out = append(out, ln)
			continue
		}
		if inOpts {
			if i := strings.Index(t, "="); i > 0 {
				k := strings.TrimSpace(t[:i])
				if v, ok := set[k]; ok {
					out = append(out, fmt.Sprintf("%s = '%s'", k, tomlEsc(v)))
					seen[k] = true
					continue
				}
			}
		}
		out = append(out, ln)
	}
	if inOpts {
		flush()
	}
	if !hasSection(lines, "[options]") {
		out = append(out, "[options]")
		for k, v := range set {
			if !seen[k] {
				out = append(out, fmt.Sprintf("%s = '%s'", k, tomlEsc(v)))
			}
		}
	}
	return os.WriteFile(path, []byte(strings.Join(out, "\n")), 0o644)
}

func hasSection(lines []string, sec string) bool {
	for _, l := range lines {
		if strings.TrimSpace(l) == sec {
			return true
		}
	}
	return false
}

func tomlEsc(s string) string { return strings.ReplaceAll(s, "'", "") }
