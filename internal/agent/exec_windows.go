//go:build windows

package agent

import (
	"context"
	"encoding/base64"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"unicode/utf16"

	"github.com/eduardohenriquemoretti0-ops/fm-rmm/internal/catalog"
)

// powershellPath usa o caminho absoluto: nada de procurar no PATH.
func powershellPath() string {
	root := os.Getenv("SystemRoot")
	if root == "" {
		root = `C:\Windows`
	}
	return filepath.Join(root, "System32", "WindowsPowerShell", "v1.0", "powershell.exe")
}

// encodeCommand gera o -EncodedCommand (UTF-16LE em base64): sem problema de
// aspas nem de escape na linha de comando.
func encodeCommand(script string) string {
	u := utf16.Encode([]rune(script))
	b := make([]byte, 2*len(u))
	for i, c := range u {
		b[2*i], b[2*i+1] = byte(c), byte(c>>8)
	}
	return base64.StdEncoding.EncodeToString(b)
}

// scriptCommand: parâmetros viram $P_<nome> = '<valor>' no topo do script.
// O valor já foi validado contra lista fechada e regex [A-Za-z0-9._-]; mesmo
// assim aspas simples são duplicadas (escape do PowerShell).
func scriptCommand(ctx context.Context, a catalog.Action, keys []string, params map[string]string) *exec.Cmd {
	var head strings.Builder
	for _, k := range keys {
		head.WriteString("$P_" + k + " = '" + strings.ReplaceAll(params[k], "'", "''") + "'\n")
	}
	script := head.String() + a.Scripts["windows"]
	cmd := exec.CommandContext(ctx, powershellPath(),
		"-NoLogo", "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass",
		"-EncodedCommand", encodeCommand(script))
	cmd.Dir = os.Getenv("SystemRoot")
	return cmd
}
