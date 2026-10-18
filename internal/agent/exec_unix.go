//go:build !windows

package agent

import (
	"context"
	"os/exec"
	"runtime"
	"strings"

	"github.com/eduardohenriquemoretti0-ops/fm-rmm/internal/catalog"
)

// scriptCommand: /bin/sh -c com ambiente mínimo. Parâmetros entram como
// variáveis P_<NOME> (nunca concatenados no texto do script).
func scriptCommand(ctx context.Context, a catalog.Action, keys []string, params map[string]string) *exec.Cmd {
	cmd := exec.CommandContext(ctx, "/bin/sh", "-c", a.Scripts[runtime.GOOS])
	env := []string{"PATH=/usr/sbin:/usr/bin:/sbin:/bin", "LC_ALL=C", "HOME=/root"}
	for _, k := range keys {
		env = append(env, "P_"+strings.ToUpper(k)+"="+params[k])
	}
	cmd.Env = env
	cmd.Dir = "/"
	return cmd
}
