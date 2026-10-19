//go:build linux

package agent

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"os/exec"
	"os/signal"
	"strconv"
	"strings"
	"syscall"
)

const unitPath = "/etc/systemd/system/fmrmm-agent.service"

func DataDir() string    { return "/var/lib/fm-rmm" }
func BinaryPath() string { return "/usr/local/sbin/fmrmm-agent" }

func uptimeSeconds() int64 {
	b, err := os.ReadFile("/proc/uptime")
	if err != nil {
		return 0
	}
	f, _ := strconv.ParseFloat(strings.Fields(string(b))[0], 64)
	return int64(f)
}

func isAdmin() bool { return os.Geteuid() == 0 }

func secureDir(dir string) error {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	if err := os.Chown(dir, 0, 0); err != nil {
		return err
	}
	return os.Chmod(dir, 0o700)
}

// O agente roda como root (decisão: mesmo modelo do Windows/SYSTEM); o
// systemd ainda tranca o que dá sem quebrar as ações do catálogo.
const unit = `[Unit]
Description=FM-RMM Agente (gestão, conexão só de saída)
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
ExecStart=%s service
Restart=always
RestartSec=30
NoNewPrivileges=yes
PrivateTmp=yes
ProtectHome=read-only
ProtectKernelTunables=yes
ProtectKernelModules=yes
ProtectControlGroups=yes
RestrictSUIDSGID=yes
LockPersonality=yes
UMask=0077

[Install]
WantedBy=multi-user.target
`

func systemctl(args ...string) error {
	out, err := exec.Command("systemctl", args...).CombinedOutput()
	if err != nil {
		return fmt.Errorf("systemctl %s: %v: %s", strings.Join(args, " "), err, strings.TrimSpace(string(out)))
	}
	return nil
}

func installService(bin string) error {
	if err := writeFileAtomic(unitPath, []byte(fmt.Sprintf(unit, bin))); err != nil {
		return err
	}
	if err := os.Chmod(unitPath, 0o644); err != nil {
		return err
	}
	if err := systemctl("daemon-reload"); err != nil {
		return err
	}
	return systemctl("enable", "fmrmm-agent.service")
}

func startService() error { return systemctl("restart", "fmrmm-agent.service") }
func stopService() error  { return systemctl("stop", "fmrmm-agent.service") }

func removeService() error {
	_ = systemctl("disable", "fmrmm-agent.service")
	if err := os.Remove(unitPath); err != nil && !os.IsNotExist(err) {
		return err
	}
	return systemctl("daemon-reload")
}

func removeBinary(bin string) { _ = os.Remove(bin) }

// No Linux o systemd chama `service`; o loop roda direto.
func IsService() bool { return false }

// RunService roda o loop até o systemd/launchd mandar SIGTERM.
func RunService(run func(ctx context.Context), _ *slog.Logger) error {
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGTERM, os.Interrupt)
	defer stop()
	run(ctx)
	return nil
}

// No Linux/macOS o indicador é um toast do próprio SO, sem helper separado.
func installHelper(string) error { return nil }
func removeHelper()              {}
