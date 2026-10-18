//go:build darwin

package agent

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"os/exec"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"golang.org/x/sys/unix"
)

const (
	plistLabel = "br.com.fratellimoretti.fmrmm"
	plistPath  = "/Library/LaunchDaemons/" + plistLabel + ".plist"
)

func DataDir() string    { return "/Library/Application Support/FM-RMM" }
func BinaryPath() string { return "/Library/FM-RMM/fmrmm-agent" }

func uptimeSeconds() int64 {
	tv, err := unix.SysctlTimeval("kern.boottime")
	if err != nil {
		return 0
	}
	return int64(time.Since(time.Unix(tv.Sec, int64(tv.Usec)*1000)) / time.Second)
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

const plist = `<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>Label</key><string>%s</string>
  <key>ProgramArguments</key><array><string>%s</string><string>service</string></array>
  <key>RunAtLoad</key><true/>
  <key>KeepAlive</key><true/>
  <key>ThrottleInterval</key><integer>30</integer>
  <key>Umask</key><integer>63</integer>
</dict>
</plist>
`

func launchctl(args ...string) error {
	out, err := exec.Command("/bin/launchctl", args...).CombinedOutput()
	if err != nil {
		return fmt.Errorf("launchctl %s: %v: %s", strings.Join(args, " "), err, strings.TrimSpace(string(out)))
	}
	return nil
}

func installService(bin string) error {
	if err := writeFileAtomic(plistPath, []byte(fmt.Sprintf(plist, plistLabel, bin))); err != nil {
		return err
	}
	if err := os.Chown(plistPath, 0, 0); err != nil {
		return err
	}
	return os.Chmod(plistPath, 0o644)
}

func startService() error {
	_ = launchctl("bootout", "system/"+plistLabel)
	return launchctl("bootstrap", "system", plistPath)
}

func stopService() error { return launchctl("bootout", "system/"+plistLabel) }

func removeService() error {
	if err := os.Remove(plistPath); err != nil && !os.IsNotExist(err) {
		return err
	}
	return nil
}

func removeBinary(bin string) { _ = os.Remove(bin) }

func IsService() bool { return false }

// RunService roda o loop até o systemd/launchd mandar SIGTERM.
func RunService(run func(ctx context.Context), _ *slog.Logger) error {
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGTERM, os.Interrupt)
	defer stop()
	run(ctx)
	return nil
}
