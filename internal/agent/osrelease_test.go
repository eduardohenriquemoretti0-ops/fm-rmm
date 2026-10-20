package agent

import (
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

func TestParseOSRelease(t *testing.T) {
	deb := "PRETTY_NAME=\"Debian GNU/Linux 12 (bookworm)\"\nVERSION_ID=\"12\"\nID=debian\nID_LIKE=x\n"
	ubu := "NAME=\"Ubuntu\"\nVERSION_ID='22.04'\nID=ubuntu\n"
	for _, c := range []struct{ in, id, ver string }{
		{deb, "debian", "12"}, {ubu, "ubuntu", "22.04"}, {"", "", ""}, {"ID=arch\n", "arch", ""},
	} {
		if id, v := parseOSRelease(c.in); id != c.id || v != c.ver {
			t.Errorf("%q -> %q %q", c.in, id, v)
		}
	}
	p := filepath.Join(t.TempDir(), "os-release")
	_ = os.WriteFile(p, []byte(deb), 0o600)
	if id, v := lerOSRelease(p); id != "debian" || v != "12" {
		t.Errorf("lerOSRelease: %q %q", id, v)
	}
	if id, v := lerOSRelease(p + "-nao-existe"); id != "" || v != "" {
		t.Errorf("arquivo ausente: %q %q", id, v)
	}
}

// O heartbeat do agente Linux carrega ID/VERSION_ID do os-release real.
func TestHeartbeatReportaOSRelease(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("só Linux")
	}
	id, ver := lerOSRelease("/etc/os-release")
	hb := (&Agent{}).heartbeat()
	if hb.OSID != id || hb.OSVersionID != ver {
		t.Fatalf("heartbeat os_id=%q os_version_id=%q; os-release %q %q", hb.OSID, hb.OSVersionID, id, ver)
	}
	t.Logf("reportado: os_id=%q os_version_id=%q", hb.OSID, hb.OSVersionID)
}
