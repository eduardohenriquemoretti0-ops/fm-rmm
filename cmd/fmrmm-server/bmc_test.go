package main

import (
	"bytes"
	"net"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
)

func TestCmdBMCSenhaDeStdinNuncaDeFlag(t *testing.T) {
	var resets []string
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if u, p, ok := r.BasicAuth(); !ok || u != "adm" || p != "segredo-cli" {
			w.WriteHeader(401)
			return
		}
		if r.Method == http.MethodPost {
			resets = append(resets, r.URL.Path)
			w.WriteHeader(204)
			return
		}
		_, _ = w.Write([]byte(`{"PowerState":"On","Status":{"Health":"OK"}}`))
	}))
	defer srv.Close()
	h, p, _ := net.SplitHostPort(srv.Listener.Addr().String())
	porta, _ := strconv.Atoi(p)
	base := []string{"--host", h, "--porta", strconv.Itoa(porta), "--usuario", "adm", "--insecure", "--senha-stdin", "--system-id", "S1"}

	var out bytes.Buffer
	if err := cmdBMCCom(append([]string{"power", "--acao", "GracefulRestart"}, base...), strings.NewReader("segredo-cli\n"), &out); err != nil {
		t.Fatal(err)
	}
	if len(resets) != 1 || resets[0] != "/redfish/v1/Systems/S1/Actions/ComputerSystem.Reset" || strings.Contains(out.String(), "segredo-cli") {
		t.Fatalf("resets=%v out=%q", resets, out.String())
	}
	out.Reset()
	if err := cmdBMCCom(append([]string{"status"}, base...), strings.NewReader("segredo-cli\n"), &out); err != nil || !strings.Contains(out.String(), "power=On") {
		t.Fatalf("status: %v %q", err, out.String())
	}
	t.Logf("CLI: %s", strings.TrimSpace(out.String()))

	// senha errada: erro sem a senha
	err := cmdBMCCom(append([]string{"status"}, base...), strings.NewReader("errada-123\n"), &out)
	if err == nil || strings.Contains(err.Error(), "errada-123") {
		t.Fatalf("erro inadequado: %v", err)
	}
	// ação inválida e sem senha
	if err := cmdBMCCom(append([]string{"power", "--acao", "X"}, base...), strings.NewReader("a\n"), &out); err == nil {
		t.Fatal("ação inválida aceita")
	}
	t.Setenv(envBMCPass, "")
	if err := cmdBMCCom([]string{"status", "--host", h, "--usuario", "adm"}, strings.NewReader(""), &out); err == nil {
		t.Fatal("sem senha deveria falhar")
	}
	// a flag --senha NÃO existe
	if err := cmdBMCCom([]string{"status", "--host", h, "--usuario", "adm", "--senha", "x"}, strings.NewReader(""), &out); err == nil {
		t.Fatal("--senha por flag não deveria existir")
	}
}

func TestCmdBMCHostsAddListRm(t *testing.T) {
	dir := t.TempDir()
	if err := cmdInit([]string{"--dir", dir, "--hosts", "localhost"}); err != nil {
		t.Fatal(err)
	}
	var out bytes.Buffer
	run := func(a ...string) error {
		out.Reset()
		return cmdBMCHostsCom(append([]string{"--dir", dir}, a...), &out)
	}
	if err := run("add", "--host", "10.1.1.10", "--grupo", "filialA", "--nome", "srv-a"); err != nil {
		t.Fatal(err)
	}
	if err := run("add", "--host", "BMC-B.local", "--porta", "8443", "--grupo", "filialB", "--nome", "srv-b"); err != nil {
		t.Fatal(err)
	}
	if err := run("add", "--host", "x"); err == nil {
		t.Fatal("add sem grupo/nome deveria falhar")
	}
	if err := run("list"); err != nil {
		t.Fatal(err)
	}
	t.Logf("list:\n%s", out.String())
	for _, w := range []string{"10.1.1.10", "443", "filialA", "bmc-b.local", "8443", "srv-b"} {
		if !strings.Contains(out.String(), w) {
			t.Fatalf("list sem %q: %s", w, out.String())
		}
	}
	if err := run("rm", "--host", "10.1.1.10"); err != nil {
		t.Fatal(err)
	}
	if err := run("rm", "--host", "10.1.1.10"); err == nil {
		t.Fatal("rm repetido deveria falhar")
	}
	_ = run("list")
	t.Logf("list após rm:\n%s", out.String())
	if strings.Contains(out.String(), "10.1.1.10") || !strings.Contains(out.String(), "bmc-b.local") {
		t.Fatalf("list após rm: %s", out.String())
	}
}
