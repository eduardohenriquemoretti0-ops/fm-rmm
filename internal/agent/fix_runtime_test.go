package agent

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func fakeWinApps(t *testing.T, pastas ...string) string {
	t.Helper()
	root := t.TempDir()
	for _, p := range pastas {
		d := filepath.Join(root, p)
		if err := os.MkdirAll(d, 0o755); err != nil {
			t.Fatal(err)
		}
		if !strings.HasPrefix(p, "SEMEXE") {
			if err := os.WriteFile(filepath.Join(d, "winget.exe"), nil, 0o644); err != nil {
				t.Fatal(err)
			}
		}
	}
	return root
}

func TestResolverWingetMaiorVersao(t *testing.T) {
	root := fakeWinApps(t,
		"Microsoft.DesktopAppInstaller_1.9.25200.0_x64__8wekyb3d8bbwe",
		"Microsoft.DesktopAppInstaller_1.24.25200.0_x64__8wekyb3d8bbwe",
		"Microsoft.DesktopAppInstaller_1.10.0.0_x64__8wekyb3d8bbwe",
		"Microsoft.DesktopAppInstaller_2.0.0.0_x64__8wekyb3d8bbwe_SEMEXE", // sem winget.exe? (nome com sufixo: ignorado abaixo)
		"Outro.App_9.9.9.9_x64__x")
	// remove o exe da 2.0 para provar que pasta sem exe é ignorada
	_ = os.Remove(filepath.Join(root, "Microsoft.DesktopAppInstaller_2.0.0.0_x64__8wekyb3d8bbwe_SEMEXE", "winget.exe"))
	got, err := resolverWingetEm(root, func(string) (string, error) { return "", errors.New("sem PATH") })
	if err != nil {
		t.Fatal(err)
	}
	want := filepath.Join(root, "Microsoft.DesktopAppInstaller_1.24.25200.0_x64__8wekyb3d8bbwe", "winget.exe")
	if got != want {
		t.Fatalf("got %s want %s", got, want)
	}
}

func TestResolverWingetFallbackPathEErro(t *testing.T) {
	vazio := t.TempDir()
	abs := filepath.Join(t.TempDir(), "winget.exe")
	if got, err := resolverWingetEm(vazio, func(string) (string, error) { return abs, nil }); err != nil || got != abs {
		t.Fatalf("fallback PATH: %q %v", got, err)
	}
	// PATH relativo não é aceito (exige absoluto)
	if _, err := resolverWingetEm(vazio, func(string) (string, error) { return "winget", nil }); err == nil {
		t.Fatal("caminho relativo aceito")
	}
	_, err := resolverWingetEm(vazio, func(string) (string, error) { return "", errors.New("x") })
	if err == nil || !strings.Contains(err.Error(), "winget não encontrado") {
		t.Fatalf("erro: %v", err)
	}
}

func TestDicaWinget(t *testing.T) {
	e := errors.New("exit status 0xc0000135")
	if d := dicaWinget(`C:\x\winget.exe`, e, ""); !strings.Contains(d, "SYSTEM") {
		t.Fatalf("sem dica: %q", d)
	}
	if d := dicaWinget("apt-get", e, ""); d != "" {
		t.Fatalf("dica indevida: %q", d)
	}
	if d := dicaWinget("winget", errors.New("exit status 1"), "boom"); d != "" {
		t.Fatalf("dica indevida: %q", d)
	}
}

func TestEstadoBitLocker(t *testing.T) {
	casos := []struct {
		p, c   int
		reboot bool
		want   string
	}{
		{1, 1, false, "protecao=ligada conversao=concluida"},
		{1, 2, false, "protecao=ligada conversao=em_andamento"},
		{0, 0, true, "protecao=pendente_reboot conversao=aguardando_reboot"},
		{1, 0, false, "protecao=pendente_reboot conversao=aguardando_reboot"},
		{0, 0, false, "protecao=desligada conversao=nao_iniciada"},
		{0, 1, false, "protecao=suspensa conversao=concluida"},
		{0, 2, false, "protecao=suspensa conversao=em_andamento"},
		{2, 3, false, "protecao=desligada conversao=decifrando"},
		{2, 0, false, "protecao=desconhecida protection_status=2 conversion_status=0"},
	}
	for _, k := range casos {
		if got := EstadoBitLocker(k.p, k.c, k.reboot); got != k.want {
			t.Errorf("(%d,%d,%v): got %q want %q", k.p, k.c, k.reboot, got, k.want)
		}
	}
	// "ligada" nunca com conversão não iniciada
	if strings.Contains(EstadoBitLocker(0, 0, true), "ligada") || strings.Contains(EstadoBitLocker(1, 0, false), "ligada") {
		t.Fatal("mentiu ligada")
	}
}

func TestParseEstadoBitLockerEReboot(t *testing.T) {
	if p, c, ok := parseEstadoBitLocker(" 0;2\r\n"); !ok || p != 0 || c != 2 {
		t.Fatalf("%d %d %v", p, c, ok)
	}
	for _, ruim := range []string{"", "1", "a;b", "1;2;3"} {
		if _, _, ok := parseEstadoBitLocker(ruim); ok {
			t.Fatalf("aceitou %q", ruim)
		}
	}
	if !pedeReboot("Para continuar, reinicie o computador") || !pedeReboot("You must restart") || pedeReboot("ok") {
		t.Fatal("pedeReboot")
	}
}
