package catalog

import "testing"

func TestValidate(t *testing.T) {
	ok := []struct {
		action, goos string
		params       map[string]string
	}{
		{"info", "windows", nil},
		{"inventario", "linux", nil},
		{"hardware", "windows", nil},
		{"hardware", "linux", nil},
		{"seguranca", "darwin", nil},
		{"reiniciar_servico", "windows", map[string]string{"nome": "Spooler"}},
		{"reiniciar_servico", "linux", map[string]string{"nome": "cups"}},
		{"forcar_criptografia", "windows", nil},
		{"forcar_criptografia", "windows", map[string]string{"volume": "C"}},
		{"forcar_criptografia", "linux", nil},
		{"cripto_status", "windows", nil},
		{"cripto_status", "linux", nil},
		{"cripto_status", "darwin", nil},
		{"wake_on_lan", "windows", map[string]string{"mac": "AA:BB:CC:DD:EE:FF"}},
		{"wake_on_lan", "linux", map[string]string{"mac": "aa-bb-cc-dd-ee-ff"}},
		{"wake_on_lan", "darwin", map[string]string{"mac": "00:1a:2B:3c:4D:5e", "broadcast": "192.168.1.255"}},
	}
	for _, c := range ok {
		if _, err := Validate(c.action, c.goos, c.params); err != nil {
			t.Errorf("%s/%s deveria passar: %v", c.action, c.goos, err)
		}
	}
	bad := []struct {
		name, action, goos string
		params             map[string]string
	}{
		{"fora do catálogo", "powershell", "windows", nil},
		{"escrow volume fora da lista", "forcar_criptografia", "windows", map[string]string{"volume": "Z"}},
		{"escrow injeção", "forcar_criptografia", "windows", map[string]string{"volume": "C;calc"}},
		{"comando livre", "shell", "linux", map[string]string{"cmd": "id"}},
		{"parâmetro desconhecido", "info", "windows", map[string]string{"x": "1"}},
		{"parâmetro ausente", "reiniciar_servico", "windows", nil},
		{"serviço fora da lista", "reiniciar_servico", "windows", map[string]string{"nome": "WinDefend"}},
		{"injeção", "reiniciar_servico", "windows", map[string]string{"nome": "Spooler'; Remove-Item C:\\ -Recurse #"}},
		{"injeção sh", "reiniciar_servico", "linux", map[string]string{"nome": "cups;id"}},
		{"valor de outro SO", "reiniciar_servico", "linux", map[string]string{"nome": "Spooler"}},
		{"SO desconhecido", "info", "plan9", nil},
		{"wol sem mac", "wake_on_lan", "linux", nil},
		{"wol param desconhecido", "wake_on_lan", "linux", map[string]string{"mac": "AA:BB:CC:DD:EE:FF", "x": "1"}},
	}
	for _, c := range bad {
		if _, err := Validate(c.action, c.goos, c.params); err == nil {
			t.Errorf("%s: deveria ser recusado", c.name)
		}
	}
}

// Toda ação precisa existir nos três sistemas e ter timeout.
func TestCatalogCompleto(t *testing.T) {
	for _, n := range Names() {
		a, _ := Get(n)
		for _, o := range []string{"windows", "linux", "darwin"} {
			sc, existe := a.Scripts[o]
			if !existe || (sc == "" && !a.Native) { // nativa: só lista o SO, sem script
				t.Errorf("%s sem script para %s", n, o)
			}
		}
		if a.Timeout <= 0 {
			t.Errorf("%s sem timeout", n)
		}
	}
}

func TestWakeOnLAN(t *testing.T) {
	a, ok := Get("wake_on_lan")
	if !ok || !a.Changes {
		t.Fatal("wake_on_lan deve existir e ter Changes=true (concessão assinada)")
	}
	mac := "AA:BB:CC:DD:EE:FF"
	bons := []map[string]string{
		{"mac": mac},
		{"mac": "AA-BB-CC-DD-EE-FF"},
		{"mac": "aa:bb:cc:dd:ee:ff", "broadcast": "255.255.255.255"},
		{"mac": mac, "broadcast": "10.0.0.255"},
	}
	for _, os := range []string{"windows", "linux", "darwin"} {
		for _, p := range bons {
			if _, err := Validate("wake_on_lan", os, p); err != nil {
				t.Errorf("%s %v deveria passar: %v", os, p, err)
			}
		}
	}
	ruins := map[string]map[string]string{
		"curto":              {"mac": "AA:BB:CC:DD:EE"},
		"longo":              {"mac": "AA:BB:CC:DD:EE:FF:00"},
		"não hex":            {"mac": "GG:BB:CC:DD:EE:FF"},
		"separador misto":    {"mac": "AA:BB-CC:DD:EE:FF"},
		"sem separador":      {"mac": "AABBCCDDEEFF"},
		"vazio":              {"mac": ""},
		"ponto e vírgula":    {"mac": "AA:BB:CC:DD:EE:FF;id"},
		"espaço":             {"mac": "AA:BB:CC:DD:EE:FF id"},
		"aspas simples":      {"mac": "AA:BB:CC:DD:EE:FF'"},
		"aspas duplas":       {"mac": `"AA:BB:CC:DD:EE:FF"`},
		"subshell":           {"mac": "$(id)"},
		"crase":              {"mac": "`id`"},
		"quebra de linha":    {"mac": "AA:BB:CC:DD:EE:FF\nid"},
		"broadcast inválido": {"mac": mac, "broadcast": "256.1.1.1"},
		"broadcast host":     {"mac": mac, "broadcast": "example.com"},
		"broadcast injeção":  {"mac": mac, "broadcast": "10.0.0.255;id"},
		"broadcast curto":    {"mac": mac, "broadcast": "10.0.0"},
	}
	for nome, p := range ruins {
		for _, os := range []string{"windows", "linux", "darwin"} {
			if _, err := Validate("wake_on_lan", os, p); err == nil {
				t.Errorf("%s (%s): %v deveria ser recusado", nome, os, p)
			}
		}
	}
}

// Param com Pattern não pode afrouxar a trava anti-injeção, mesmo com um
// Pattern permissivo (.*): o alfabeto máximo vale antes.
func TestPatternNaoAbreInjecao(t *testing.T) {
	register(Action{
		Name:    "_teste_pattern",
		Params:  map[string]Param{"v": {Pattern: `.*`}},
		Scripts: map[string]string{"linux": "true"},
	})
	defer delete(actions, "_teste_pattern")
	if _, err := Validate("_teste_pattern", "linux", map[string]string{"v": "a;b"}); err == nil {
		t.Error("';' deveria ser recusado mesmo com Pattern .*")
	}
	if _, err := Validate("_teste_pattern", "linux", map[string]string{"v": "a:b-c.1"}); err != nil {
		t.Errorf("valor limpo deveria passar: %v", err)
	}
}

func TestForcarCriptografiaEhNativaEMudaEstado(t *testing.T) {
	a, ok := Get("forcar_criptografia")
	if !ok || !a.Native || !a.Changes {
		t.Fatalf("forcar_criptografia deve ser nativa e Changes: %+v", a)
	}
	for goos, sc := range a.Scripts {
		if sc != "" {
			t.Errorf("%s: ação nativa não pode ter script", goos)
		}
	}
	if c, _ := Get("cripto_status"); c.Changes || c.Native {
		t.Error("cripto_status deve ser só leitura (script)")
	}
}
