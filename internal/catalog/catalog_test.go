package catalog

import "testing"

func TestValidate(t *testing.T) {
	ok := []struct {
		action, goos string
		params       map[string]string
	}{
		{"info", "windows", nil},
		{"inventario", "linux", nil},
		{"seguranca", "darwin", nil},
		{"reiniciar_servico", "windows", map[string]string{"nome": "Spooler"}},
		{"reiniciar_servico", "linux", map[string]string{"nome": "cups"}},
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
		{"comando livre", "shell", "linux", map[string]string{"cmd": "id"}},
		{"parâmetro desconhecido", "info", "windows", map[string]string{"x": "1"}},
		{"parâmetro ausente", "reiniciar_servico", "windows", nil},
		{"serviço fora da lista", "reiniciar_servico", "windows", map[string]string{"nome": "WinDefend"}},
		{"injeção", "reiniciar_servico", "windows", map[string]string{"nome": "Spooler'; Remove-Item C:\\ -Recurse #"}},
		{"injeção sh", "reiniciar_servico", "linux", map[string]string{"nome": "cups;id"}},
		{"valor de outro SO", "reiniciar_servico", "linux", map[string]string{"nome": "Spooler"}},
		{"SO desconhecido", "info", "plan9", nil},
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
			if a.Scripts[o] == "" {
				t.Errorf("%s sem script para %s", n, o)
			}
		}
		if a.Timeout <= 0 {
			t.Errorf("%s sem timeout", n)
		}
	}
}
