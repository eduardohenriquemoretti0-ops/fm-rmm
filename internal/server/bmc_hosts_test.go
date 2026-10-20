package server

import (
	"errors"
	"path/filepath"
	"testing"
)

func TestBMCHostsInventarioEPermissao(t *testing.T) {
	st, err := OpenStore(filepath.Join(t.TempDir(), "s.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	if err := st.AdicionarBMCHost("10.1.1.10", 0, "filialA", "srv-a"); err != nil {
		t.Fatal(err)
	}
	if err := st.AdicionarBMCHost("BMC-B.Local", 8443, "filialB", "srv-b"); err != nil {
		t.Fatal(err)
	}
	_ = st.GrantGroup("tA", "filialA")
	_ = st.GrantGroup("tB", "filialB")
	_ = st.GrantGroup("adm", "*")

	casos := []struct {
		host  string
		porta int
		tech  string
		want  error
	}{
		{"10.1.1.10", 0, "tA", nil},
		{"10.1.1.10", 443, "tA", nil},
		{"10.1.1.10", 0, "tB", ErrBMCHostNegado},
		{"10.1.1.10", 8443, "tA", ErrBMCHostDesconhecido}, // porta diferente
		{"bmc-b.local", 8443, "tB", nil},                  // normalização de caixa
		{"bmc-b.local", 8443, "tA", ErrBMCHostNegado},
		{"10.9.9.9", 0, "tA", ErrBMCHostDesconhecido},
		{"10.1.1.10", 0, "adm", nil}, // curinga
		{"10.1.1.10", 0, "ninguem", ErrBMCHostNegado},
	}
	for _, c := range casos {
		if got := st.BMCHostPermitido(c.host, c.porta, c.tech); !errors.Is(got, c.want) {
			t.Errorf("%s:%d %s => %v, esperado %v", c.host, c.porta, c.tech, got, c.want)
		}
	}
	_ = st.DisableTech("tA", true)
	if !errors.Is(st.BMCHostPermitido("10.1.1.10", 0, "tA"), ErrBMCHostNegado) {
		t.Error("técnico desabilitado deveria ser negado")
	}
	hs, _ := st.ListarBMCHosts()
	if len(hs) != 2 {
		t.Fatalf("lista: %v", hs)
	}
	if err := st.RemoverBMCHost("10.1.1.10", 0); err != nil {
		t.Fatal(err)
	}
	if !errors.Is(st.BMCHostPermitido("10.1.1.10", 0, "adm"), ErrBMCHostDesconhecido) {
		t.Error("removido deveria sumir")
	}
	if !errors.Is(st.RemoverBMCHost("10.1.1.10", 0), ErrNotFound) {
		t.Error("remover inexistente deveria dar ErrNotFound")
	}
	if st.AdicionarBMCHost("x", 0, "*", "n") == nil || st.AdicionarBMCHost("a/b", 0, "g", "n") == nil {
		t.Error("grupo '*' e host inválido deveriam ser recusados")
	}
}
