package escrow

import (
	"path/filepath"
	"strings"
	"testing"
)

const chaveTeste = "123456-234567-345678-456789-567890-678901-789012-890123"

func novoPar(t *testing.T) (string, string) {
	t.Helper()
	p := filepath.Join(t.TempDir(), "escrow.key")
	pub, err := GenerateKey(p)
	if err != nil {
		t.Fatal(err)
	}
	return p, pub
}

func TestRoundtrip(t *testing.T) {
	priv, pub := novoPar(t)
	blob, err := Seal(pub, Segredo{AgentID: "ag-1", Volume: "C:", Metodo: "bitlocker", Chave: chaveTeste})
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(blob, chaveTeste) {
		t.Fatal("blob contém a chave em claro")
	}
	s, err := Open(priv, blob)
	if err != nil {
		t.Fatal(err)
	}
	if s.Chave != chaveTeste || s.AgentID != "ag-1" || s.Volume != "C:" {
		t.Fatalf("roundtrip divergente: %+v", s)
	}
	if p2, err := PublicFromPrivate(priv); err != nil || p2 != pub {
		t.Fatalf("pública derivada difere: %v", err)
	}
}

func TestFalhasLimpas(t *testing.T) {
	priv, pub := novoPar(t)
	outra, _ := novoPar(t)
	blob, _ := Seal(pub, Segredo{Chave: chaveTeste})
	if _, err := Open(outra, blob); err == nil {
		t.Fatal("privada errada deveria falhar")
	} else if strings.Contains(err.Error(), chaveTeste) {
		t.Fatal("erro vaza a chave")
	}
	for nome, b := range map[string]string{"lixo": "!!!não-base64", "vazio": "", "curto": "AAAA", "adulterado": blob[:len(blob)-8] + "AAAAAAAA"} {
		if _, err := Open(priv, b); err == nil {
			t.Errorf("%s: deveria falhar", nome)
		}
	}
	if _, err := Open(priv, strings.Repeat("A", MaxBlob+1)); err == nil {
		t.Error("blob enorme deveria falhar")
	}
	if _, err := Seal("curta", Segredo{Chave: "x"}); err == nil {
		t.Error("pública inválida deveria falhar")
	}
	if _, err := Seal(pub, Segredo{}); err == nil {
		t.Error("chave vazia deveria falhar")
	}
	if _, err := GenerateKey(priv); err == nil {
		t.Error("GenerateKey não pode sobrescrever")
	}
}
