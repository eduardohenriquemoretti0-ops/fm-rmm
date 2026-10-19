package agent

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func writeTmp(t *testing.T, content string) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "RustDesk.toml")
	if err := os.WriteFile(p, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

func TestEditTOMLTrocaEInsere(t *testing.T) {
	p := writeTmp(t, "id = 'antigo'\nenc_id = 'x'\n")
	if err := editTOML(p, map[string]string{"id": "fmhost", "password": "deadbeef"}, []string{"enc_id"}); err != nil {
		t.Fatal(err)
	}
	b, _ := os.ReadFile(p)
	s := string(b)
	if !strings.Contains(s, "id = 'fmhost'") {
		t.Errorf("id não trocado: %q", s)
	}
	if !strings.Contains(s, "password = 'deadbeef'") {
		t.Errorf("password não inserida: %q", s)
	}
	if strings.Contains(s, "enc_id") {
		t.Errorf("enc_id deveria ter sido removida: %q", s)
	}
}

// A senha de uso único não pode ser corrompida silenciosamente: valor com aspa
// simples (sem escape em TOML literal) tem de FALHAR, não ser reescrito sem a aspa.
func TestEditTOMLRecusaAspaSimples(t *testing.T) {
	p := writeTmp(t, "id = 'x'\n")
	antes, _ := os.ReadFile(p)
	err := editTOML(p, map[string]string{"password": "ab'cd"}, nil)
	if err == nil {
		t.Fatal("deveria recusar valor com aspa simples")
	}
	depois, _ := os.ReadFile(p)
	if string(antes) != string(depois) {
		t.Errorf("arquivo não deveria ter mudado em caso de erro")
	}
}

func TestEditTOMLRecusaControle(t *testing.T) {
	p := writeTmp(t, "id = 'x'\n")
	if err := editTOML(p, map[string]string{"password": "a\nb"}, nil); err == nil {
		t.Fatal("deveria recusar caractere de controle")
	}
}

func TestEditTOMLPerm0600(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("modo de arquivo unix não se aplica ao Windows (ACL via icacls)")
	}
	p := writeTmp(t, "id = 'x'\n")
	if err := editTOML(p, map[string]string{"password": "cafe"}, nil); err != nil {
		t.Fatal(err)
	}
	fi, err := os.Stat(p)
	if err != nil {
		t.Fatal(err)
	}
	if perm := fi.Mode().Perm(); perm != 0o600 {
		t.Errorf("perm = %o, quer 0600", perm)
	}
}

func TestEditTOMLOptionsSobSecao(t *testing.T) {
	p := writeTmp(t, "[options]\nenable-keyboard = 'Y'\n")
	if err := editTOMLOptions(p, map[string]string{"enable-keyboard": "N", "key": "k1"}); err != nil {
		t.Fatal(err)
	}
	b, _ := os.ReadFile(p)
	s := string(b)
	if !strings.Contains(s, "enable-keyboard = 'N'") {
		t.Errorf("enable-keyboard não trocado: %q", s)
	}
	if !strings.Contains(s, "key = 'k1'") {
		t.Errorf("key não inserida sob [options]: %q", s)
	}
}

func TestEditTOMLOptionsCriaSecao(t *testing.T) {
	p := writeTmp(t, "id = 'x'\n")
	if err := editTOMLOptions(p, map[string]string{"key": "k1"}); err != nil {
		t.Fatal(err)
	}
	b, _ := os.ReadFile(p)
	s := string(b)
	if !strings.Contains(s, "[options]") || !strings.Contains(s, "key = 'k1'") {
		t.Errorf("[options] não criada com a chave: %q", s)
	}
}
