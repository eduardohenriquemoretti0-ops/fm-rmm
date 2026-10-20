package agent

// sha256 imposto no install: executor FAKE (nada é baixado nem instalado).

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/eduardohenriquemoretti0-ops/fm-rmm/internal/catalog"
)

func hexSHA(b []byte) string { h := sha256.Sum256(b); return hex.EncodeToString(h[:]) }

// shaFake: "baixa" o conteúdo dado no diretório indicado (--download-directory
// ou Dir::Cache::archives=) e registra os comandos.
type shaFake struct {
	softFake
	arquivo, conteudo string
}

func (f *shaFake) run(ctx context.Context, name string, args ...string) (string, error) {
	for i, a := range args {
		dir := ""
		if a == "--download-directory" && i+1 < len(args) {
			dir = args[i+1]
		}
		if strings.HasPrefix(a, "Dir::Cache::archives=") && contains(args, "--download-only") {
			dir = strings.TrimPrefix(a, "Dir::Cache::archives=")
		}
		if dir != "" {
			if err := os.WriteFile(filepath.Join(dir, f.arquivo), []byte(f.conteudo), 0o600); err != nil {
				return "", err
			}
		}
	}
	return f.softFake.run(ctx, name, args...)
}

func contains(l []string, s string) bool {
	for _, x := range l {
		if x == s {
			return true
		}
	}
	return false
}

func instalarComSHA(t *testing.T, goos, itemID, sha, arquivo, conteudo string) (*shaFake, error) {
	t.Helper()
	ag, _, raiz, rel := agenteSoft(t, goos)
	itens := itensAgente()
	for i := range itens {
		if itens[i].ID == itemID {
			itens[i].SHA256 = sha
		}
	}
	raw, sig := catalogoAssinado(t, raiz, 2, itens)
	if err := ag.IngerirCatalogoSoftware(raw, sig); err != nil {
		t.Fatal(err)
	}
	f := &shaFake{arquivo: arquivo, conteudo: conteudo}
	ag.softRun = f.run
	ag.wingetResolve = nil
	a, _ := catalog.Get("instalar_pacote")
	_, err := ag.softwareAcao(context.Background(), a, jobSW(ag, rel, "instalar_pacote", map[string]string{"item_id": itemID}))
	return f, err
}

func instalou(f *shaFake) bool {
	for _, c := range f.registrado {
		if strings.Contains(c, " install ") && !strings.Contains(c, "--download-only") {
			return true
		}
		if strings.HasPrefix(c, "winget install") || strings.HasPrefix(c, "apt-get -o") {
			return true
		}
	}
	return false
}

func TestSHA256DivergenteRecusaInstalacao(t *testing.T) {
	bom := hexSHA([]byte("instalador-legitimo"))
	casos := []struct{ nome, goos, item, arq string }{
		{"winget", "windows", "vlc", "VLC.exe"},
		{"apt", "linux", "htop", "htop_3.3.0-1_amd64.deb"},
	}
	for _, c := range casos {
		f, err := instalarComSHA(t, c.goos, c.item, bom, c.arq, "instalador-ADULTERADO")
		if err == nil || !strings.Contains(err.Error(), "DIVERGE") {
			t.Errorf("%s: sha divergente deveria recusar: %v", c.nome, err)
		}
		if instalou(f) {
			t.Errorf("%s: INSTALOU apesar da divergência: %v", c.nome, f.registrado)
		}
	}
}

func TestSHA256CorretoInstala(t *testing.T) {
	bom := hexSHA([]byte("instalador-legitimo"))
	f, err := instalarComSHA(t, "windows", "vlc", bom, "VLC.exe", "instalador-legitimo")
	if err != nil || !instalou(f) {
		t.Fatalf("winget: %v %v", err, f.registrado)
	}
	f, err = instalarComSHA(t, "linux", "htop", bom, "htop_3.3.0-1_amd64.deb", "instalador-legitimo")
	if err != nil || !instalou(f) {
		t.Fatalf("apt: %v %v", err, f.registrado)
	}
	// apt instala a partir dos .deb verificados
	if last := f.registrado[len(f.registrado)-1]; !strings.Contains(last, "Dir::Cache::archives=") || !strings.Contains(last, "install -y htop") {
		t.Errorf("apt não reaproveitou o diretório verificado: %q", last)
	}
}

func TestSHA256SemArquivoBaixadoRecusa(t *testing.T) {
	bom := hexSHA([]byte("x"))
	f, err := instalarComSHA(t, "linux", "htop", bom, "outro-pacote_1_amd64.deb", "x")
	if err == nil || !strings.Contains(err.Error(), "não verificável") || instalou(f) {
		t.Fatalf("sem .deb do pacote deveria recusar: %v %v", err, f.registrado)
	}
}

func TestSHA256AusenteMantemFluxo(t *testing.T) {
	f, err := instalarComSHA(t, "windows", "vlc", "", "", "")
	if err != nil || len(f.registrado) != 1 || !strings.HasPrefix(f.registrado[0], "winget install") {
		t.Fatalf("sem sha256 o fluxo deve ser só o install: %v %v", err, f.registrado)
	}
	f, err = instalarComSHA(t, "linux", "htop", "", "", "")
	if err != nil || len(f.registrado) != 1 || f.registrado[0] != "apt-get install -y htop" {
		t.Fatalf("apt sem sha256: %v %v", err, f.registrado)
	}
}
