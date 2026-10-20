package agent

// Testes do catálogo de software e de instalar_pacote/desinstalar_pacote.
// NENHUM instala nada: o executor é o softFake, que só registra o comando.

import (
	"context"
	"crypto/ed25519"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/eduardohenriquemoretti0-ops/fm-rmm/internal/catalog"
	"github.com/eduardohenriquemoretti0-ops/fm-rmm/internal/proto"
	"github.com/eduardohenriquemoretti0-ops/fm-rmm/internal/server"
	"github.com/eduardohenriquemoretti0-ops/fm-rmm/internal/sign"
)

type softFake struct{ registrado []string }

func (f *softFake) run(_ context.Context, name string, args ...string) (string, error) {
	f.registrado = append(f.registrado, strings.TrimSpace(name+" "+strings.Join(args, " ")))
	return "fake: nada instalado", nil
}

func itensAgente() []sign.SoftwareItem {
	return []sign.SoftwareItem{
		{ID: "firefox", Nome: "Mozilla Firefox", Gerenciador: sign.GerenciadorWinget, PkgID: "Mozilla.Firefox"},
		{ID: "vlc", Nome: "VLC", Gerenciador: sign.GerenciadorWinget, PkgID: "VideoLAN.VLC", Versao: "3.0.21"},
		{ID: "htop", Nome: "htop", Gerenciador: sign.GerenciadorApt, PkgID: "htop"},
	}
}

func catalogoAssinado(t *testing.T, raiz par, versao int, itens []sign.SoftwareItem) ([]byte, []byte) {
	t.Helper()
	raw, sig, err := sign.SignSoftwareCatalog(raiz.priv, sign.SoftwareCatalog{Version: versao, IssuedAt: time.Now(), Items: itens})
	if err != nil {
		t.Fatal(err)
	}
	return raw, sig
}

// agenteSoft: agente com trust (raiz), catálogo v1 ingerido, SO simulado e fake.
func agenteSoft(t *testing.T, goos string) (*Agent, *softFake, par, *relogio) {
	t.Helper()
	raiz := novoPar(t)
	rel := &relogio{t: time.Now().UTC()}
	ag := novoAgenteTrust(t, raiz, rel)
	s, err := openSeen(filepath.Join(ag.Dir, fileSeen))
	if err != nil {
		t.Fatal(err)
	}
	ag.seen = s
	ag.Log = slog.New(slog.NewTextHandler(io.Discard, nil))
	if ag.soft, err = openSoft(filepath.Join(ag.Dir, fileSoftware), raiz.pub, ag.Log); err != nil {
		t.Fatal(err)
	}
	raw, sig := catalogoAssinado(t, raiz, 1, itensAgente())
	if err := ag.IngerirCatalogoSoftware(raw, sig); err != nil {
		t.Fatal(err)
	}
	f := &softFake{}
	ag.softRun, ag.goos = f.run, goos
	ag.exec = func(context.Context, catalog.Action, map[string]string) (string, int, bool, error) {
		t.Fatal("software passou pelo pipeline de script")
		return "", 0, false, nil
	}
	return ag, f, raiz, rel
}

func jobSW(ag *Agent, rel *relogio, acao string, params map[string]string) proto.JobPayload {
	return proto.JobPayload{V: proto.Version, JobID: fmt.Sprintf("job-sw-%d", contadorJob.Add(1)),
		AgentID: ag.state.AgentID, Action: acao, Params: params,
		IssuedAt: rel.agora(), ExpiresAt: rel.agora().Add(time.Hour), Issuer: "op"}
}

func TestCatalogoSoftwareIngestaoAntiDowngradeEPersistencia(t *testing.T) {
	ag, _, raiz, _ := agenteSoft(t, "windows")
	raw1, sig1 := catalogoAssinado(t, raiz, 1, itensAgente())
	if err := ag.IngerirCatalogoSoftware(raw1, sig1); !errors.Is(err, errCatalogoRepetido) {
		t.Fatalf("mesma versão deveria ser repetida: %v", err)
	}
	raw2, sig2 := catalogoAssinado(t, raiz, 2, itensAgente()[:1])
	if err := ag.IngerirCatalogoSoftware(raw2, sig2); err != nil {
		t.Fatal(err)
	}
	// downgrade (v1 assinada corretamente) recusado
	if err := ag.IngerirCatalogoSoftware(raw1, sig1); !errors.Is(err, sign.ErrCatalogoVersao) {
		t.Fatalf("downgrade aceito: %v", err)
	}
	if _, ok := ag.soft.resolver("htop"); ok {
		t.Fatal("v2 não removeu htop")
	}
	// assinatura de outra chave recusada
	outra := novoPar(t)
	raw3, sig3 := catalogoAssinado(t, outra, 9, itensAgente())
	if err := ag.IngerirCatalogoSoftware(raw3, sig3); !errors.Is(err, sign.ErrCatalogoAssinatura) {
		t.Fatalf("catálogo de outra chave aceito: %v", err)
	}
	// persistência: reabrir mantém v2 e a trava de versão
	s2, err := openSoft(filepath.Join(ag.Dir, fileSoftware), raiz.pub, ag.Log)
	if err != nil {
		t.Fatal(err)
	}
	if s2.maxVersion != 2 {
		t.Fatalf("versão persistida = %d", s2.maxVersion)
	}
	if _, ok := s2.resolver("firefox"); !ok {
		t.Fatal("item perdido após reabrir")
	}
	// com outra raiz (reprovisionamento) o guardado é descartado
	s3, err := openSoft(filepath.Join(ag.Dir, fileSoftware), ed25519.PublicKey(outra.pub), ag.Log)
	if err != nil || s3.maxVersion != 0 {
		t.Fatalf("catálogo de outra raiz não foi descartado: v=%d err=%v", s3.maxVersion, err)
	}
}

func TestInstalarPacoteMontaComandoCerto(t *testing.T) {
	casos := []struct {
		goos, acao, item, want string
	}{
		{"windows", "instalar_pacote", "firefox", "winget install --id Mozilla.Firefox --exact --silent --accept-package-agreements --accept-source-agreements"},
		{"windows", "instalar_pacote", "vlc", "winget install --id VideoLAN.VLC --exact --silent --accept-package-agreements --accept-source-agreements --version 3.0.21"},
		{"windows", "desinstalar_pacote", "firefox", "winget uninstall --id Mozilla.Firefox --exact --silent --accept-source-agreements"},
		{"linux", "instalar_pacote", "htop", "apt-get install -y htop"},
		{"linux", "desinstalar_pacote", "htop", "apt-get remove -y htop"},
	}
	for _, c := range casos {
		ag, f, raiz, rel := agenteSoft(t, c.goos)
		res := ag.handleJob(context.Background(), assina(t, raiz, jobSW(ag, rel, c.acao, map[string]string{"item_id": c.item})))
		if res.Status != "ok" {
			t.Fatalf("%s/%s: %+v", c.acao, c.item, res)
		}
		if len(f.registrado) != 1 || f.registrado[0] != c.want {
			t.Fatalf("%s/%s: comando = %v, queria %q", c.acao, c.item, f.registrado, c.want)
		}
		t.Logf("fake registrou (NADA instalado): %s", f.registrado[0])
	}
}

func TestSoftwareItemForaDoCatalogoRecusado(t *testing.T) {
	for _, acao := range []string{"instalar_pacote", "desinstalar_pacote"} {
		ag, f, raiz, rel := agenteSoft(t, "windows")
		res := ag.handleJob(context.Background(), assina(t, raiz, jobSW(ag, rel, acao, map[string]string{"item_id": "malware"})))
		if res.Status == "ok" || len(f.registrado) != 0 {
			t.Fatalf("%s: item fora do catálogo executou: %+v cmds=%v", acao, res, f.registrado)
		}
		t.Logf("%s recusado: %s", acao, res.Error)
	}
	// sem catálogo nenhum: tudo recusado
	ag, f, raiz, rel := agenteSoft(t, "windows")
	ag.soft, _ = openSoft(filepath.Join(t.TempDir(), "s.json"), raiz.pub, ag.Log)
	res := ag.handleJob(context.Background(), assina(t, raiz, jobSW(ag, rel, "instalar_pacote", map[string]string{"item_id": "firefox"})))
	if res.Status == "ok" || len(f.registrado) != 0 {
		t.Fatalf("sem catálogo executou: %+v", res)
	}
	// item winget num Linux (gerenciador incompatível com o SO): recusado
	ag, f, raiz, rel = agenteSoft(t, "linux")
	res = ag.handleJob(context.Background(), assina(t, raiz, jobSW(ag, rel, "instalar_pacote", map[string]string{"item_id": "firefox"})))
	if res.Status == "ok" || len(f.registrado) != 0 {
		t.Fatalf("winget no linux executou: %+v", res)
	}
}

func TestOperadorNaoInjetaPkgID(t *testing.T) {
	ag, f, raiz, rel := agenteSoft(t, "windows")
	maus := []map[string]string{
		{"item_id": "firefox", "pkg_id": "Evil.Malware"},
		{"pkg_id": "Evil.Malware"},
		{"item_id": "firefox", "comando": "calc"},
		{"item_id": "firefox; calc"},
		{"item_id": "firefox --source evil"},
		{"item_id": "$(calc)"},
		{"item_id": "-firefox"},
		{"item_id": "FIREFOX"},
		{"item_id": "../firefox"},
		{},
	}
	for _, p := range maus {
		for _, acao := range []string{"instalar_pacote", "desinstalar_pacote"} {
			res := ag.handleJob(context.Background(), assina(t, raiz, jobSW(ag, rel, acao, p)))
			if res.Status == "ok" {
				t.Fatalf("%s %v aceito", acao, p)
			}
		}
	}
	if len(f.registrado) != 0 {
		t.Fatalf("algo executou: %v", f.registrado)
	}
}

func TestValidateRecusaInjecaoNoItemID(t *testing.T) {
	for _, acao := range []string{"instalar_pacote", "desinstalar_pacote"} {
		if _, err := catalog.Validate(acao, "windows", map[string]string{"item_id": "firefox"}); err != nil {
			t.Fatalf("%s item válido recusado: %v", acao, err)
		}
		if _, err := catalog.Validate(acao, "linux", map[string]string{"item_id": "htop"}); err != nil {
			t.Fatalf("%s item válido recusado: %v", acao, err)
		}
		if _, err := catalog.Validate(acao, "darwin", map[string]string{"item_id": "htop"}); err == nil {
			t.Fatalf("%s aceito em darwin", acao)
		}
		for _, v := range []string{"a;b", "a b", "a&b", "a|b", "a`b`", "$(x)", "a\nb", "-x", "A", "a/b", "", strings.Repeat("a", 49), "a\"b"} {
			if _, err := catalog.Validate(acao, "windows", map[string]string{"item_id": v}); err == nil {
				t.Errorf("%s: item_id %q aceito", acao, v)
			}
		}
		if _, err := catalog.Validate(acao, "windows", map[string]string{"item_id": "firefox", "pkg_id": "x"}); err == nil {
			t.Errorf("%s: pkg_id aceito como parâmetro", acao)
		}
	}
}

func TestMontarSoftwareRevalidaItem(t *testing.T) {
	// defesa em profundidade: item corrompido em memória não vira comando
	_, err := MontarSoftware("windows", "instalar", sign.SoftwareItem{ID: "x", Nome: "X", Gerenciador: sign.GerenciadorWinget, PkgID: "a --source evil"})
	if err == nil {
		t.Fatal("pkg_id com espaço virou comando")
	}
	if _, err := MontarSoftware("windows", "formatar", itensAgente()[0]); err == nil {
		t.Fatal("operação desconhecida aceita")
	}
}

// E2E: build offline -> publicar -> servido no check-in -> agente guarda -> instala (fake).
func TestCatalogoSoftwareEndToEnd(t *testing.T) {
	l := newLab(t)
	ctx := context.Background()
	ag := l.newAgent(l.token(1))
	l.enrolled(ag)
	raizPub := l.admin.Public().(ed25519.PublicKey)
	f := &softFake{}
	ag.softRun, ag.goos = f.run, "windows"

	raw1, sig1, v1, err := server.ConstruirCatalogoSoftware(l.admin, 0, itensAgente(), ag.now())
	if err != nil || v1 != 1 {
		t.Fatalf("construir: v=%d %v", v1, err)
	}
	if _, err := server.PublicarCatalogoSoftware(l.st, raizPub, raw1, sig1, "teste"); err != nil {
		t.Fatal(err)
	}
	// republicar a mesma versão e publicar com outra raiz: recusados no servidor
	if _, err := server.PublicarCatalogoSoftware(l.st, raizPub, raw1, sig1, "teste"); !errors.Is(err, sign.ErrCatalogoVersao) {
		t.Fatalf("republicar v1: %v", err)
	}
	outra := novoPar(t)
	rawX, sigX, _, _ := server.ConstruirCatalogoSoftware(outra.priv, 1, itensAgente(), ag.now())
	if _, err := server.PublicarCatalogoSoftware(l.st, raizPub, rawX, sigX, "teste"); !errors.Is(err, sign.ErrCatalogoAssinatura) {
		t.Fatalf("publicar com outra raiz: %v", err)
	}
	if err := ag.CheckinOnce(ctx); err != nil {
		t.Fatal(err)
	}
	if _, ok := ag.soft.resolver("firefox"); !ok || ag.soft.maxVersion != 1 {
		t.Fatalf("agente não recebeu o catálogo no check-in (v=%d)", ag.soft.maxVersion)
	}
	// job assinado de instalar item do catálogo recebido
	p := proto.JobPayload{V: proto.Version, JobID: "job-sw-e2e", AgentID: ag.state.AgentID, Action: "instalar_pacote",
		Params: map[string]string{"item_id": "firefox"}, IssuedAt: ag.now(), ExpiresAt: ag.now().Add(time.Hour), Issuer: "admin"}
	sj, err := sign.SignJob(l.admin, p)
	if err != nil {
		t.Fatal(err)
	}
	if res := ag.handleJob(ctx, sj); res.Status != "ok" {
		t.Fatalf("instalar: %+v", res)
	}
	if len(f.registrado) != 1 || !strings.HasPrefix(f.registrado[0], "winget install --id Mozilla.Firefox --exact") {
		t.Fatalf("comando: %v", f.registrado)
	}
	// v2 (sem vlc) chega no próximo check-in
	raw2, sig2, _, _ := server.ConstruirCatalogoSoftware(l.admin, 1, itensAgente()[:1], ag.now())
	if _, err := server.PublicarCatalogoSoftware(l.st, raizPub, raw2, sig2, "teste"); err != nil {
		t.Fatal(err)
	}
	if err := ag.CheckinOnce(ctx); err != nil {
		t.Fatal(err)
	}
	if _, ok := ag.soft.resolver("vlc"); ok || ag.soft.maxVersion != 2 {
		t.Fatal("v2 não aplicada")
	}
}
