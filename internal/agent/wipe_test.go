package agent

// Testes do gate do wipe_remoto e da montagem do comando. NENHUM executa wipe
// de verdade: o executor é o wipeFake, que só registra. Também usado como
// padrão em lab.newAgent, para que nenhum teste jamais alcance o realWipe.

import (
	"context"
	"io"
	"log/slog"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/eduardohenriquemoretti0-ops/fm-rmm/internal/catalog"
	"github.com/eduardohenriquemoretti0-ops/fm-rmm/internal/proto"
	"github.com/eduardohenriquemoretti0-ops/fm-rmm/internal/sign"
)

type wipeFake struct {
	alvos      []string
	alvosErr   error
	consultas  int
	execucoes  int // quantas vezes Executar foi chamado
	registrado []string
	protErr    error
	verifErr   error
	verificado int
	ordem      []string // "exec" / "verif" na ordem
}

func (f *wipeFake) Protetores(_ context.Context, goos string, alvos []string) (map[string][]string, error) {
	if f.protErr != nil {
		return nil, f.protErr
	}
	m := map[string][]string{}
	if goos == "windows" {
		for _, a := range alvos {
			m[a] = []string{idTPM, idRec}
		}
	}
	return m, nil
}

func (f *wipeFake) Verificar(_ context.Context, _ string, _ []string) error {
	f.verificado++
	f.ordem = append(f.ordem, "verif")
	return f.verifErr
}

const (
	idTPM = "{11111111-2222-3333-4444-555555555555}"
	idRec = "{AAAAAAAA-BBBB-CCCC-DDDD-EEEEEEEEEEEE}"
)

func (f *wipeFake) Alvos(_ context.Context, _ string) ([]string, error) {
	f.consultas++
	return f.alvos, f.alvosErr
}

func (f *wipeFake) Executar(_ context.Context, cmds []WipeCmd) (string, error) {
	f.execucoes++
	f.ordem = append(f.ordem, "exec")
	for _, c := range cmds {
		f.registrado = append(f.registrado, c.String())
	}
	return "fake: nada executado de verdade", nil
}

// agenteWipe: agente com trust-set (raiz = operador), seen, SO simulado e o fake.
func agenteWipe(t *testing.T) (*Agent, *wipeFake, par, *relogio) {
	t.Helper()
	raiz := novoPar(t)
	rel := &relogio{t: time.Now().UTC()}
	ag := novoAgenteTrust(t, raiz, rel)
	s, err := openSeen(filepath.Join(ag.Dir, fileSeen))
	if err != nil {
		t.Fatal(err)
	}
	ag.seen = s
	ag.state.AgentID = "ag-0123456789abcdef"
	ag.Log = slog.New(slog.NewTextHandler(io.Discard, nil))
	f := &wipeFake{alvos: []string{"C:"}}
	ag.wipe, ag.goos = f, "windows"
	ag.exec = func(context.Context, catalog.Action, map[string]string) (string, int, bool, error) {
		t.Fatal("wipe passou pelo pipeline de script")
		return "", 0, false, nil
	}
	return ag, f, raiz, rel
}

func jobWipe(ag *Agent, rel *relogio, id string, params map[string]string) proto.JobPayload {
	return proto.JobPayload{V: proto.Version, JobID: id, AgentID: ag.state.AgentID, Action: "wipe_remoto",
		Params: params, IssuedAt: rel.agora(), ExpiresAt: rel.agora().Add(time.Hour), Issuer: "op"}
}

func okParams(ag *Agent) map[string]string {
	return map[string]string{"motivo": "roubo", "confirmacao": "WIPE-" + ag.state.AgentID}
}

func assina(t *testing.T, k par, p proto.JobPayload) proto.SignedJob {
	t.Helper()
	sj, err := sign.SignJob(k.priv, p)
	if err != nil {
		t.Fatal(err)
	}
	return sj
}

func TestWipeCaminhoCompletoSoRegistraNoFake(t *testing.T) {
	ag, f, raiz, rel := agenteWipe(t)
	res := ag.handleJob(context.Background(), assina(t, raiz, jobWipe(ag, rel, "job-wipe-ok", okParams(ag))))
	if res.Status != "ok" {
		t.Fatalf("wipe do caminho completo deveria ser aceito: %+v", res)
	}
	if f.execucoes != 2 {
		t.Fatalf("execuções = %d", f.execucoes)
	}
	// a senha aleatória NUNCA aparece no registro (Sigiloso); protetor novo ANTES dos deletes;
	// nunca "-delete" sem -id (seria o caminho que gera clear key); verificação entre o corpo e o shutdown
	want := []string{
		"manage-bde <argumentos ocultos>",
		"manage-bde -protectors -delete C: -id " + idTPM,
		"manage-bde -protectors -delete C: -id " + idRec,
		"shutdown /s /t 15 /f",
	}
	if strings.Join(f.ordem, ",") != "exec,verif,exec" {
		t.Fatalf("ordem = %v", f.ordem)
	}
	if strings.Join(f.registrado, "|") != strings.Join(want, "|") {
		t.Fatalf("comandos de cripto-erase = %v", f.registrado)
	}
	t.Logf("fake registrou (NADA executado): %v", f.registrado)
}

func TestWipeLinuxMontaLuksErase(t *testing.T) {
	ag, f, raiz, rel := agenteWipe(t)
	ag.goos, f.alvos = "linux", []string{"/dev/nvme0n1p3"}
	res := ag.handleJob(context.Background(), assina(t, raiz, jobWipe(ag, rel, "job-wipe-lx", okParams(ag))))
	if res.Status != "ok" || len(f.registrado) != 2 || f.verificado != 1 || f.registrado[0] != "cryptsetup luksErase --batch-mode /dev/nvme0n1p3" {
		t.Fatalf("%+v %v", res, f.registrado)
	}
}

func TestWipeRecusadoNoGate(t *testing.T) {
	casos := []struct {
		nome   string
		params func(ag *Agent) map[string]string
	}{
		{"sem confirmacao", func(ag *Agent) map[string]string { return map[string]string{"motivo": "roubo"} }},
		{"confirmacao errada (outro agente)", func(ag *Agent) map[string]string {
			return map[string]string{"motivo": "roubo", "confirmacao": "WIPE-ag-ffffffffffffffff"}
		}},
		{"confirmacao sem prefixo", func(ag *Agent) map[string]string {
			return map[string]string{"motivo": "roubo", "confirmacao": ag.state.AgentID}
		}},
		{"sem motivo", func(ag *Agent) map[string]string {
			return map[string]string{"confirmacao": "WIPE-" + ag.state.AgentID}
		}},
		{"motivo fora da lista", func(ag *Agent) map[string]string {
			return map[string]string{"motivo": "teste", "confirmacao": "WIPE-" + ag.state.AgentID}
		}},
	}
	for i, c := range casos {
		t.Run(c.nome, func(t *testing.T) {
			ag, f, raiz, rel := agenteWipe(t)
			res := ag.handleJob(context.Background(), assina(t, raiz, jobWipe(ag, rel, "job-recusa-"+string(rune('a'+i))+"xx", c.params(ag))))
			if res.Status == "ok" || f.execucoes != 0 || f.consultas != 0 {
				t.Fatalf("deveria recusar sem tocar em nada: %+v execucoes=%d consultas=%d", res, f.execucoes, f.consultas)
			}
		})
	}
}

// confirmacao errada passando pelo gate do agente (catalog.Validate aceita o formato).
func TestWipeConfirmacaoErradaRecusaNoAgenteNaoNoCatalogo(t *testing.T) {
	ag, f, raiz, rel := agenteWipe(t)
	p := jobWipe(ag, rel, "job-conf-errada", map[string]string{"motivo": "perda", "confirmacao": "WIPE-ag-ffffffffffffffff"})
	res := ag.handleJob(context.Background(), assina(t, raiz, p))
	if res.Status != "erro" || !strings.Contains(res.Error, "wipe recusado") || f.execucoes != 0 {
		t.Fatalf("%+v execucoes=%d", res, f.execucoes)
	}
}

func TestWipeSemFlagDestructiveRecusado(t *testing.T) {
	ag, f, _, rel := agenteWipe(t)
	a, _ := catalog.Get("wipe_remoto")
	a.Destructive = false // catálogo adulterado/regressão
	_, _, _, err := ag.runNative(context.Background(), a, jobWipe(ag, rel, "job-sem-flag", okParams(ag)))
	if err == nil || !strings.Contains(err.Error(), "Destructive") || f.execucoes != 0 || f.consultas != 0 {
		t.Fatalf("err=%v execucoes=%d", err, f.execucoes)
	}
}

func TestWipeAssinaturaInvalidaNaoExecuta(t *testing.T) {
	ag, f, _, rel := agenteWipe(t)
	intruso := novoPar(t) // fora do trust-set
	res := ag.handleJob(context.Background(), assina(t, intruso, jobWipe(ag, rel, "job-forjado", okParams(ag))))
	if res.JobID != "" || res.Status == "ok" || f.execucoes != 0 || f.consultas != 0 {
		t.Fatalf("job forjado foi tratado: %+v", res)
	}
}

func TestWipeReplayNaoExecutaDuasVezes(t *testing.T) {
	ag, f, raiz, rel := agenteWipe(t)
	sj := assina(t, raiz, jobWipe(ag, rel, "job-replay-w", okParams(ag)))
	if ag.handleJob(context.Background(), sj).Status != "ok" {
		t.Fatal("1ª deveria ok")
	}
	if r := ag.handleJob(context.Background(), sj); r.Status != "recusado" || f.execucoes != 2 {
		t.Fatalf("replay: %+v execucoes=%d", r, f.execucoes)
	}
}

func TestWipeJobDeOutroAgenteRecusado(t *testing.T) {
	ag, f, raiz, rel := agenteWipe(t)
	p := jobWipe(ag, rel, "job-outro-ag", map[string]string{"motivo": "roubo", "confirmacao": "WIPE-ag-ffffffffffffffff"})
	p.AgentID = "ag-ffffffffffffffff"
	res := ag.handleJob(context.Background(), assina(t, raiz, p))
	if res.Status == "ok" || f.execucoes != 0 {
		t.Fatalf("%+v", res)
	}
}

func TestWipeDiscoNaoCifradoRecusaSemApagar(t *testing.T) {
	ag, f, raiz, rel := agenteWipe(t)
	f.alvos, f.alvosErr = nil, context.DeadlineExceeded
	res := ag.handleJob(context.Background(), assina(t, raiz, jobWipe(ag, rel, "job-sem-cifra", okParams(ag))))
	if res.Status != "erro" || f.execucoes != 0 {
		t.Fatalf("%+v", res)
	}
}

func TestMontarWipeRecusaAlvoComInjecao(t *testing.T) {
	for _, a := range []string{"C:;calc", "C", "/dev/sda1", "c:"} {
		if _, err := MontarWipe("windows", []string{a}, map[string][]string{a: {idTPM}}); err == nil {
			t.Errorf("windows aceitou %q", a)
		}
	}
	for _, a := range []string{"/dev/sda1; rm -rf /", "/etc/passwd", "/dev/../etc/x", "/dev/a b"} {
		if _, err := MontarWipe("linux", []string{a}, nil); err == nil {
			t.Errorf("linux aceitou %q", a)
		}
	}
	if _, err := MontarWipe("darwin", []string{"/"}, nil); err == nil {
		t.Error("darwin deveria ser sem suporte")
	}
	if _, err := MontarWipe("windows", nil, nil); err == nil {
		t.Error("sem alvos deveria falhar")
	}
}

// lock_remoto: ação assinada comum (script), aceita no caminho assinado.
func TestLockRemotoAceitoNoCaminhoAssinado(t *testing.T) {
	ag, _, raiz, rel := agenteWipe(t)
	var ran []string
	ag.exec = func(_ context.Context, a catalog.Action, p map[string]string) (string, int, bool, error) {
		ran = append(ran, a.Name)
		return "travado", 0, false, nil
	}
	p := proto.JobPayload{V: proto.Version, JobID: "job-lock-ok1", AgentID: ag.state.AgentID, Action: "lock_remoto",
		IssuedAt: rel.agora(), ExpiresAt: rel.agora().Add(time.Hour), Issuer: "op"}
	if res := ag.handleJob(context.Background(), assina(t, raiz, p)); res.Status != "ok" || len(ran) != 1 || ran[0] != "lock_remoto" {
		t.Fatalf("%+v %v", res, ran)
	}
	// forjado: não executa
	intruso := novoPar(t)
	p.JobID = "job-lock-bad"
	if res := ag.handleJob(context.Background(), assina(t, intruso, p)); res.Status == "ok" || len(ran) != 1 {
		t.Fatalf("lock forjado executou: %+v", res)
	}
}

// Wipe do Windows: protetor aleatório entra antes de qualquer remoção; remoção só por -id;
// a senha vai no argumento do manage-bde mas nunca no String() (log/resultado).
func TestMontarWindowsSenhaAleatoriaPrimeiroEDescartada(t *testing.T) {
	orig := novaSenhaWipe
	defer func() { novaSenhaWipe = orig }()
	novaSenhaWipe = func() (string, error) { return "987659-222222-333333-444444-555555-666666-777777-888888", nil }
	cmds, err := MontarWipe("windows", []string{"C:"}, map[string][]string{"C:": {idTPM, idRec}})
	if err != nil {
		t.Fatal(err)
	}
	if len(cmds) != 4 || !cmds[0].Sigiloso || cmds[0].Args[1] != "-add" || cmds[0].Args[3] != "-RecoveryPassword" {
		t.Fatalf("primeiro comando deve ser o -add sigiloso: %+v", cmds)
	}
	for _, c := range cmds[1:] {
		if c.Sigiloso {
			t.Errorf("só o -add é sigiloso: %+v", c)
		}
		if c.Name == "manage-bde" && !strings.Contains(c.String(), " -id {") {
			t.Errorf("delete sem -id: %s", c)
		}
	}
	for _, c := range cmds {
		if strings.Contains(c.String(), "987659") {
			t.Errorf("senha vazou em String(): %s", c)
		}
	}
}

func TestGerarSenhaNumericaFormatoBitLocker(t *testing.T) {
	re := regexp.MustCompile(`^(\d{6}-){7}\d{6}$`)
	a, _ := gerarSenhaNumerica()
	b, _ := gerarSenhaNumerica()
	if !re.MatchString(a) || a == b {
		t.Fatalf("%q %q", a, b)
	}
	for _, g := range strings.Split(a, "-") {
		n, _ := strconv.Atoi(g)
		if n%11 != 0 || n > 720895 {
			t.Fatalf("grupo inválido %s", g)
		}
	}
}

func TestMontarWindowsRecusaSemProtetoresOuIdInvalido(t *testing.T) {
	if _, err := MontarWipe("windows", []string{"C:"}, nil); err == nil {
		t.Error("sem protetores listados deveria recusar")
	}
	if _, err := MontarWipe("windows", []string{"C:"}, map[string][]string{"C:": {"{x}; calc"}}); err == nil {
		t.Error("id inválido deveria recusar")
	}
}

// verificação reprova (ex.: clear key presente): NÃO desliga, reporta INEFETIVO.
func TestWipeInefetivoNaoDesligaEReportaErro(t *testing.T) {
	ag, f, raiz, rel := agenteWipe(t)
	f.verifErr = context.Canceled
	res := ag.handleJob(context.Background(), assina(t, raiz, jobWipe(ag, rel, "job-inefetivo", okParams(ag))))
	if res.Status != "erro" || !strings.Contains(res.Error, "INEFETIVO") || f.execucoes != 1 {
		t.Fatalf("%+v execucoes=%d", res, f.execucoes)
	}
	for _, r := range f.registrado {
		if strings.HasPrefix(r, "shutdown") {
			t.Fatalf("desligou apesar de inefetivo: %v", f.registrado)
		}
	}
}

func TestWipeSemListaDeProtetoresRecusaSemApagar(t *testing.T) {
	ag, f, raiz, rel := agenteWipe(t)
	f.protErr = context.DeadlineExceeded
	res := ag.handleJob(context.Background(), assina(t, raiz, jobWipe(ag, rel, "job-sem-prot", okParams(ag))))
	if res.Status != "erro" || f.execucoes != 0 {
		t.Fatalf("%+v", res)
	}
}
