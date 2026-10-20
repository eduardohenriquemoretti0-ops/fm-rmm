package agent

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/eduardohenriquemoretti0-ops/fm-rmm/internal/catalog"
	"github.com/eduardohenriquemoretti0-ops/fm-rmm/internal/escrow"
	"github.com/eduardohenriquemoretti0-ops/fm-rmm/internal/proto"
)

const chaveFalsa = "111111-222222-333333-444444-555555-666666-777777-888888"

// runnerBitLocker simula o manage-bde: o protetor só existe depois do -add, e
// a saída do -add/-get IMPRIME a chave (como o real). Registra os comandos.
type runnerBitLocker struct {
	temProtetor bool
	protegido   string // "prot;conv" devolvido pelo WMI simulado
	aposOn      string // estado após manage-bde -on ("" = 1;2, cifrando)
	onSaida     string
	cmds        []string
}

func (r *runnerBitLocker) run(_ context.Context, name string, args ...string) (string, error) {
	r.cmds = append(r.cmds, name+" "+strings.Join(args, " "))
	j := strings.Join(args, " ")
	switch {
	case name == "manage-bde" && strings.Contains(j, "-protectors -get"):
		if r.temProtetor {
			return "Password:\n  " + chaveFalsa + "\n", nil
		}
		return "nenhum protetor", fmt.Errorf("exit 1")
	case name == "manage-bde" && strings.Contains(j, "-protectors -add") && strings.Contains(j, "-RecoveryPassword"):
		r.temProtetor = true
		return "Numerical Password:\n Password:\n  " + chaveFalsa + "\n", nil
	case name == "powershell":
		return r.protegido, nil
	case name == "manage-bde" && strings.Contains(j, "-on"):
		r.protegido = r.aposOn
		if r.protegido == "" {
			r.protegido = "1;2"
		}
		return "ok" + r.onSaida, nil
	}
	return "", nil
}

func (l *lab) agenteEscrow(t *testing.T, comPub bool) (*Agent, string) {
	t.Helper()
	priv := filepath.Join(t.TempDir(), "escrow.key")
	pub, err := escrow.GenerateKey(priv)
	if err != nil {
		t.Fatal(err)
	}
	if comPub {
		l.bundle.EscrowPub = pub
	}
	ag := l.newAgent(l.token(1))
	l.enrolled(ag)
	return ag, priv
}

func TestEscrowRoundtripEFluxoDeDados(t *testing.T) {
	l := newLab(t)
	ag, priv := l.agenteEscrow(t, true)
	r := &runnerBitLocker{protegido: "0;0"}
	ag.run, ag.goos = r.run, "windows"

	id := l.job(ag.state.AgentID, "forcar_criptografia", nil)
	if err := ag.CheckinOnce(context.Background()); err != nil {
		t.Fatal(err)
	}
	st, res := l.jobStatus(id)
	if st != "done" || res.Status != "ok" {
		t.Fatalf("job: %s %+v", st, res)
	}
	if !strings.Contains(strings.Join(r.cmds, "|"), "manage-bde -on C: ") {
		t.Fatalf("manage-bde -on não foi chamado: %v", r.cmds)
	}
	if len(l.ran) != 0 {
		t.Fatalf("ação nativa passou pelo pipeline de script: %v", l.ran)
	}

	// o servidor tem o registro SELADO; a privada recupera a chave
	rows, err := l.st.Escrows("")
	if err != nil || len(rows) != 1 {
		t.Fatalf("registros de escrow: %v %v", rows, err)
	}
	e := rows[0]
	if e.AgentID != ag.state.AgentID || e.Volume != "C:" || e.Metodo != "bitlocker" || e.JobID != id {
		t.Fatalf("metadados: %+v", e)
	}
	seg, err := escrow.Open(priv, e.Blob)
	if err != nil || seg.Chave != chaveFalsa || seg.AgentID != ag.state.AgentID {
		t.Fatalf("roundtrip: %+v %v", seg, err)
	}

	// a chave em claro NUNCA aparece: resultado, auditoria, banco (inclusive WAL)
	j, _ := l.st.Job(id)
	entries, _ := l.st.AuditEntries()
	var tudo strings.Builder
	tudo.WriteString(j.Result + j.Signed + j.Params)
	for _, en := range entries {
		fmt.Fprintf(&tudo, "%s %s %v\n", en.Event, en.Actor, en.Data)
	}
	if strings.Contains(tudo.String(), chaveFalsa) || strings.Contains(tudo.String(), "111111-222222") {
		t.Fatalf("chave em claro vazou:\n%s", tudo.String())
	}
	if !strings.Contains(tudo.String(), "escrow.registrado") {
		t.Fatal("auditoria sem escrow.registrado")
	}
	if strings.Contains(j.Result, e.Blob) {
		t.Fatal("blob duplicado no resultado do job")
	}
	// o texto do resultado (o que o operador vê) também não tem a chave
	if strings.Contains(res.Output, chaveFalsa) || res.Escrow != nil {
		t.Fatalf("resultado: %+v", res)
	}
}

func TestEscrowSemPubFalhaAntesDeMexerNoDisco(t *testing.T) {
	l := newLab(t)
	ag, _ := l.agenteEscrow(t, false)
	r := &runnerBitLocker{protegido: "0;0"}
	ag.run, ag.goos = r.run, "windows"
	id := l.job(ag.state.AgentID, "forcar_criptografia", nil)
	_ = ag.CheckinOnce(context.Background())
	st, res := l.jobStatus(id)
	if st != "failed" || !strings.Contains(res.Error, "EscrowPub") {
		t.Fatalf("esperava falha clara: %s %+v", st, res)
	}
	if len(r.cmds) != 0 {
		t.Fatalf("mexeu no disco sem escrow: %v", r.cmds)
	}
	if rows, _ := l.st.Escrows(""); len(rows) != 0 {
		t.Fatal("registro de escrow indevido")
	}
}

func TestEscrowReaproveitaChaveEJaAtiva(t *testing.T) {
	l := newLab(t)
	ag, priv := l.agenteEscrow(t, true)
	r := &runnerBitLocker{temProtetor: true, protegido: "1;1"}
	ag.run, ag.goos = r.run, "windows"
	l.job(ag.state.AgentID, "forcar_criptografia", nil)
	_ = ag.CheckinOnce(context.Background())
	for _, c := range r.cmds {
		if strings.Contains(c, " -on ") || strings.Contains(c, "-RecoveryPassword") && strings.Contains(c, "-add") {
			t.Fatalf("não devia religar nem criar protetor: %v", r.cmds)
		}
	}
	rows, _ := l.st.Escrows("")
	if len(rows) != 1 {
		t.Fatal("sem registro")
	}
	if seg, err := escrow.Open(priv, rows[0].Blob); err != nil || seg.Chave != chaveFalsa {
		t.Fatalf("%+v %v", seg, err)
	}
}

func TestEscrowErroNaoVazaChave(t *testing.T) {
	l := newLab(t)
	ag, _ := l.agenteEscrow(t, true)
	ag.goos = "windows"
	ag.run = func(_ context.Context, name string, args ...string) (string, error) {
		if strings.Contains(strings.Join(args, " "), "-protectors -add") {
			return "falhou, senha " + chaveFalsa, fmt.Errorf("exit 2")
		}
		return "", fmt.Errorf("exit 1")
	}
	id := l.job(ag.state.AgentID, "forcar_criptografia", nil)
	_ = ag.CheckinOnce(context.Background())
	st, res := l.jobStatus(id)
	if st != "failed" || strings.Contains(res.Error+res.Output, chaveFalsa) {
		t.Fatalf("%s %+v", st, res)
	}
}

func TestEscrowLinuxRelataSemHabilitar(t *testing.T) {
	l := newLab(t)
	ag, _ := l.agenteEscrow(t, true)
	var cmds []string
	ag.goos = "linux"
	ag.run = func(_ context.Context, name string, args ...string) (string, error) {
		cmds = append(cmds, name)
		return "sda1 part crypto_LUKS", nil
	}
	id := l.job(ag.state.AgentID, "forcar_criptografia", nil)
	_ = ag.CheckinOnce(context.Background())
	st, res := l.jobStatus(id)
	if st != "failed" || !strings.Contains(res.Error, "LUKS") || !strings.Contains(res.Error, "cryptsetup") {
		t.Fatalf("%s %+v", st, res)
	}
	if len(cmds) != 1 || cmds[0] != "lsblk" {
		t.Fatalf("só leitura era esperada: %v", cmds)
	}
}

func TestEscrowFileVaultLeChaveDoPlistEApaga(t *testing.T) {
	l := newLab(t)
	ag, priv := l.agenteEscrow(t, true)
	ag.goos = "darwin"
	plist := filepath.Join(ag.Dir, arqFileVaultPlist)
	_ = os.WriteFile(plist, []byte("<dict><key>RecoveryKey</key>\n<string>ABCD-EFGH-IJKL-MNOP-QRST-UVWX</string></dict>"), 0o600)
	ag.run = func(context.Context, string, ...string) (string, error) { return "", nil }
	l.job(ag.state.AgentID, "forcar_criptografia", nil)
	_ = ag.CheckinOnce(context.Background())
	rows, _ := l.st.Escrows("")
	if len(rows) != 1 || rows[0].Metodo != "filevault" {
		t.Fatalf("%+v", rows)
	}
	if seg, err := escrow.Open(priv, rows[0].Blob); err != nil || seg.Chave != "ABCD-EFGH-IJKL-MNOP-QRST-UVWX" {
		t.Fatalf("%+v %v", seg, err)
	}
	if _, err := os.Stat(plist); err == nil {
		t.Fatal("plist com a chave não foi removido")
	}
}

func TestEscrowServidorRecusaResultadoDeOutraAcao(t *testing.T) {
	// um agente com bug anexa Escrow ao resultado de um job "info": não entra
	// na tabela; e uma senha de recuperação no Output é redigida.
	l := newLab(t)
	ag, priv := l.agenteEscrow(t, true)
	id := l.job(ag.state.AgentID, "info", nil)
	if _, err := l.st.TakeQueued(context.Background(), ag.state.AgentID); err != nil {
		t.Fatal(err)
	}
	blob, _ := escrow.Seal(ag.bundle.EscrowPub, escrow.Segredo{Chave: chaveFalsa})
	c, _ := ag.client()
	err := ag.post(context.Background(), c, "/v1/result", proto.Result{JobID: id, Status: "ok",
		Output: "vazou " + chaveFalsa, Escrow: &proto.EscrowRecord{Volume: "C:", Metodo: "bitlocker", Blob: blob}}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if rows, _ := l.st.Escrows(""); len(rows) != 0 {
		t.Fatal("escrow de job que não é forcar_criptografia foi aceito")
	}
	_, res := l.jobStatus(id)
	if strings.Contains(res.Output, chaveFalsa) || !strings.Contains(res.Output, "REDIGIDO") {
		t.Fatalf("senha em claro no resultado: %q", res.Output)
	}
	_ = priv
}

func TestAcaoNativaNaoRodaComoScript(t *testing.T) {
	_, _, _, err := runActionNativaParaTeste()
	if err == nil {
		t.Fatal("runAction deveria recusar ação nativa")
	}
}

func runActionNativaParaTeste() (string, int, bool, error) {
	a, _ := catalog.Get("forcar_criptografia")
	return runAction(context.Background(), a, nil)
}

// BitLocker pendente de reboot (teste de hardware do TPM): NÃO pode dizer ligada.
func TestEscrowPendenteRebootNaoMente(t *testing.T) {
	l := newLab(t)
	ag, _ := l.agenteEscrow(t, true)
	r := &runnerBitLocker{protegido: "0;0", aposOn: "0;0", onSaida: " Reinicie o computador para continuar"}
	ag.run, ag.goos = r.run, "windows"
	id := l.job(ag.state.AgentID, "forcar_criptografia", nil)
	_ = ag.CheckinOnce(context.Background())
	st, res := l.jobStatus(id)
	if st != "done" || !strings.Contains(res.Output, "protecao=pendente_reboot") || strings.Contains(res.Output, "protecao=ligada") {
		t.Fatalf("estado mentiu: %s %+v", st, res)
	}
}
