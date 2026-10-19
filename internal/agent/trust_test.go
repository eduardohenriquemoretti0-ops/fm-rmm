package agent

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/eduardohenriquemoretti0-ops/fm-rmm/internal/catalog"
	"github.com/eduardohenriquemoretti0-ops/fm-rmm/internal/proto"
	"github.com/eduardohenriquemoretti0-ops/fm-rmm/internal/sign"
)

// Trust-set do agente: lista assinada pela raiz, anti-downgrade persistido,
// revogação por nova versão e validade (not_after).

type par struct {
	pub  ed25519.PublicKey
	priv ed25519.PrivateKey
}

func novoPar(t *testing.T) par {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return par{pub, priv}
}

func entrada(p par, role string, notAfter *time.Time) sign.SignerEntry {
	return sign.SignerEntry{KeyID: sign.KeyID(p.pub), Pub: sign.EncodePub(p.pub), Role: role, NotAfter: notAfter}
}

// relogio é um relógio controlável para os testes.
type relogio struct {
	mu sync.Mutex
	t  time.Time
}

func (r *relogio) agora() time.Time { r.mu.Lock(); defer r.mu.Unlock(); return r.t }
func (r *relogio) avanca(d time.Duration) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.t = r.t.Add(d)
}

// novoAgenteTrust monta um Agent mínimo com trust-set em diretório temporário.
func novoAgenteTrust(t *testing.T, raiz par, rel *relogio) *Agent {
	t.Helper()
	dir := t.TempDir()
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	tr, err := openTrust(filepath.Join(dir, fileTrust), raiz.pub, rel.agora(), log)
	if err != nil {
		t.Fatal(err)
	}
	ag := &Agent{Dir: dir, Log: log, signer: raiz.pub, trust: tr, now: rel.agora}
	ag.state.AgentID = "ag-1"
	return ag
}

// listaAssinada gera raw+assinatura de uma lista, assinados pela raiz.
func listaAssinada(t *testing.T, raiz par, versao int, emitida time.Time, signers ...sign.SignerEntry) ([]byte, []byte) {
	t.Helper()
	raw, sig, err := sign.SignSignerList(raiz.priv, sign.SignerList{Version: versao, IssuedAt: emitida, Signers: signers})
	if err != nil {
		t.Fatal(err)
	}
	return raw, sig
}

var contadorJob atomic.Int64

// jobDeTeste monta um job de ação "info" para o agente de teste (ID inédito).
func jobDeTeste(now time.Time) proto.JobPayload {
	return proto.JobPayload{V: proto.Version, JobID: fmt.Sprintf("job-trust-%d", contadorJob.Add(1)),
		AgentID: "ag-1", Action: "info", IssuedAt: now, ExpiresAt: now.Add(time.Hour), Issuer: "teste"}
}

// concessao assina uma concessão de sessão de teste com a chave dada.
func concessao(t *testing.T, p par, agentID string, now time.Time) proto.SignedGrant {
	t.Helper()
	g := proto.RemoteGrant{V: proto.Version, SessionID: "sessao-1", AgentID: agentID, Technician: "joao",
		Mode: proto.ModeView, Engine: proto.EngineScreenshot, RelayURL: "wss://relay.test", RelayToken: "tok",
		IssuedAt: now, ExpiresAt: now.Add(10 * time.Minute), Issuer: "teste"}
	sg, err := sign.SignGrant(p.priv, g)
	if err != nil {
		t.Fatal(err)
	}
	return sg
}

// aceitaConcessao diz se a concessão passa pelo trust-set atual do agente.
func aceitaConcessao(ag *Agent, sg proto.SignedGrant) error {
	_, err := sign.VerifyGrantAny(ag.confianca(), sg, ag.state.AgentID, ag.now())
	return err
}

func TestListaForjadaNaoAltera(t *testing.T) {
	raiz, intruso, op := novoPar(t), novoPar(t), novoPar(t)
	rel := &relogio{t: time.Now().UTC()}
	ag := novoAgenteTrust(t, raiz, rel)

	raw, sig := listaAssinada(t, intruso, 1, rel.agora(), entrada(op, sign.RoleOperator, nil)) // assinada por NÃO-raiz
	if err := ag.IngerirListaSigners(raw, sig); !errors.Is(err, sign.ErrListaAssinatura) {
		t.Fatalf("lista forjada: esperado ErrListaAssinatura, veio %v", err)
	}
	if err := aceitaConcessao(ag, concessao(t, op, "ag-1", rel.agora())); !errors.Is(err, sign.ErrSignature) {
		t.Fatalf("operador de lista forjada foi aceito: %v", err)
	}
}

func TestDowngradeRecusadoEPersistido(t *testing.T) {
	raiz, op := novoPar(t), novoPar(t)
	rel := &relogio{t: time.Now().UTC()}
	ag := novoAgenteTrust(t, raiz, rel)

	raw2, sig2 := listaAssinada(t, raiz, 2, rel.agora(), entrada(op, sign.RoleOperator, nil))
	if err := ag.IngerirListaSigners(raw2, sig2); err != nil {
		t.Fatalf("v2 válida recusada: %v", err)
	}
	raw1, sig1 := listaAssinada(t, raiz, 1, rel.agora()) // lista antiga, sem operador, assinada corretamente
	if err := ag.IngerirListaSigners(raw1, sig1); !errors.Is(err, sign.ErrListaVersao) {
		t.Fatalf("downgrade v1 após v2: esperado ErrListaVersao, veio %v", err)
	}
	if err := ag.IngerirListaSigners(raw2, sig2); !errors.Is(err, sign.ErrListaVersao) {
		t.Fatalf("replay da mesma v2: esperado ErrListaVersao, veio %v", err)
	}
	// o downgrade não pode ter removido o operador
	if err := aceitaConcessao(ag, concessao(t, op, "ag-1", rel.agora())); err != nil {
		t.Fatalf("operador da v2 perdeu validade após downgrade recusado: %v", err)
	}

	// reinício do agente: a versão máxima continua sendo v2
	tr, err := openTrust(filepath.Join(ag.Dir, fileTrust), raiz.pub, rel.agora(), ag.Log)
	if err != nil {
		t.Fatal(err)
	}
	ag2 := &Agent{Dir: ag.Dir, Log: ag.Log, signer: raiz.pub, trust: tr, now: rel.agora}
	ag2.state.AgentID = "ag-1"
	if err := ag2.IngerirListaSigners(raw1, sig1); !errors.Is(err, sign.ErrListaVersao) {
		t.Fatalf("após reinício, downgrade aceito: %v", err)
	}
	if err := aceitaConcessao(ag2, concessao(t, op, "ag-1", rel.agora())); err != nil {
		t.Fatalf("após reinício, trust-set da v2 não foi restaurado: %v", err)
	}
}

func TestOperadorDaListaEntraNoTrustSet(t *testing.T) {
	raiz, op := novoPar(t), novoPar(t)
	rel := &relogio{t: time.Now().UTC()}
	ag := novoAgenteTrust(t, raiz, rel)

	if err := aceitaConcessao(ag, concessao(t, op, "ag-1", rel.agora())); !errors.Is(err, sign.ErrSignature) {
		t.Fatalf("operador antes da lista: esperado ErrSignature, veio %v", err)
	}
	raw, sig := listaAssinada(t, raiz, 1, rel.agora(), entrada(op, sign.RoleOperator, nil))
	if err := ag.IngerirListaSigners(raw, sig); err != nil {
		t.Fatalf("lista v1 recusada: %v", err)
	}
	if err := aceitaConcessao(ag, concessao(t, op, "ag-1", rel.agora())); err != nil {
		t.Fatalf("grant do operador da lista recusado: %v", err)
	}
	// a raiz continua valendo junto com a lista
	if err := aceitaConcessao(ag, concessao(t, raiz, "ag-1", rel.agora())); err != nil {
		t.Fatalf("grant da raiz recusado com lista presente: %v", err)
	}
}

func TestOperadorRemovidoNaV2DeixaDeValer(t *testing.T) {
	raiz, op := novoPar(t), novoPar(t)
	rel := &relogio{t: time.Now().UTC()}
	ag := novoAgenteTrust(t, raiz, rel)

	raw1, sig1 := listaAssinada(t, raiz, 1, rel.agora(), entrada(op, sign.RoleOperator, nil))
	if err := ag.IngerirListaSigners(raw1, sig1); err != nil {
		t.Fatal(err)
	}
	sgAntiga := concessao(t, op, "ag-1", rel.agora())
	if err := aceitaConcessao(ag, sgAntiga); err != nil {
		t.Fatalf("antes da revogação: %v", err)
	}

	raw2, sig2 := listaAssinada(t, raiz, 2, rel.agora()) // v2 sem o operador
	if err := ag.IngerirListaSigners(raw2, sig2); err != nil {
		t.Fatalf("v2 recusada: %v", err)
	}
	if err := aceitaConcessao(ag, concessao(t, op, "ag-1", rel.agora())); !errors.Is(err, sign.ErrSignature) {
		t.Fatalf("operador revogado ainda aceito: %v", err)
	}
	// reinício: a revogação persiste
	tr, err := openTrust(filepath.Join(ag.Dir, fileTrust), raiz.pub, rel.agora(), ag.Log)
	if err != nil {
		t.Fatal(err)
	}
	ag2 := &Agent{Dir: ag.Dir, Log: ag.Log, signer: raiz.pub, trust: tr, now: rel.agora}
	ag2.state.AgentID = "ag-1"
	if err := aceitaConcessao(ag2, concessao(t, op, "ag-1", rel.agora())); !errors.Is(err, sign.ErrSignature) {
		t.Fatalf("após reinício, operador revogado voltou: %v", err)
	}
}

func TestNotAfterVencidoIgnorado(t *testing.T) {
	raiz, vivo, vencido := novoPar(t), novoPar(t), novoPar(t)
	rel := &relogio{t: time.Now().UTC()}
	ag := novoAgenteTrust(t, raiz, rel)

	fim := rel.agora().Add(time.Hour)
	jaVencido := rel.agora().Add(-time.Minute)
	raw, sig := listaAssinada(t, raiz, 1, rel.agora(),
		entrada(vivo, sign.RoleOperator, &fim),
		entrada(vencido, sign.RoleOperator, &jaVencido))
	if err := ag.IngerirListaSigners(raw, sig); err != nil {
		t.Fatalf("lista com not_after recusada: %v", err)
	}
	if err := aceitaConcessao(ag, concessao(t, vivo, "ag-1", rel.agora())); err != nil {
		t.Fatalf("operador dentro da validade recusado: %v", err)
	}
	if err := aceitaConcessao(ag, concessao(t, vencido, "ag-1", rel.agora())); !errors.Is(err, sign.ErrSignature) {
		t.Fatalf("operador com not_after vencido aceito: %v", err)
	}
	// o tempo passa além do not_after do operador vivo, sem nova lista
	rel.avanca(2 * time.Hour)
	if err := aceitaConcessao(ag, concessao(t, vivo, "ag-1", rel.agora())); !errors.Is(err, sign.ErrSignature) {
		t.Fatalf("operador vencido com o tempo ainda aceito: %v", err)
	}
}

func TestSemListaSoRaiz(t *testing.T) {
	raiz, op := novoPar(t), novoPar(t)
	rel := &relogio{t: time.Now().UTC()}
	ag := novoAgenteTrust(t, raiz, rel)

	if err := aceitaConcessao(ag, concessao(t, raiz, "ag-1", rel.agora())); err != nil {
		t.Fatalf("fluxo de uma chave (raiz) quebrou: %v", err)
	}
	if err := aceitaConcessao(ag, concessao(t, op, "ag-1", rel.agora())); !errors.Is(err, sign.ErrSignature) {
		t.Fatalf("sem lista, operador aceito: %v", err)
	}
	// job da raiz passa pelo handleJob inteiro (verificação, replay, catálogo, execução)
	ag.exec = func(_ context.Context, _ catalog.Action, _ map[string]string) (string, int, bool, error) {
		return "ok", 0, false, nil
	}
	seen, err := openSeen(filepath.Join(ag.Dir, fileSeen))
	if err != nil {
		t.Fatal(err)
	}
	ag.seen = seen
	sjRaiz, err := sign.SignJob(raiz.priv, jobDeTeste(rel.agora()))
	if err != nil {
		t.Fatal(err)
	}
	if res := ag.handleJob(context.Background(), sjRaiz); res.Status != "ok" {
		t.Fatalf("job da raiz sem lista: %+v", res)
	}
}

func TestJobDeOperadorPeloHandleJob(t *testing.T) {
	raiz, op := novoPar(t), novoPar(t)
	rel := &relogio{t: time.Now().UTC()}
	ag := novoAgenteTrust(t, raiz, rel)
	ag.exec = func(_ context.Context, _ catalog.Action, _ map[string]string) (string, int, bool, error) {
		return "ok", 0, false, nil
	}
	seen, err := openSeen(filepath.Join(ag.Dir, fileSeen))
	if err != nil {
		t.Fatal(err)
	}
	ag.seen = seen
	sjOp, err := sign.SignJob(op.priv, jobDeTeste(rel.agora()))
	if err != nil {
		t.Fatal(err)
	}
	// antes da lista: descartado por assinatura (sem ID para reportar)
	if res := ag.handleJob(context.Background(), sjOp); res.JobID != "" {
		t.Fatalf("job de operador sem lista foi processado: %+v", res)
	}
	raw, sig := listaAssinada(t, raiz, 1, rel.agora(), entrada(op, sign.RoleOperator, nil))
	if err := ag.IngerirListaSigners(raw, sig); err != nil {
		t.Fatal(err)
	}
	sjOp2, err := sign.SignJob(op.priv, jobDeTeste(rel.agora()))
	if err != nil {
		t.Fatal(err)
	}
	if res := ag.handleJob(context.Background(), sjOp2); res.Status != "ok" {
		t.Fatalf("job do operador da lista: %+v", res)
	}
}

func TestIngestaoConcorrenteComVerificacao(t *testing.T) {
	raiz, op := novoPar(t), novoPar(t)
	rel := &relogio{t: time.Now().UTC()}
	ag := novoAgenteTrust(t, raiz, rel)
	raw, sig := listaAssinada(t, raiz, 1, rel.agora(), entrada(op, sign.RoleOperator, nil))
	sg := concessao(t, op, "ag-1", rel.agora())

	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < 50; j++ {
				_ = aceitaConcessao(ag, sg) // lê o trust-set enquanto outro chama ingerir
			}
		}()
	}
	if err := ag.IngerirListaSigners(raw, sig); err != nil {
		t.Fatal(err)
	}
	wg.Wait()
	if err := aceitaConcessao(ag, sg); err != nil {
		t.Fatalf("após ingestão concorrente: %v", err)
	}
}

func TestTrustCorrompidoFalhaFechado(t *testing.T) {
	raiz := novoPar(t)
	rel := &relogio{t: time.Now().UTC()}
	dir := t.TempDir()
	path := filepath.Join(dir, fileTrust)
	if err := writeFileAtomic(path, []byte("{não é json")); err != nil {
		t.Fatal(err)
	}
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	if _, err := openTrust(path, raiz.pub, rel.agora(), log); err == nil {
		t.Fatal("trust.json corrompido não falhou fechado")
	}
}
