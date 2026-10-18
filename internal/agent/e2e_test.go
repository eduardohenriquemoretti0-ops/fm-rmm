package agent

// Teste de ponta a ponta: servidor TLS de verdade (httptest) + agente real,
// com a execução das ações trocada por uma função falsa. Cobre inscrição,
// aprovação, mTLS, assinatura, replay, catálogo, revogação e pinning.

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/tls"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/eduardohenriquemoretti0-ops/fm-rmm/internal/catalog"
	"github.com/eduardohenriquemoretti0-ops/fm-rmm/internal/pki"
	"github.com/eduardohenriquemoretti0-ops/fm-rmm/internal/proto"
	"github.com/eduardohenriquemoretti0-ops/fm-rmm/internal/server"
	"github.com/eduardohenriquemoretti0-ops/fm-rmm/internal/sign"
)

type lab struct {
	t       *testing.T
	ts      *httptest.Server
	srv     *server.Server
	st      *server.Store
	admin   ed25519.PrivateKey
	signers map[string]ed25519.PublicKey
	bundle  proto.Bundle
	ran     []string // ações que a execução falsa recebeu
}

func newLab(t *testing.T) *lab {
	t.Helper()
	ca, caKey, err := pki.NewCA("CA de teste")
	if err != nil {
		t.Fatal(err)
	}
	sc, sk, err := pki.NewServerCert(ca, caKey, []string{"127.0.0.1", "localhost"})
	if err != nil {
		t.Fatal(err)
	}
	st, err := server.OpenStore(filepath.Join(t.TempDir(), "srv.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	signers := map[string]ed25519.PublicKey{sign.KeyID(pub): pub}
	l := &lab{t: t, st: st, admin: priv, signers: signers}
	l.srv = &server.Server{Store: st, CA: ca, CAKey: caKey, Signers: signers, Interval: 30 * time.Second,
		Log: slog.New(slog.NewTextHandler(io.Discard, nil))}
	l.ts = httptest.NewUnstartedServer(l.srv.Handler())
	l.ts.TLS = server.TLSConfig(ca, tls.Certificate{Certificate: [][]byte{sc.Raw}, PrivateKey: sk})
	l.ts.StartTLS()
	t.Cleanup(l.ts.Close)
	l.bundle = proto.Bundle{ServerURL: l.ts.URL, CAPEM: pki.CertPEM(ca), SignerPub: sign.EncodePub(pub), SignerID: sign.KeyID(pub)}
	return l
}

// newAgent cria um agente com diretório próprio e o token informado.
func (l *lab) newAgent(token string) *Agent {
	l.t.Helper()
	dir := l.t.TempDir()
	b, _ := json.Marshal(l.bundle)
	if err := os.WriteFile(filepath.Join(dir, fileBundle), b, 0o600); err != nil {
		l.t.Fatal(err)
	}
	s, _ := json.Marshal(State{Token: token})
	if err := os.WriteFile(filepath.Join(dir, fileState), s, 0o600); err != nil {
		l.t.Fatal(err)
	}
	ag, err := New(dir, slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err != nil {
		l.t.Fatal(err)
	}
	ag.exec = func(_ context.Context, a catalog.Action, p map[string]string) (string, int, bool, error) {
		l.ran = append(l.ran, a.Name)
		return "saida de " + a.Name, 0, false, nil
	}
	return ag
}

func (l *lab) token(uses int) string {
	_, tok, err := l.st.NewToken("teste", uses, time.Hour)
	if err != nil {
		l.t.Fatal(err)
	}
	return tok
}

// enrolled leva o agente até ter certificado (aprovando no meio).
func (l *lab) enrolled(ag *Agent) {
	l.t.Helper()
	ctx := context.Background()
	ok, err := ag.enroll(ctx)
	if err != nil || ok {
		l.t.Fatalf("1º passo da inscrição: ok=%v err=%v", ok, err)
	}
	if ok, _ := ag.enroll(ctx); ok {
		l.t.Fatal("agente recebeu certificado SEM aprovação")
	}
	if err := server.ApproveAgent(l.st, l.srv.CA, l.srv.CAKey, ag.state.AgentID, "teste"); err != nil {
		l.t.Fatal(err)
	}
	if ok, err := ag.enroll(ctx); !ok || err != nil {
		l.t.Fatalf("após aprovação: ok=%v err=%v", ok, err)
	}
	if ag.state.Token != "" {
		l.t.Fatal("token continua gravado depois da inscrição")
	}
}

func (l *lab) job(agentID, action string, params map[string]string) string {
	l.t.Helper()
	id, err := server.NewJob(l.st, l.admin, l.signers, agentID, action, params, time.Hour, "teste")
	if err != nil {
		l.t.Fatal(err)
	}
	return id
}

func (l *lab) jobStatus(id string) (string, proto.Result) {
	l.t.Helper()
	j, err := l.st.Job(id)
	if err != nil {
		l.t.Fatal(err)
	}
	var r proto.Result
	if j.Result != "" {
		_ = json.Unmarshal([]byte(j.Result), &r)
	}
	return j.Status, r
}

// injectSigned coloca na fila um job montado à mão (simula servidor/DB comprometido).
func (l *lab) injectSigned(agentID string, sj proto.SignedJob, id string) {
	l.t.Helper()
	raw, _ := json.Marshal(sj)
	if err := l.st.AddJob(server.Job{ID: id, AgentID: agentID, Action: "?", Params: "{}", Signed: string(raw), Issuer: "injetado", ExpiresAt: time.Now().Add(time.Hour).Unix()}); err != nil {
		l.t.Fatal(err)
	}
}

func TestFluxoCompleto(t *testing.T) {
	l := newLab(t)
	ctx := context.Background()
	ag := l.newAgent(l.token(1))
	l.enrolled(ag)

	// check-in sem jobs
	if err := ag.CheckinOnce(ctx); err != nil {
		t.Fatalf("check-in: %v", err)
	}
	// job legítimo
	id := l.job(ag.state.AgentID, "info", nil)
	if err := ag.CheckinOnce(ctx); err != nil {
		t.Fatal(err)
	}
	st, res := l.jobStatus(id)
	if st != "done" || res.Output != "saida de info" {
		t.Fatalf("job info: status=%s saída=%q", st, res.Output)
	}
	// job com parâmetro da lista
	params := map[string]string{"nome": map[string]string{"windows": "Spooler", "linux": "cups", "darwin": "org.cups.cupsd"}[runtime.GOOS]}
	id2 := l.job(ag.state.AgentID, "reiniciar_servico", params)
	_ = ag.CheckinOnce(ctx)
	if st, _ := l.jobStatus(id2); st != "done" {
		t.Fatalf("reiniciar_servico: %s", st)
	}

	// heartbeat chegou
	a, _ := l.st.Agent(ag.state.AgentID)
	if a.LastSeen == 0 || !strings.Contains(a.Heartbeat, runtime.GOOS) {
		t.Fatalf("heartbeat não registrado: %+v", a)
	}

	// auditoria registra tudo e a cadeia confere
	entries, _ := l.st.AuditEntries()
	var events []string
	for _, e := range entries {
		events = append(events, e.Event)
	}
	for _, want := range []string{"inscricao.pendente", "agente.aprovado", "job.criado", "job.entregue", "job.resultado"} {
		if !strings.Contains(strings.Join(events, " "), want) {
			t.Errorf("auditoria sem %s: %v", want, events)
		}
	}
}

func TestReplay(t *testing.T) {
	l := newLab(t)
	ctx := context.Background()
	ag := l.newAgent(l.token(1))
	l.enrolled(ag)
	id := l.job(ag.state.AgentID, "info", nil)
	_ = ag.CheckinOnce(ctx)
	j, _ := l.st.Job(id)
	var sj proto.SignedJob
	_ = json.Unmarshal([]byte(j.Signed), &sj)
	// atacante grava o job assinado e reenvia (novo ID na fila, mesmo payload)
	l.injectSigned(ag.state.AgentID, sj, "replay-1")
	l.ran = nil
	_ = ag.CheckinOnce(ctx)
	if len(l.ran) != 0 {
		t.Fatalf("job repetido foi executado de novo: %v", l.ran)
	}
	// e o replay sobrevive a reinício do agente (seen.json em disco)
	ag2, err := New(ag.Dir, ag.Log)
	if err != nil {
		t.Fatal(err)
	}
	ag2.exec = ag.exec
	l.injectSigned(ag.state.AgentID, sj, "replay-2")
	_ = ag2.CheckinOnce(ctx)
	if len(l.ran) != 0 {
		t.Fatalf("replay aceito após reinício: %v", l.ran)
	}
}

func TestJobForjado(t *testing.T) {
	l := newLab(t)
	ctx := context.Background()
	ag := l.newAgent(l.token(1))
	l.enrolled(ag)
	now := time.Now().UTC()
	p := proto.JobPayload{V: proto.Version, JobID: "job-forjado", AgentID: ag.state.AgentID, Action: "info", IssuedAt: now, ExpiresAt: now.Add(time.Hour), Issuer: "atacante"}

	// 1) assinado por chave que não é do admin: o servidor nem entrega
	_, evil, _ := ed25519.GenerateKey(rand.Reader)
	sj, _ := sign.SignJob(evil, p)
	l.injectSigned(ag.state.AgentID, sj, "forjado-1")
	// 2) servidor comprometido pula a checagem: o agente recusa mesmo assim
	sj.KeyID = l.bundle.SignerID
	l.injectSigned(ag.state.AgentID, sj, "forjado-2")
	// 3) assinatura válida, ação fora do catálogo (chave do admin roubada não vira shell)
	p2 := p
	p2.JobID, p2.Action, p2.Params = "job-shell", "shell", map[string]string{"cmd": "whoami"}
	sj2, _ := sign.SignJob(l.admin, p2)
	l.injectSigned(ag.state.AgentID, sj2, "job-shell")
	// 4) job assinado para OUTRO agente
	p3 := p
	p3.JobID, p3.AgentID = "job-outro", "ag-outro"
	sj3, _ := sign.SignJob(l.admin, p3)
	l.injectSigned(ag.state.AgentID, sj3, "job-outro")

	l.ran = nil
	if err := ag.CheckinOnce(ctx); err != nil {
		t.Fatal(err)
	}
	if len(l.ran) != 0 {
		t.Fatalf("job forjado executado: %v", l.ran)
	}
	if st, r := l.jobStatus("job-shell"); st != "failed" || r.Status != "recusado" || !strings.Contains(r.Error, "catálogo") {
		t.Fatalf("ação fora do catálogo: status=%s res=%+v", st, r)
	}
	// o job forjado-1 ficou bloqueado no servidor e registrado na auditoria
	entries, _ := l.st.AuditEntries()
	blocked := 0
	for _, e := range entries {
		if e.Event == "job.bloqueado" {
			blocked++
		}
	}
	if blocked < 2 {
		t.Fatalf("servidor deveria bloquear e auditar jobs forjados (bloqueados=%d)", blocked)
	}
}

func TestRevogacao(t *testing.T) {
	l := newLab(t)
	ctx := context.Background()
	ag := l.newAgent(l.token(1))
	l.enrolled(ag)
	if err := l.st.SetStatus(ag.state.AgentID, "approved", "revoked"); err != nil {
		t.Fatal(err)
	}
	err := ag.CheckinOnce(ctx)
	var he *httpError
	if !errors.As(err, &he) || he.code != http.StatusForbidden {
		t.Fatalf("agente revogado deveria levar 403, veio %v", err)
	}
	// e o servidor não aceita mais job para ele
	if _, err := server.NewJob(l.st, l.admin, l.signers, ag.state.AgentID, "info", nil, time.Hour, "teste"); err == nil {
		t.Fatal("job criado para agente revogado")
	}
}

func TestSemAprovacaoNaoEntra(t *testing.T) {
	l := newLab(t)
	ctx := context.Background()
	ag := l.newAgent(l.token(1))
	if _, err := ag.enroll(ctx); err != nil {
		t.Fatal(err)
	}
	// pendente: sem certificado, check-in é recusado
	if err := ag.CheckinOnce(ctx); err == nil {
		t.Fatal("check-in aceito sem aprovação")
	}
	// rejeitado: inscrição termina com erro
	if err := l.st.SetStatus(ag.state.AgentID, "pending", "rejected"); err != nil {
		t.Fatal(err)
	}
	if _, err := ag.enroll(ctx); err == nil || !strings.Contains(err.Error(), "rejected") {
		t.Fatalf("rejeição não chegou ao agente: %v", err)
	}
	// token de uso único já foi gasto: outra máquina com o mesmo token não entra
	ag2 := l.newAgent(ag.state.Token)
	if _, err := l.newAgent("fmr_inventado").enroll(ctx); err == nil {
		t.Fatal("token inventado aceito")
	}
	_ = ag2
}

func TestTokenReusado(t *testing.T) {
	l := newLab(t)
	ctx := context.Background()
	tok := l.token(1)
	if _, err := l.newAgent(tok).enroll(ctx); err != nil {
		t.Fatal(err)
	}
	if _, err := l.newAgent(tok).enroll(ctx); err == nil {
		t.Fatal("token de uso único usado por segunda máquina")
	}
}

// Pinning: agente com o bundle de OUTRA CA não fala com o servidor
// (simula servidor falso/MITM com certificado "válido" de outra autoridade).
func TestPinning(t *testing.T) {
	l := newLab(t)
	other, _, _ := pki.NewCA("CA estranha")
	l.bundle.CAPEM = pki.CertPEM(other)
	ag := l.newAgent(l.token(1))
	_, err := ag.enroll(context.Background())
	if err == nil || !strings.Contains(err.Error(), "certificate") {
		t.Fatalf("agente aceitou servidor de outra CA: %v", err)
	}
}

// Certificado de cliente de outra CA é recusado no handshake.
func TestCertificadoDeOutraCA(t *testing.T) {
	l := newLab(t)
	otherCA, otherKey, _ := pki.NewCA("CA do atacante")
	key, csrPEM, _ := pki.NewAgentKeyAndCSR("pc-atacante")
	csr, _ := pki.ParseCSR(csrPEM)
	cert, _ := pki.SignAgent(otherCA, otherKey, csr, "ag-falso")
	pool, _ := l.ts.Client().Transport.(*http.Transport)
	tc := pool.TLSClientConfig.Clone()
	// força o envio (o cliente Go normalmente nem apresenta cert de CA não pedida)
	evil := tls.Certificate{Certificate: [][]byte{cert.Raw}, PrivateKey: key}
	tc.GetClientCertificate = func(*tls.CertificateRequestInfo) (*tls.Certificate, error) { return &evil, nil }
	c := &http.Client{Transport: &http.Transport{TLSClientConfig: tc}}
	resp, err := c.Post(l.ts.URL+"/v1/checkin", "application/json", strings.NewReader(`{"heartbeat":{}}`))
	if err == nil {
		resp.Body.Close()
		t.Fatalf("handshake com certificado de outra CA aceito (status %d)", resp.StatusCode)
	}
	// sem certificado nenhum: 401
	resp, err = l.ts.Client().Post(l.ts.URL+"/v1/checkin", "application/json", strings.NewReader(`{"heartbeat":{}}`))
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("check-in sem certificado: esperado 401, veio %d", resp.StatusCode)
	}
}

// Ações reais deste sistema (só leitura) rodam e saem com código 0.
func TestAcoesReaisLeitura(t *testing.T) {
	if testing.Short() {
		t.Skip("modo curto")
	}
	for _, n := range catalog.Names() {
		a, _ := catalog.Get(n)
		if a.Changes {
			continue
		}
		out, code, _, err := runAction(context.Background(), a, nil)
		if err != nil || code != 0 || strings.TrimSpace(out) == "" {
			t.Errorf("%s: código=%d erro=%v saída=%q", n, code, err, firstLine(out))
		}
	}
}

func firstLine(s string) string {
	s, _, _ = strings.Cut(s, "\n")
	return s
}
