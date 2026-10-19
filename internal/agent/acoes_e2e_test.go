package agent

// Aceite do T5c, ponta a ponta no mesmo processo: o operador assina (aqui, no
// teste, como o navegador faria), POST /api/acoes enfileira SEM re-assinar, o
// servidor entrega no check-in e o AGENTE real aceita ou recusa conforme a
// lista de signers publicada (trust-set ancorado na raiz).

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/eduardohenriquemoretti0-ops/fm-rmm/internal/console"
	"github.com/eduardohenriquemoretti0-ops/fm-rmm/internal/pki"
	"github.com/eduardohenriquemoretti0-ops/fm-rmm/internal/proto"
	"github.com/eduardohenriquemoretti0-ops/fm-rmm/internal/server"
	"github.com/eduardohenriquemoretti0-ops/fm-rmm/internal/sign"
)

const relayAcoes = "wss://relay.exemplo:8443/r"

type opLab struct {
	t     *testing.T
	l     *lab
	c     *console.Console
	cert  *x509.Certificate
	priv  ed25519.PrivateKey
	pub   ed25519.PublicKey
	tok   string
	csrf  string
	agent string
}

func novoOpLab(t *testing.T, l *lab, agentID string) *opLab {
	t.Helper()
	pool := x509.NewCertPool()
	pool.AddCert(l.srv.CA)
	sm := console.NewSessionManager(15*time.Minute, 10*time.Minute)
	aut, err := console.NovoAutenticador(console.ConfigWebAuthn{RPID: "localhost", RPOrigins: []string{"https://localhost"}}, l.st, sm)
	if err != nil {
		t.Fatal(err)
	}
	c, err := console.NovoConsole(sm, aut, l.st, pool, time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	c.ConfigurarRelay(relayAcoes)

	_, csrPEM, err := pki.NewAgentKeyAndCSR("op-joao")
	if err != nil {
		t.Fatal(err)
	}
	csr, err := pki.ParseCSR(csrPEM)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := pki.SignOperator(l.srv.CA, l.srv.CAKey, csr, "op-joao")
	if err != nil {
		t.Fatal(err)
	}
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	if err := l.st.AddTech("joao"); err != nil {
		t.Fatal(err)
	}
	if err := l.st.GrantGroup("joao", "*"); err != nil {
		t.Fatal(err)
	}
	if err := l.st.CreateOperator(server.Operator{ID: "op-joao", Nome: "João", TechName: "joao", CertThumbprint: console.CertThumbprint(cert)}); err != nil {
		t.Fatal(err)
	}
	if err := l.st.SetOperatorStatus("op-joao", "ativo"); err != nil {
		t.Fatal(err)
	}
	if err := l.st.SetOperatorSigningPub("op-joao", sign.EncodePub(pub)); err != nil {
		t.Fatal(err)
	}
	tok, csrf, err := sm.New("op-joao", console.CertThumbprint(cert))
	if err != nil {
		t.Fatal(err)
	}
	if err := sm.MarcarStepUp(tok, console.CertThumbprint(cert), time.Minute); err != nil {
		t.Fatal(err)
	}
	return &opLab{t: t, l: l, c: c, cert: cert, priv: priv, pub: pub, tok: tok, csrf: csrf, agent: agentID}
}

func (o *opLab) post(corpo any) *httptest.ResponseRecorder {
	o.t.Helper()
	b, _ := json.Marshal(corpo)
	r := httptest.NewRequest(http.MethodPost, "/api/acoes", bytes.NewReader(b))
	r.TLS = &tls.ConnectionState{PeerCertificates: []*x509.Certificate{o.cert}}
	r.AddCookie(console.SessionCookie(console.NomeCookieSessao, o.tok, time.Minute))
	r.Header.Set(console.CabecalhoCSRF, o.csrf)
	rec := httptest.NewRecorder()
	o.c.Roteador().ServeHTTP(rec, r)
	return rec
}

func (o *opLab) enviaJob(id string) {
	o.t.Helper()
	now := time.Now().UTC().Truncate(time.Second)
	sj, err := sign.SignJob(o.priv, proto.JobPayload{V: proto.Version, JobID: id, AgentID: o.agent, Action: "info",
		IssuedAt: now, ExpiresAt: now.Add(time.Hour), Issuer: "op-joao"})
	if err != nil {
		o.t.Fatal(err)
	}
	rec := o.post(map[string]any{"tipo": "job", "payload": []byte(sj.Payload), "sig": sj.Sig, "key_id": sj.KeyID})
	if rec.Code != http.StatusAccepted {
		o.t.Fatalf("POST /api/acoes job: %d %s", rec.Code, rec.Body.String())
	}
}

func (o *opLab) enviaGrant(id string) {
	o.t.Helper()
	now := time.Now().UTC().Truncate(time.Second)
	sg, err := sign.SignGrant(o.priv, proto.RemoteGrant{V: proto.Version, SessionID: id, AgentID: o.agent, Technician: "joao",
		Mode: proto.ModeView, Engine: proto.EngineScreenshot, RelayURL: relayAcoes, RelayToken: strings.Repeat("t", 40),
		IssuedAt: now, ExpiresAt: now.Add(10 * time.Minute), Issuer: "op-joao"})
	if err != nil {
		o.t.Fatal(err)
	}
	rec := o.post(map[string]any{"tipo": "grant", "payload": sg.Payload, "sig": sg.Sig, "key_id": sg.KeyID})
	if rec.Code != http.StatusAccepted {
		o.t.Fatalf("POST /api/acoes grant: %d %s", rec.Code, rec.Body.String())
	}
}

func TestAcoesDoOperadorAteOAgente(t *testing.T) {
	l := newLab(t)
	ctx := context.Background()
	ag := l.newAgent(l.token(1))
	l.enrolled(ag)
	agentID := ag.state.AgentID
	o := novoOpLab(t, l, agentID)
	raiz := l.admin
	raizPub := raiz.Public().(ed25519.PublicKey)

	// 1. operador NÃO publicado: o servidor enfileira e entrega (operador apto),
	// mas o AGENTE recusa (a chave não está no trust-set) e nada executa.
	o.enviaJob("job-op-antes0001")
	if err := ag.CheckinOnce(ctx); err != nil {
		t.Fatal(err)
	}
	if len(l.ran) != 0 {
		t.Fatalf("agente executou ação de operador NÃO publicado: %v", l.ran)
	}
	jb, err := l.st.Job("job-op-antes0001")
	if err != nil {
		t.Fatal(err)
	}
	if jb.Status == "queued" {
		t.Fatal("servidor barrou o job do operador apto (pendência do T5b): deveria entregar")
	}
	t.Logf("antes da lista: job entregue pelo servidor (status=%s); agente não executou nada", jb.Status)

	// grant de operador não publicado: verificação do agente falha
	o.enviaGrant("ses-op-antes0002")
	gs, err := l.st.TakeSessions(agentID)
	if err != nil || len(gs) == 0 {
		t.Fatalf("TakeSessions: %v %d", err, len(gs))
	}
	for _, sg := range gs {
		if _, err := sign.VerifyGrantAny(ag.confianca(), sg, agentID, ag.now()); err == nil {
			t.Fatal("agente aceitou grant de operador não publicado")
		}
	}

	// 2. admin publica a lista com o operador (offline, com a raiz)
	exp, err := l.st.ExportarLista()
	if err != nil {
		t.Fatal(err)
	}
	raw, sig, _, err := server.ConstruirLista(raiz, exp.VersaoAtual, exp.Operadores, ag.now())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := server.PublicarLista(l.st, raizPub, raw, sig, "teste"); err != nil {
		t.Fatal(err)
	}

	// 3. job do operador publicado: o agente ACEITA e executa
	o.enviaJob("job-op-depois001")
	if err := ag.CheckinOnce(ctx); err != nil {
		t.Fatal(err)
	}
	if len(l.ran) != 1 || l.ran[0] != "info" {
		t.Fatalf("agente não executou o job do operador publicado: ran=%v", l.ran)
	}
	jb, _ = l.st.Job("job-op-depois001")
	if jb.Status != "done" {
		t.Fatalf("job do operador publicado: status=%s result=%s", jb.Status, jb.Result)
	}

	// 4. grant do operador publicado: o agente ACEITA (VerifyGrantAny no trust-set)
	o.enviaGrant("ses-op-depois001")
	gs, err = l.st.TakeSessions(agentID)
	if err != nil || len(gs) != 1 {
		t.Fatalf("TakeSessions: %v %d", err, len(gs))
	}
	g, err := sign.VerifyGrantAny(ag.confianca(), gs[0], agentID, ag.now())
	if err != nil {
		t.Fatalf("agente recusou grant de operador publicado: %v", err)
	}
	if g.SessionID != "ses-op-depois001" || g.Technician != "joao" || gs[0].KeyID != sign.KeyID(o.pub) {
		t.Fatalf("grant inesperado: %+v key=%s", g, gs[0].KeyID)
	}
}
