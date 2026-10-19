package agent

// Acesso remoto ponta a ponta: RBAC, concessão assinada, indicador de sessão
// obrigatório (fail-closed), relay e auditoria. Sem captura de tela real —
// usa indicador e mídia falsos para exercitar o caminho autorizado.

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/tls"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/eduardohenriquemoretti0-ops/fm-rmm/internal/proto"
	"github.com/eduardohenriquemoretti0-ops/fm-rmm/internal/server"
	"github.com/eduardohenriquemoretti0-ops/fm-rmm/internal/sign"
)

type fakeIndicator struct {
	mu          sync.Mutex
	shown       bool
	failForever bool
	lost        chan struct{} // se != nil, é devolvido como canal de perda
}

func (f *fakeIndicator) Show(_, _, _ string) (func(), <-chan struct{}, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.failForever {
		return nil, nil, io.ErrClosedPipe // simula endpoint sem sessão gráfica
	}
	f.shown = true
	lost := f.lost
	if lost == nil {
		lost = make(chan struct{}) // nunca fecha: indicador saudável
	}
	return func() {}, lost, nil
}

type fakeMedia struct {
	mu   sync.Mutex
	mode string
	got  string
}

func (m *fakeMedia) Serve(ctx context.Context, conn net.Conn, mode, _ string) error {
	m.mu.Lock()
	m.mode = mode
	m.mu.Unlock()
	_, _ = conn.Write([]byte("ola do agente"))
	buf := make([]byte, 64)
	n, _ := conn.Read(buf)
	m.mu.Lock()
	m.got = string(buf[:n])
	m.mu.Unlock()
	return nil
}

func (l *lab) startRelay(t *testing.T) *httptest.Server {
	t.Helper()
	rl := server.NewRelay(l.st, slog.New(slog.NewTextHandler(io.Discard, nil)))
	rs := httptest.NewUnstartedServer(rl.Handler())
	rs.TLS = l.ts.TLS.Clone()
	rs.StartTLS()
	t.Cleanup(rs.Close)
	return rs
}

// relayURL converte a URL https do httptest em algo que dialRelay entende.
func relayURL(rs *httptest.Server) string { return "wss://" + strings.TrimPrefix(rs.URL, "https://") }

func enableRemote(ag *Agent) (*fakeIndicator, *fakeMedia) {
	ind, med := &fakeIndicator{}, &fakeMedia{}
	ag.EnableRemote(ind, med)
	return ind, med
}

// consoleConnect simula o console conectando no relay com o token da sessão.
func consoleConnect(t *testing.T, rs *httptest.Server, sessionID, token string) {
	t.Helper()
	conf := rs.Client().Transport.(*http.Transport).TLSClientConfig.Clone()
	host := strings.TrimPrefix(rs.URL, "https://")
	c, err := tls.Dial("tcp", host, conf)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	req := "POST /relay HTTP/1.1\r\nHost: x\r\nUpgrade: fm-relay\r\nConnection: Upgrade\r\nX-Session-ID: " + sessionID + "\r\nX-Relay-Token: " + token + "\r\n\r\n"
	if _, err := c.Write([]byte(req)); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, 256)
	n, _ := c.Read(buf) // 101 + "ola do agente"
	if !strings.Contains(string(buf[:n]), "101") {
		t.Fatalf("relay não fez upgrade: %q", buf[:n])
	}
	_, _ = c.Write([]byte("ola do console"))
	time.Sleep(50 * time.Millisecond)
}

func TestSessaoRemotaFluxo(t *testing.T) {
	l := newLab(t)
	rs := l.startRelay(t)
	ctx := context.Background()
	ag := l.newAgent(l.token(1))
	l.enrolled(ag)
	ind, med := enableRemote(ag)

	// RBAC: técnico sem permissão é barrado já na criação
	if _, _, err := server.CreateSession(l.st, l.admin, l.signers, ag.state.AgentID, "tec-sem-acesso", proto.ModeView, proto.EngineScreenshot, relayURL(rs), 10*time.Minute, "teste"); err == nil {
		t.Fatal("sessão criada para técnico sem permissão")
	}
	// dá acesso ao grupo do agente (default)
	if err := l.st.GrantGroup("joao", "default"); err != nil {
		t.Fatal(err)
	}
	g, token, err := server.CreateSession(l.st, l.admin, l.signers, ag.state.AgentID, "joao", proto.ModeView, proto.EngineScreenshot, relayURL(rs), 10*time.Minute, "teste")
	if err != nil {
		t.Fatal(err)
	}

	// console conecta no relay em paralelo; o agente pega a concessão no check-in
	done := make(chan struct{})
	go func() { consoleConnect(t, rs, g.SessionID, token); close(done) }()
	time.Sleep(50 * time.Millisecond)
	if err := ag.CheckinOnce(ctx); err != nil {
		t.Fatal(err)
	}
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("sessão não completou pelo relay")
	}

	// a sessão roda em goroutine no agente; espera ela completar
	deadlineMedia := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadlineMedia) {
		med.mu.Lock()
		got := med.got
		med.mu.Unlock()
		if got != "" {
			break
		}
		time.Sleep(50 * time.Millisecond)
	}
	ind.mu.Lock()
	shown := ind.shown
	ind.mu.Unlock()
	if !shown {
		t.Fatal("indicador de sessão NÃO foi aceso")
	}
	med.mu.Lock()
	got := med.got
	med.mu.Unlock()
	if got != "ola do console" {
		t.Fatalf("mídia não trafegou pelo relay: recebeu %q", got)
	}

	// auditoria registra autorização, indicador e início
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		entries, _ := l.st.AuditEntries()
		var ev []string
		for _, e := range entries {
			ev = append(ev, e.Event)
		}
		j := strings.Join(ev, " ")
		if strings.Contains(j, "sessao.autorizada") && strings.Contains(j, "sessao.indicador_on") && strings.Contains(j, "sessao.iniciada") {
			return
		}
		time.Sleep(50 * time.Millisecond)
	}
	t.Fatal("auditoria da sessão incompleta")
}

// Sem indicador visível (fail-closed), a sessão é recusada e nenhuma mídia abre.
func TestSessaoSemIndicadorRecusa(t *testing.T) {
	l := newLab(t)
	ctx := context.Background()
	ag := l.newAgent(l.token(1))
	l.enrolled(ag)
	ind, med := enableRemote(ag)
	ind.failForever = true
	_ = l.st.GrantGroup("joao", "*")
	g, _, err := server.CreateSession(l.st, l.admin, l.signers, ag.state.AgentID, "joao", proto.ModeView, proto.EngineScreenshot, "wss://x", 10*time.Minute, "teste")
	if err != nil {
		t.Fatal(err)
	}
	if err := ag.CheckinOnce(ctx); err != nil {
		t.Fatal(err)
	}
	// dá tempo da goroutine reportar
	time.Sleep(200 * time.Millisecond)
	med.mu.Lock()
	opened := med.mode != ""
	med.mu.Unlock()
	if opened {
		t.Fatal("mídia abriu mesmo sem indicador")
	}
	entries, _ := l.st.AuditEntries()
	recusada := false
	for _, e := range entries {
		if e.Event == "sessao.recusada" {
			recusada = true
		}
	}
	if !recusada {
		t.Fatal("recusa por falta de indicador não foi auditada")
	}
	_ = g
}

// blockingMedia fica na sessão até o contexto cair; sinaliza quando começou e
// quando terminou, para o teste observar o teardown.
type blockingMedia struct{ started, ended chan struct{} }

func (m *blockingMedia) Serve(ctx context.Context, _ net.Conn, _, _ string) error {
	close(m.started)
	<-ctx.Done()
	close(m.ended)
	return ctx.Err()
}

// Se o indicador cair no meio da sessão, o agente encerra a mídia na hora
// (1.3: vida da sessão amarrada à vida do indicador, fail-closed).
func TestSessaoIndicadorCaiEncerra(t *testing.T) {
	l := newLab(t)
	rs := l.startRelay(t)
	ctx := context.Background()
	ag := l.newAgent(l.token(1))
	l.enrolled(ag)

	lost := make(chan struct{})
	ind := &fakeIndicator{lost: lost}
	med := &blockingMedia{started: make(chan struct{}), ended: make(chan struct{})}
	ag.EnableRemote(ind, med)
	_ = l.st.GrantGroup("joao", "*")

	g, token, err := server.CreateSession(l.st, l.admin, l.signers, ag.state.AgentID, "joao", proto.ModeView, proto.EngineScreenshot, relayURL(rs), 10*time.Minute, "teste")
	if err != nil {
		t.Fatal(err)
	}
	go func() { consoleConnect(t, rs, g.SessionID, token) }()
	time.Sleep(50 * time.Millisecond)
	if err := ag.CheckinOnce(ctx); err != nil {
		t.Fatal(err)
	}

	select {
	case <-med.started:
	case <-time.After(3 * time.Second):
		t.Fatal("mídia não iniciou")
	}
	close(lost) // indicador caiu
	select {
	case <-med.ended:
	case <-time.After(2 * time.Second):
		t.Fatal("mídia não encerrou após o indicador cair")
	}
}

// Concessão forjada (assinada por chave que não é do admin) é recusada: o
// servidor nem entrega, e mesmo injetada na fila o agente não abre a sessão.
func TestConcessaoForjada(t *testing.T) {
	l := newLab(t)
	ctx := context.Background()
	ag := l.newAgent(l.token(1))
	l.enrolled(ag)
	ind, med := enableRemote(ag)
	_, evil, _ := ed25519.GenerateKey(rand.Reader)
	now := time.Now().UTC()
	g := proto.RemoteGrant{V: proto.Version, SessionID: "ses-forjada", AgentID: ag.state.AgentID, Technician: "invasor", Mode: proto.ModeView, RelayURL: "wss://x", RelayToken: "t", IssuedAt: now, ExpiresAt: now.Add(time.Minute), Issuer: "invasor"}
	sg, _ := sign.SignGrant(evil, g)
	if err := l.st.EnqueueSignedGrantForTest(ag.state.AgentID, g.SessionID, sg, "t", time.Minute); err != nil {
		t.Fatal(err)
	}
	_ = ag.CheckinOnce(ctx)
	time.Sleep(150 * time.Millisecond)
	ind.mu.Lock()
	shown := ind.shown
	ind.mu.Unlock()
	med.mu.Lock()
	opened := med.mode != ""
	med.mu.Unlock()
	if shown || opened {
		t.Fatal("concessão forjada acendeu indicador ou abriu mídia")
	}
}
