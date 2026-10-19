// Package server é o servidor do FM-RMM: inscrição com aprovação, check-in
// por mTLS, entrega de jobs assinados e recebimento de resultados.
package server

import (
	"crypto"
	"crypto/ed25519"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"sync"
	"time"

	"github.com/eduardohenriquemoretti0-ops/fm-rmm/internal/pki"
	"github.com/eduardohenriquemoretti0-ops/fm-rmm/internal/proto"
	"github.com/eduardohenriquemoretti0-ops/fm-rmm/internal/sign"
)

type Server struct {
	Store    *Store
	CA       *x509.Certificate
	CAKey    crypto.Signer
	Signers  map[string]ed25519.PublicKey // key_id -> chave pública do administrador
	Interval time.Duration
	Log      *slog.Logger
	limiter  *rateLimiter
}

const (
	maxBody       = 1 << 20
	maxResultBody = 2 << 20
)

// TLSConfig: certificado de cliente é opcional no handshake (a inscrição não
// tem certificado ainda), mas se vier PRECISA ser da nossa CA. Rotas de
// agente exigem certificado em requireAgent.
func TLSConfig(ca *x509.Certificate, serverCert tls.Certificate) *tls.Config {
	pool := x509.NewCertPool()
	pool.AddCert(ca)
	return &tls.Config{
		MinVersion:   tls.VersionTLS12,
		Certificates: []tls.Certificate{serverCert},
		ClientAuth:   tls.VerifyClientCertIfGiven,
		ClientCAs:    pool,
	}
}

func (s *Server) Handler() http.Handler {
	if s.limiter == nil {
		s.limiter = newRateLimiter(20, time.Minute)
	}
	mux := http.NewServeMux()
	mux.HandleFunc("POST /v1/enroll", s.limited(s.handleEnroll))
	mux.HandleFunc("POST /v1/enroll/status", s.limited(s.handleEnrollStatus))
	mux.HandleFunc("POST /v1/checkin", s.handleCheckin)
	mux.HandleFunc("POST /v1/result", s.handleResult)
	mux.HandleFunc("POST /v1/session/event", s.handleSessionEvent)
	mux.HandleFunc("GET /v1/health", func(w http.ResponseWriter, _ *http.Request) { w.Write([]byte("ok\n")) })
	return mux
}

// NewHTTPServer aplica os timeouts (sem eles um cliente lento prende conexões).
func NewHTTPServer(addr string, h http.Handler, tc *tls.Config) *http.Server {
	return &http.Server{
		Addr: addr, Handler: h, TLSConfig: tc,
		ReadHeaderTimeout: 10 * time.Second, ReadTimeout: 30 * time.Second,
		WriteTimeout: 60 * time.Second, IdleTimeout: 120 * time.Second,
		MaxHeaderBytes: 16 << 10,
	}
}

func clientIP(r *http.Request) string {
	h, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return h
}

func writeJSON(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(v)
}

func fail(w http.ResponseWriter, code int, msg string) {
	writeJSON(w, code, map[string]string{"erro": msg})
}

func readJSON(w http.ResponseWriter, r *http.Request, limit int64, v any) bool {
	dec := json.NewDecoder(http.MaxBytesReader(w, r.Body, limit))
	dec.DisallowUnknownFields()
	if err := dec.Decode(v); err != nil {
		fail(w, http.StatusBadRequest, "requisição inválida")
		return false
	}
	return true
}

func (s *Server) audit(event, actor string, data map[string]any) {
	if err := s.Store.Audit(event, actor, data); err != nil {
		s.Log.Error("falha ao gravar auditoria", "evento", event, "erro", err)
	}
}

// ---------------------------------------------------------------- inscrição

func (s *Server) handleEnroll(w http.ResponseWriter, r *http.Request) {
	var req proto.EnrollRequest
	if !readJSON(w, r, maxBody, &req) {
		return
	}
	if len(req.Hostname) == 0 || len(req.Hostname) > 255 || (req.OS != "windows" && req.OS != "linux" && req.OS != "darwin") {
		fail(w, http.StatusBadRequest, "hostname ou sistema inválido")
		return
	}
	if _, err := pki.ParseCSR(req.CSRPEM); err != nil {
		fail(w, http.StatusBadRequest, err.Error())
		return
	}
	id, poll, err := s.Store.Enroll(req.Token, req.Hostname, req.OS, req.CSRPEM, clientIP(r))
	if errors.Is(err, ErrToken) {
		s.audit("inscricao.recusada", "ip:"+clientIP(r), map[string]any{"hostname": req.Hostname, "motivo": "token inválido"})
		fail(w, http.StatusForbidden, err.Error())
		return
	}
	if err != nil {
		s.Log.Error("inscrição", "erro", err)
		fail(w, http.StatusInternalServerError, "erro interno")
		return
	}
	s.audit("inscricao.pendente", "ip:"+clientIP(r), map[string]any{"agente": id, "hostname": req.Hostname, "os": req.OS})
	writeJSON(w, http.StatusOK, proto.EnrollResponse{AgentID: id, PollSecret: poll})
}

func (s *Server) handleEnrollStatus(w http.ResponseWriter, r *http.Request) {
	var req proto.EnrollStatusRequest
	if !readJSON(w, r, maxBody, &req) {
		return
	}
	a, err := s.Store.CheckPoll(req.AgentID, req.PollSecret)
	if err != nil {
		fail(w, http.StatusForbidden, "inscrição desconhecida")
		return
	}
	resp := proto.EnrollStatusResponse{Status: a.Status}
	if a.Status == "approved" {
		resp.CertPEM = a.CertPEM
	}
	writeJSON(w, http.StatusOK, resp)
}

// ApproveAgent emite o certificado do agente (usado pela CLI do admin).
func ApproveAgent(st *Store, ca *x509.Certificate, caKey crypto.Signer, id, actor string) error {
	a, err := st.Agent(id)
	if err != nil {
		return err
	}
	if a.Status != "pending" {
		return fmt.Errorf("agente %s está %s, não pendente", id, a.Status)
	}
	csr, err := pki.ParseCSR(a.CSRPEM)
	if err != nil {
		return err
	}
	cert, err := pki.SignAgent(ca, caKey, csr, id)
	if err != nil {
		return err
	}
	if err := st.Approve(id, pki.CertPEM(cert), cert.SerialNumber.Text(16), cert.NotAfter.Unix()); err != nil {
		return err
	}
	return st.Audit("agente.aprovado", actor, map[string]any{"agente": id, "hostname": a.Hostname, "serial": cert.SerialNumber.Text(16)})
}

// ------------------------------------------------------------------ agentes

// requireAgent: certificado da nossa CA (já verificado no handshake), CN =
// agente aprovado e serial igual ao emitido (certificado antigo/revogado cai).
func (s *Server) requireAgent(w http.ResponseWriter, r *http.Request) (Agent, bool) {
	if r.TLS == nil || len(r.TLS.PeerCertificates) == 0 {
		fail(w, http.StatusUnauthorized, "certificado de cliente obrigatório")
		return Agent{}, false
	}
	c := r.TLS.PeerCertificates[0]
	a, err := s.Store.Agent(c.Subject.CommonName)
	if err != nil || a.Status != "approved" || !eqHash(a.CertSerial, c.SerialNumber.Text(16)) {
		status := "desconhecido"
		if err == nil {
			status = a.Status
		}
		s.audit("acesso.negado", "cert:"+c.Subject.CommonName, map[string]any{"status": status, "ip": clientIP(r)})
		fail(w, http.StatusForbidden, "agente não autorizado")
		return Agent{}, false
	}
	return a, true
}

func (s *Server) handleCheckin(w http.ResponseWriter, r *http.Request) {
	a, ok := s.requireAgent(w, r)
	if !ok {
		return
	}
	var req proto.CheckinRequest
	if !readJSON(w, r, maxBody, &req) {
		return
	}
	hb, _ := json.Marshal(req.Heartbeat)
	goos := a.OS
	if req.Heartbeat.OS == "windows" || req.Heartbeat.OS == "linux" || req.Heartbeat.OS == "darwin" {
		goos = req.Heartbeat.OS
	}
	if err := s.Store.Seen(a.ID, string(hb), goos); err != nil {
		s.Log.Error("check-in", "agente", a.ID, "erro", err)
	}
	jobs, err := s.Store.TakeQueued(r.Context(), a.ID)
	if err != nil {
		s.Log.Error("fila", "agente", a.ID, "erro", err)
		fail(w, http.StatusInternalServerError, "erro interno")
		return
	}
	resp := proto.CheckinResponse{Jobs: []proto.SignedJob{}, IntervalSec: int(s.Interval / time.Second)}
	if grants, err := s.Store.TakeSessions(a.ID); err != nil {
		s.Log.Error("sessões", "agente", a.ID, "erro", err)
	} else {
		for _, sg := range grants {
			pub, ok := s.Signers[sg.KeyID]
			if !ok {
				s.audit("sessao.bloqueada", "servidor", map[string]any{"motivo": "chave do emissor desconhecida"})
				continue
			}
			if g, err := sign.VerifyGrant(pub, sg, a.ID, time.Now()); err != nil {
				s.audit("sessao.bloqueada", "servidor", map[string]any{"sessao": g.SessionID, "motivo": err.Error()})
				continue
			}
			resp.Grants = append(resp.Grants, sg)
		}
	}
	// lista de signers publicada: o agente ingere (anti-downgrade) e amplia o trust-set
	if v, raw, sig, err := s.Store.listaAtual(); err != nil {
		s.Log.Error("lista de signers", "agente", a.ID, "erro", err)
	} else if v > 0 {
		resp.Lista = &proto.SignedSignerList{Raw: raw, Sig: sig}
	}
	for _, j := range jobs {
		var sj proto.SignedJob
		if err := json.Unmarshal([]byte(j.Signed), &sj); err != nil {
			s.Log.Error("job ilegível no banco", "job", j.ID)
			continue
		}
		// defesa em profundidade: o servidor também confere a assinatura
		pub, ok := s.Signers[sj.KeyID]
		if !ok {
			s.audit("job.bloqueado", "servidor", map[string]any{"job": j.ID, "motivo": "chave do emissor desconhecida"})
			continue
		}
		if _, err := sign.VerifyJob(pub, sj, a.ID, time.Now()); err != nil {
			s.audit("job.bloqueado", "servidor", map[string]any{"job": j.ID, "motivo": err.Error()})
			continue
		}
		resp.Jobs = append(resp.Jobs, sj)
		s.audit("job.entregue", "servidor", map[string]any{"job": j.ID, "agente": a.ID, "acao": j.Action})
	}
	writeJSON(w, http.StatusOK, resp)
}

func (s *Server) handleResult(w http.ResponseWriter, r *http.Request) {
	a, ok := s.requireAgent(w, r)
	if !ok {
		return
	}
	var res proto.Result
	if !readJSON(w, r, maxResultBody, &res) {
		return
	}
	if len(res.Output) > proto.MaxOutputSize {
		res.Output, res.Truncated = res.Output[:proto.MaxOutputSize], true
	}
	status := "done"
	if res.Status != "ok" {
		status = "failed"
	}
	raw, _ := json.Marshal(res)
	if err := s.Store.FinishJob(a.ID, res.JobID, status, string(raw)); err != nil {
		fail(w, http.StatusConflict, "job não está aguardando resultado deste agente")
		return
	}
	s.audit("job.resultado", "agente:"+a.ID, map[string]any{"job": res.JobID, "status": res.Status, "codigo_saida": res.ExitCode, "erro": res.Error})
	writeJSON(w, http.StatusOK, map[string]string{"ok": "1"})
}

func (s *Server) handleSessionEvent(w http.ResponseWriter, r *http.Request) {
	a, ok := s.requireAgent(w, r)
	if !ok {
		return
	}
	var ev proto.SessionEvent
	if !readJSON(w, r, maxBody, &ev) {
		return
	}
	if err := s.Store.MarkSession(a.ID, ev.SessionID, ev.Event); err != nil {
		s.Log.Error("evento de sessão", "sessao", ev.SessionID, "erro", err)
	}
	s.audit("sessao."+ev.Event, "agente:"+a.ID, map[string]any{"sessao": ev.SessionID, "detalhe": ev.Detail})
	writeJSON(w, http.StatusOK, map[string]string{"ok": "1"})
}

// ------------------------------------------------------------ limite de taxa

// rateLimiter simples por IP para as rotas sem certificado (inscrição).
type rateLimiter struct {
	mu     sync.Mutex
	max    int
	window time.Duration
	hits   map[string][]time.Time
}

func newRateLimiter(max int, window time.Duration) *rateLimiter {
	return &rateLimiter{max: max, window: window, hits: map[string][]time.Time{}}
}

func (l *rateLimiter) allow(ip string) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	now := time.Now()
	h := l.hits[ip][:0]
	for _, t := range l.hits[ip] {
		if now.Sub(t) < l.window {
			h = append(h, t)
		}
	}
	if len(h) >= l.max {
		l.hits[ip] = h
		return false
	}
	l.hits[ip] = append(h, now)
	if len(l.hits) > 10000 { // não deixa o mapa crescer sem limite
		for k, v := range l.hits {
			if len(v) == 0 || now.Sub(v[len(v)-1]) >= l.window {
				delete(l.hits, k)
			}
		}
	}
	return true
}

func (s *Server) limited(h http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if !s.limiter.allow(clientIP(r)) {
			fail(w, http.StatusTooManyRequests, "muitas tentativas, aguarde")
			return
		}
		h(w, r)
	}
}
