package console

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/go-webauthn/webauthn/protocol"

	"github.com/eduardohenriquemoretti0-ops/fm-rmm/internal/pki"
)

// ambiente: fixture (store real + sessões + autenticador) + Console + CA de teste.
type ambiente struct {
	f    *fixture
	c    *Console
	ca   *x509.Certificate
	caK  *ecdsa.PrivateKey
	pool *x509.CertPool
}

func novoAmbiente(t *testing.T) *ambiente {
	t.Helper()
	f := novoFixture(t)
	ca, caK, err := pki.NewCA("FM-RMM CA teste")
	if err != nil {
		t.Fatal(err)
	}
	pool := x509.NewCertPool()
	pool.AddCert(ca)
	c, err := NovoConsole(f.sm, f.a, f.st, pool)
	if err != nil {
		t.Fatal(err)
	}
	return &ambiente{f: f, c: c, ca: ca, caK: caK, pool: pool}
}

// certDe emite um cert de cliente de uma CA (o agente é o emissor de cliente na pki).
func certDe(t *testing.T, ca *x509.Certificate, caK *ecdsa.PrivateKey, id string) (*x509.Certificate, *ecdsa.PrivateKey) {
	t.Helper()
	chave, csrPEM, err := pki.NewAgentKeyAndCSR(id)
	if err != nil {
		t.Fatal(err)
	}
	csr, err := pki.ParseCSR(csrPEM)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := pki.SignAgent(ca, caK, csr, id)
	if err != nil {
		t.Fatal(err)
	}
	return cert, chave
}

// estado simula o handshake mTLS com o cert informado (nil = sem cert).
func estado(cert *x509.Certificate) *tls.ConnectionState {
	if cert == nil {
		return &tls.ConnectionState{}
	}
	return &tls.ConnectionState{PeerCertificates: []*x509.Certificate{cert}}
}

func reqTLS(metodo, alvo string, corpo io.Reader, cert *x509.Certificate) *http.Request {
	r := httptest.NewRequest(metodo, alvo, corpo)
	r.TLS = estado(cert)
	return r
}

// operadorAtivoComCert cria o operador com o thumbprint do cert, registra uma
// chave WebAuthn e o ativa.
func (a *ambiente) operadorAtivoComCert(t *testing.T, id string, cert *x509.Certificate) *autSoft {
	t.Helper()
	k := novoAutSoft(t)
	a.f.criaOperador(t, id, "pendente", CertThumbprint(cert))
	if _, err := a.f.registra(t, id, k, 0x45); err != nil {
		t.Fatalf("registro %s: %v", id, err)
	}
	if err := a.f.st.SetOperatorStatus(id, "ativo"); err != nil {
		t.Fatal(err)
	}
	return k
}

// ecoOperador é um handler de teste que devolve o id do operador vindo do contexto.
func ecoOperador(w http.ResponseWriter, r *http.Request) {
	op, thumb, ok := OperadorDoContexto(r.Context())
	if !ok {
		http.Error(w, "sem operador", http.StatusInternalServerError)
		return
	}
	w.Header().Set("X-Teste-Operador", op.ID)
	w.Header().Set("X-Teste-Thumb", thumb)
	w.WriteHeader(http.StatusOK)
}

// (a) cert de outra CA -> 401, mesmo com o thumbprint cadastrado como operador.
func TestMTLSRecusaCertDeOutraCA(t *testing.T) {
	a := novoAmbiente(t)
	certBom, _ := certDe(t, a.ca, a.caK, "op-bom")
	a.operadorAtivoComCert(t, "op-bom", certBom)

	outraCA, outraK, err := pki.NewCA("CA estranha")
	if err != nil {
		t.Fatal(err)
	}
	certEstranho, _ := certDe(t, outraCA, outraK, "op-bom")
	// operador cadastrado com o thumbprint do cert estranho (erro de cadastro):
	// só a verificação de cadeia pode barrar, e tem de barrar.
	a.f.criaOperador(t, "op-intruso", "ativo", CertThumbprint(certEstranho))

	h := a.c.soCert(http.HandlerFunc(ecoOperador))

	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, reqTLS(http.MethodPost, "/api/login/inicio", nil, certEstranho))
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("cert de outra CA = %d, quer 401", rec.Code)
	}
	if strings.Contains(rec.Body.String(), "CA") || strings.Contains(rec.Body.String(), "op-") {
		t.Errorf("resposta vaza detalhe: %q", rec.Body.String())
	}

	// controle: o cert da nossa CA passa
	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, reqTLS(http.MethodPost, "/api/login/inicio", nil, certBom))
	if rec.Code != http.StatusOK {
		t.Fatalf("controle com cert válido = %d, quer 200", rec.Code)
	}
}

// Sem cert, cert de CA válida mas sem operador cadastrado -> 401 genérico.
func TestMTLSSemCertOuSemOperador(t *testing.T) {
	a := novoAmbiente(t)
	h := a.c.soCert(http.HandlerFunc(ecoOperador))

	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, reqTLS(http.MethodPost, "/", nil, nil))
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("sem cert = %d, quer 401", rec.Code)
	}

	semOperador, _ := certDe(t, a.ca, a.caK, "ninguem")
	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, reqTLS(http.MethodPost, "/", nil, semOperador))
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("cert sem operador = %d, quer 401", rec.Code)
	}
}

// (b) cert válido mapeia ao operador certo, com o thumbprint certo no contexto.
func TestMTLSMapeiaAoOperadorCerto(t *testing.T) {
	a := novoAmbiente(t)
	certA, _ := certDe(t, a.ca, a.caK, "op-a")
	certB, _ := certDe(t, a.ca, a.caK, "op-b")
	a.operadorAtivoComCert(t, "op-a", certA)
	a.operadorAtivoComCert(t, "op-b", certB)
	h := a.c.soCert(http.HandlerFunc(ecoOperador))

	for _, caso := range []struct {
		cert *x509.Certificate
		id   string
	}{{certA, "op-a"}, {certB, "op-b"}} {
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, reqTLS(http.MethodGet, "/", nil, caso.cert))
		if rec.Code != http.StatusOK {
			t.Fatalf("%s: status %d", caso.id, rec.Code)
		}
		if got := rec.Header().Get("X-Teste-Operador"); got != caso.id {
			t.Errorf("operador = %q, quer %q", got, caso.id)
		}
		if got := rec.Header().Get("X-Teste-Thumb"); got != CertThumbprint(caso.cert) {
			t.Errorf("thumbprint no contexto != thumbprint do cert")
		}
	}
}

// (c) token de sessão apresentado com cert de OUTRO cliente -> 401, sem revogar.
func TestSessaoComCertDiferenteRecusa(t *testing.T) {
	a := novoAmbiente(t)
	certA, _ := certDe(t, a.ca, a.caK, "op-a")
	certB, _ := certDe(t, a.ca, a.caK, "op-b")
	a.operadorAtivoComCert(t, "op-a", certA)
	a.operadorAtivoComCert(t, "op-b", certB)

	raw, _, err := a.f.sm.New("op-a", CertThumbprint(certA))
	if err != nil {
		t.Fatal(err)
	}
	// o erro de domínio é exatamente ErrClienteDiferente
	if _, err := a.f.sm.Validate(raw, CertThumbprint(certB)); !errors.Is(err, ErrClienteDiferente) {
		t.Fatalf("Validate com cert de outro cliente = %v, quer ErrClienteDiferente", err)
	}

	h := a.c.protegido(a.c.sessaoAtual)
	ck := SessionCookie(NomeCookieSessao, raw, time.Minute)

	reqB := reqTLS(http.MethodGet, "/api/sessao", nil, certB)
	reqB.AddCookie(ck)
	recB := httptest.NewRecorder()
	h.ServeHTTP(recB, reqB)
	if recB.Code != http.StatusUnauthorized {
		t.Fatalf("token + cert de outro cliente = %d, quer 401", recB.Code)
	}
	if !cookieLimpo(recB) {
		t.Error("401 de sessão deveria limpar o cookie no navegador")
	}

	// a sessão continua viva para o dono original (não foi revogada por engano)
	reqA := reqTLS(http.MethodGet, "/api/sessao", nil, certA)
	reqA.AddCookie(ck)
	recA := httptest.NewRecorder()
	h.ServeHTTP(recA, reqA)
	if recA.Code != http.StatusOK {
		t.Fatalf("dono original = %d, quer 200", recA.Code)
	}
}

// (d) escrita sem header CSRF -> 403; com o CSRF certo -> passa.
func TestEscritaExigeCSRF(t *testing.T) {
	a := novoAmbiente(t)
	certA, _ := certDe(t, a.ca, a.caK, "op-a")
	a.operadorAtivoComCert(t, "op-a", certA)
	raw, csrf, err := a.f.sm.New("op-a", CertThumbprint(certA))
	if err != nil {
		t.Fatal(err)
	}
	h := a.c.protegido(a.c.logout)
	ck := SessionCookie(NomeCookieSessao, raw, time.Minute)

	montar := func(cabecalho string) *http.Request {
		r := reqTLS(http.MethodPost, "/api/logout", nil, certA)
		r.AddCookie(ck)
		if cabecalho != "" {
			r.Header.Set(CabecalhoCSRF, cabecalho)
		}
		return r
	}

	for _, caso := range []struct{ nome, cab string }{
		{"sem header", ""},
		{"csrf errado", "nao-e-o-token"},
	} {
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, montar(caso.cab))
		if rec.Code != http.StatusForbidden {
			t.Fatalf("%s = %d, quer 403", caso.nome, rec.Code)
		}
	}
	if _, err := a.f.sm.Validate(raw, CertThumbprint(certA)); err != nil {
		t.Fatalf("CSRF recusado não pode revogar a sessão: %v", err)
	}

	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, montar(csrf))
	if rec.Code != http.StatusOK {
		t.Fatalf("CSRF certo = %d, quer 200", rec.Code)
	}
	if _, err := a.f.sm.Validate(raw, CertThumbprint(certA)); !errors.Is(err, ErrSessaoInvalida) {
		t.Fatalf("logout deveria revogar a sessão, Validate = %v", err)
	}
}

// Escrita sem sessão nenhuma -> 401 (fail-closed, não 403).
func TestEscritaSemSessaoRecusaComo401(t *testing.T) {
	a := novoAmbiente(t)
	certA, _ := certDe(t, a.ca, a.caK, "op-a")
	a.operadorAtivoComCert(t, "op-a", certA)
	h := a.c.protegido(a.c.logout)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, reqTLS(http.MethodPost, "/api/logout", nil, certA))
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("sem sessão = %d, quer 401", rec.Code)
	}
}

// (e) login /fim emite cookie HttpOnly+Secure+SameSite=Strict, ligado ao cert.
func TestLoginFimEmiteCookieSeguro(t *testing.T) {
	a := novoAmbiente(t)
	certA, _ := certDe(t, a.ca, a.caK, "op-a")
	k := a.operadorAtivoComCert(t, "op-a", certA)

	// /inicio: cert -> opções + chave da cerimônia
	rec := httptest.NewRecorder()
	a.c.Roteador().ServeHTTP(rec, reqTLS(http.MethodPost, "/api/login/inicio", nil, certA))
	if rec.Code != http.StatusOK {
		t.Fatalf("/inicio = %d: %s", rec.Code, rec.Body.String())
	}
	var ini struct {
		Cerimonia string                       `json:"cerimonia"`
		Opcoes    protocol.CredentialAssertion `json:"opcoes"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &ini); err != nil {
		t.Fatal(err)
	}
	if ini.Cerimonia == "" {
		t.Fatal("/inicio sem chave de cerimônia")
	}

	// /fim: asserção assinada pela chave do operador, chave no header
	corpo := k.corpoAsercao(ini.Opcoes.Response.Challenge.String(), originTeste, rpIDTeste, 1, []byte("op-a"))
	fim := reqTLS(http.MethodPost, "/api/login/fim", bytes.NewReader(corpo), certA)
	fim.Header.Set(CabecalhoCerimonia, ini.Cerimonia)
	rec = httptest.NewRecorder()
	a.c.Roteador().ServeHTTP(rec, fim)
	if rec.Code != http.StatusOK {
		t.Fatalf("/fim = %d: %s", rec.Code, rec.Body.String())
	}

	var ck *http.Cookie
	for _, c := range rec.Result().Cookies() {
		if c.Name == NomeCookieSessao {
			ck = c
		}
	}
	if ck == nil {
		t.Fatal("/fim não emitiu o cookie de sessão")
	}
	if !ck.HttpOnly {
		t.Error("cookie sem HttpOnly")
	}
	if !ck.Secure {
		t.Error("cookie sem Secure")
	}
	if ck.SameSite != http.SameSiteStrictMode {
		t.Error("cookie sem SameSite=Strict")
	}
	if ck.Path != "/" {
		t.Errorf("Path = %q, quer /", ck.Path)
	}
	if ck.Domain != "" {
		t.Errorf("cookie com Domain %q (quebra __Host-)", ck.Domain)
	}
	if _, err := a.f.sm.Validate(ck.Value, CertThumbprint(certA)); err != nil {
		t.Errorf("token do cookie não valida ligado ao cert: %v", err)
	}
	if strings.Contains(rec.Body.String(), ck.Value) {
		t.Error("token de sessão vazou no corpo da resposta (deve ir só no cookie)")
	}

	// e a sessão funciona de ponta a ponta: GET /api/sessao com o cookie
	sess := reqTLS(http.MethodGet, "/api/sessao", nil, certA)
	sess.AddCookie(ck)
	recS := httptest.NewRecorder()
	a.c.Roteador().ServeHTTP(recS, sess)
	if recS.Code != http.StatusOK {
		t.Fatalf("/api/sessao com cookie = %d", recS.Code)
	}
}

// Cadastro de chave só para operador pendente; ativo recebe recusa.
func TestRegistroRotaSoComPendente(t *testing.T) {
	a := novoAmbiente(t)
	certP, _ := certDe(t, a.ca, a.caK, "op-p")
	a.f.criaOperador(t, "op-p", "pendente", CertThumbprint(certP))

	rec := httptest.NewRecorder()
	a.c.Roteador().ServeHTTP(rec, reqTLS(http.MethodPost, "/api/registro/inicio", nil, certP))
	if rec.Code != http.StatusOK {
		t.Fatalf("registro/inicio de pendente = %d: %s", rec.Code, rec.Body.String())
	}

	certT, _ := certDe(t, a.ca, a.caK, "op-t")
	a.operadorAtivoComCert(t, "op-t", certT)
	rec = httptest.NewRecorder()
	a.c.Roteador().ServeHTTP(rec, reqTLS(http.MethodPost, "/api/registro/inicio", nil, certT))
	// operador ativo: cadastro fechado (403, ErrRegistroFechado), nunca 200
	if rec.Code != http.StatusForbidden {
		t.Fatalf("registro/inicio de ativo = %d, quer 403", rec.Code)
	}
}

// Logout e sessão de operador desativado: a sessão cai na hora.
func TestSessaoDeOperadorInativoCai(t *testing.T) {
	a := novoAmbiente(t)
	certA, _ := certDe(t, a.ca, a.caK, "op-a")
	a.operadorAtivoComCert(t, "op-a", certA)
	raw, _, err := a.f.sm.New("op-a", CertThumbprint(certA))
	if err != nil {
		t.Fatal(err)
	}
	if err := a.f.st.SetOperatorStatus("op-a", "suspenso"); err != nil {
		t.Fatal(err)
	}
	r := reqTLS(http.MethodGet, "/api/sessao", nil, certA)
	r.AddCookie(SessionCookie(NomeCookieSessao, raw, time.Minute))
	rec := httptest.NewRecorder()
	a.c.Roteador().ServeHTTP(rec, r)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("operador suspenso = %d, quer 401", rec.Code)
	}
	if _, err := a.f.sm.Validate(raw, CertThumbprint(certA)); !errors.Is(err, ErrSessaoInvalida) {
		t.Errorf("sessão de operador suspenso deveria estar revogada, Validate = %v", err)
	}
}

// Validação das dependências do construtor.
func TestNovoConsoleValidaDependencias(t *testing.T) {
	a := novoAmbiente(t)
	outraSM := NewSessionManager(time.Minute, time.Minute)
	if _, err := NovoConsole(outraSM, a.f.a, a.f.st, a.pool); err == nil {
		t.Error("aceitou SessionManager diferente do autenticador")
	}
	if _, err := NovoConsole(a.f.sm, a.f.a, a.f.st, nil); err == nil {
		t.Error("aceitou CA nula")
	}
}

// cookieLimpo confere se a resposta manda apagar o cookie de sessão.
func cookieLimpo(rec *httptest.ResponseRecorder) bool {
	for _, c := range rec.Result().Cookies() {
		if c.Name == NomeCookieSessao && c.MaxAge < 0 {
			return true
		}
	}
	return false
}
