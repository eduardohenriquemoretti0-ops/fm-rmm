package console

import (
	"bytes"
	"crypto/tls"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/go-webauthn/webauthn/protocol"
)

func TestStepUpPelasRotasMarcaSessaoESessaoTrazTecnicoERelay(t *testing.T) {
	a := novoAmbiente(t)
	certA, _ := certDe(t, a.ca, a.caK, "op-a")
	k := a.operadorAtivoComCert(t, "op-a", certA)
	a.c.ConfigurarRelay("wss://relay.exemplo:8443")
	h := a.c.Roteador()

	// login
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, reqTLS(http.MethodPost, "/api/login/inicio", nil, certA))
	var ini struct {
		Cerimonia string                       `json:"cerimonia"`
		Opcoes    protocol.CredentialAssertion `json:"opcoes"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &ini); err != nil {
		t.Fatal(err)
	}
	corpo := k.corpoAsercao(ini.Opcoes.Response.Challenge.String(), originTeste, rpIDTeste, 1, []byte("op-a"))
	fim := reqTLS(http.MethodPost, "/api/login/fim", bytes.NewReader(corpo), certA)
	fim.Header.Set(CabecalhoCerimonia, ini.Cerimonia)
	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, fim)
	if rec.Code != http.StatusOK {
		t.Fatalf("login/fim = %d: %s", rec.Code, rec.Body.String())
	}
	var lf map[string]string
	_ = json.Unmarshal(rec.Body.Bytes(), &lf)
	var ck *http.Cookie
	for _, c := range rec.Result().Cookies() {
		if c.Name == NomeCookieSessao {
			ck = c
		}
	}
	novo := func(m, p string, b []byte) *http.Request {
		r := reqTLS(m, p, bytes.NewReader(b), certA)
		r.AddCookie(ck)
		r.Header.Set(CabecalhoCSRF, lf["csrf"])
		return r
	}

	// /api/sessao: tecnico + relay_url
	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, novo(http.MethodGet, "/api/sessao", nil))
	var ss map[string]string
	_ = json.Unmarshal(rec.Body.Bytes(), &ss)
	if rec.Code != 200 || ss["relay_url"] != "wss://relay.exemplo:8443" {
		t.Fatalf("/api/sessao = %d %s", rec.Code, rec.Body.String())
	}
	if _, ok := ss["tecnico"]; !ok {
		t.Fatalf("/api/sessao sem campo tecnico: %s", rec.Body.String())
	}

	// step-up sem sessão/cookie: recusa
	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, reqTLS(http.MethodPost, "/api/stepup/inicio", nil, certA))
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("stepup/inicio sem sessão = %d", rec.Code)
	}
	// sem CSRF: 403
	r := reqTLS(http.MethodPost, "/api/stepup/inicio", nil, certA)
	r.AddCookie(ck)
	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, r)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("stepup/inicio sem CSRF = %d", rec.Code)
	}

	if a.f.sm.StepUpValido(ck.Value, CertThumbprint(certA)) {
		t.Fatal("step-up válido antes do re-toque")
	}
	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, novo(http.MethodPost, "/api/stepup/inicio", nil))
	if rec.Code != 200 {
		t.Fatalf("stepup/inicio = %d: %s", rec.Code, rec.Body.String())
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &ini); err != nil {
		t.Fatal(err)
	}
	corpo = k.corpoAsercao(ini.Opcoes.Response.Challenge.String(), originTeste, rpIDTeste, 2, []byte("op-a"))
	r = novo(http.MethodPost, "/api/stepup/fim", corpo)
	r.Header.Set(CabecalhoCerimonia, ini.Cerimonia)
	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, r)
	if rec.Code != 200 {
		t.Fatalf("stepup/fim = %d: %s", rec.Code, rec.Body.String())
	}
	if !a.f.sm.StepUpValido(ck.Value, CertThumbprint(certA)) {
		t.Fatal("stepup/fim não marcou o step-up na sessão")
	}
}

func TestEstaticosMesmaOrigemSemInvadirAPI(t *testing.T) {
	a := novoAmbiente(t)
	dir := t.TempDir()
	_ = os.WriteFile(filepath.Join(dir, "index.html"), []byte("<html>spa</html>"), 0o600)
	_ = os.MkdirAll(filepath.Join(dir, "assets"), 0o700)
	_ = os.WriteFile(filepath.Join(dir, "assets", "app.js"), []byte("x"), 0o600)
	a.c.ServirEstaticos(dir)
	h := a.c.Roteador()
	get := func(p string) *httptest.ResponseRecorder {
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, p, nil))
		return rec
	}
	if rec := get("/"); rec.Code != 200 || !strings.Contains(rec.Body.String(), "spa") ||
		rec.Header().Get("Cache-Control") != "no-store" || rec.Header().Get("Content-Security-Policy") == "" {
		t.Fatalf("index: %d %v", rec.Code, rec.Header())
	}
	if rec := get("/assets/app.js"); rec.Code != 200 {
		t.Fatalf("asset = %d", rec.Code)
	}
	if rec := get("/api/inexistente"); rec.Code != 404 || strings.Contains(rec.Body.String(), "spa") {
		t.Fatalf("/api/inexistente = %d", rec.Code)
	}
	if rec := get("/../../etc/passwd"); rec.Code == 200 && strings.Contains(rec.Body.String(), "root:") {
		t.Fatal("traversal")
	}
	// /api/agentes continua protegido (não cai no estático)
	if rec := get("/api/agentes"); rec.Code != http.StatusUnauthorized {
		t.Fatalf("/api/agentes sem cert = %d", rec.Code)
	}
}

// Listener real: handshake sem cert de cliente falha; com cert de operador da
// CA, /api/sessao sem sessão responde 401 (middleware) e /healthz 200.
func TestListenerConsoleExigeCertDeCliente(t *testing.T) {
	a := novoAmbiente(t)
	certA, keyA := certDe(t, a.ca, a.caK, "op-a")
	srvCert, srvKey := certDe(t, a.ca, a.caK, "console-srv")
	tc, err := TLSConfigConsole(a.ca, tls.Certificate{Certificate: [][]byte{srvCert.Raw}, PrivateKey: srvKey})
	if err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewUnstartedServer(a.c.Roteador())
	srv.TLS = tc
	srv.StartTLS()
	defer srv.Close()

	raiz := a.pool
	semCert := &http.Client{Transport: &http.Transport{TLSClientConfig: &tls.Config{RootCAs: raiz, InsecureSkipVerify: true}}}
	if resp, err := semCert.Get(srv.URL + "/healthz"); err == nil {
		resp.Body.Close()
		t.Fatalf("handshake sem cert de cliente deveria falhar (status %d)", resp.StatusCode)
	}
	comCert := &http.Client{Transport: &http.Transport{TLSClientConfig: &tls.Config{
		InsecureSkipVerify: true,
		Certificates:       []tls.Certificate{{Certificate: [][]byte{certA.Raw}, PrivateKey: keyA}},
	}}}
	resp, err := comCert.Get(srv.URL + "/healthz")
	if err != nil || resp.StatusCode != 200 {
		t.Fatalf("com cert: %v %v", err, resp)
	}
	resp.Body.Close()
}

// L1: diretório sem index.html => 404 (sem listagem); arquivo => 200.
// L2: a 404 de estático também sai com Cache-Control: no-store.
func TestEstaticosSemListagemDeDiretorioENoStoreNo404(t *testing.T) {
	a := novoAmbiente(t)
	dir := t.TempDir()
	_ = os.WriteFile(filepath.Join(dir, "index.html"), []byte("<html>spa</html>"), 0o600)
	_ = os.MkdirAll(filepath.Join(dir, "assets"), 0o700)
	_ = os.WriteFile(filepath.Join(dir, "assets", "segredo-listado.js"), []byte("x"), 0o600)
	_ = os.MkdirAll(filepath.Join(dir, "comindex"), 0o700)
	_ = os.WriteFile(filepath.Join(dir, "comindex", "index.html"), []byte("sub"), 0o600)
	a.c.ServirEstaticos(dir)
	h := a.c.Roteador()
	get := func(p string) *httptest.ResponseRecorder {
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, p, nil))
		return rec
	}
	for _, p := range []string{"/assets/", "/assets"} {
		rec := get(p)
		if strings.Contains(rec.Body.String(), "segredo-listado") {
			t.Fatalf("%s listou o diretório: %s", p, rec.Body.String())
		}
		if p == "/assets/" && rec.Code != http.StatusNotFound {
			t.Errorf("%s = %d, quer 404", p, rec.Code)
		}
	}
	if rec := get("/assets/segredo-listado.js"); rec.Code != 200 {
		t.Errorf("arquivo regular = %d, quer 200", rec.Code)
	}
	if rec := get("/comindex/"); rec.Code != 200 || !strings.Contains(rec.Body.String(), "sub") {
		t.Errorf("diretório com index.html = %d, quer 200", rec.Code)
	}
	for _, p := range []string{"/assets/", "/nao-existe.js", "/api/qualquer"} {
		rec := get(p)
		if rec.Code != http.StatusNotFound {
			t.Errorf("%s = %d, quer 404", p, rec.Code)
		}
		if got := rec.Header().Get("Cache-Control"); got != "no-store" {
			t.Errorf("%s: Cache-Control = %q, quer no-store", p, got)
		}
		if rec.Header().Get("Content-Security-Policy") == "" || rec.Header().Get("X-Content-Type-Options") != "nosniff" {
			t.Errorf("%s: faltam headers de segurança", p)
		}
	}
}
