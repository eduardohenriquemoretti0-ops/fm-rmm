package redfish

import (
	"context"
	"encoding/json"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"
)

const (
	userTeste  = "admin-bmc"
	senhaTeste = "S3nh4-Sup3r-S3cr3t4!"
)

// bmcFalso é um Redfish mockado sobre TLS (cert self-signed do httptest).
type bmcFalso struct {
	*httptest.Server
	mu     sync.Mutex
	resets []string
	forca  int // se != 0, todas as respostas autenticadas saem com esse status
}

func novoBMC(t *testing.T) *bmcFalso {
	t.Helper()
	b := &bmcFalso{}
	mux := http.NewServeMux()
	auth := func(h http.HandlerFunc) http.HandlerFunc {
		return func(w http.ResponseWriter, r *http.Request) {
			u, p, ok := r.BasicAuth()
			if !ok || u != userTeste || p != senhaTeste {
				http.Error(w, "credencial "+p+" recusada", http.StatusUnauthorized) // eco hostil
				return
			}
			if b.forca != 0 {
				http.Error(w, "boom "+p, b.forca)
				return
			}
			h(w, r)
		}
	}
	mux.HandleFunc("GET /redfish/v1/Systems", auth(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{"Members":[{"@odata.id":"/redfish/v1/Systems/System.Embedded.1"}]}`))
	}))
	mux.HandleFunc("GET /redfish/v1/Systems/{id}", auth(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"Id":"` + r.PathValue("id") + `","PowerState":"On","Model":"PowerEdge R740","Status":{"Health":"OK"}}`))
	}))
	mux.HandleFunc("POST /redfish/v1/Systems/{id}/Actions/ComputerSystem.Reset", auth(func(w http.ResponseWriter, r *http.Request) {
		var body map[string]string
		_ = json.NewDecoder(r.Body).Decode(&body)
		b.mu.Lock()
		b.resets = append(b.resets, r.PathValue("id")+":"+body["ResetType"])
		b.mu.Unlock()
		w.WriteHeader(http.StatusNoContent)
	}))
	b.Server = httptest.NewTLSServer(mux)
	t.Cleanup(b.Close)
	return b
}

func (b *bmcFalso) cfg(t *testing.T, insecure bool) Config {
	t.Helper()
	h, p, _ := net.SplitHostPort(b.Listener.Addr().String())
	porta, _ := strconv.Atoi(p)
	c := Config{Host: h, Porta: porta, Usuario: userTeste, Senha: senhaTeste, Insecure: insecure, Timeout: 5 * time.Second}
	if !insecure {
		c.RootCAs = b.Client().Transport.(*http.Transport).TLSClientConfig.RootCAs
	}
	return c
}

func TestStatusEDescoberta(t *testing.T) {
	b := novoBMC(t)
	c, err := Novo(b.cfg(t, false))
	if err != nil {
		t.Fatal(err)
	}
	e, err := c.Status(context.Background(), "")
	if err != nil {
		t.Fatal(err)
	}
	if e.PowerState != "On" || e.SystemID != "System.Embedded.1" || e.Health != "OK" || e.Modelo != "PowerEdge R740" {
		t.Fatalf("estado inesperado: %+v", e)
	}
	t.Logf("status: %+v", e)
}

func TestCadaAcaoEnviaResetTypeCerto(t *testing.T) {
	b := novoBMC(t)
	c, _ := Novo(b.cfg(t, false))
	acoes := []string{AcaoOn, AcaoForceOff, AcaoGracefulShutdown, AcaoForceRestart, AcaoGracefulRestart}
	for _, a := range acoes {
		if _, err := c.Reset(context.Background(), "System.Embedded.1", a); err != nil {
			t.Fatalf("%s: %v", a, err)
		}
	}
	for i, a := range acoes {
		if b.resets[i] != "System.Embedded.1:"+a {
			t.Fatalf("reset %d: %q", i, b.resets[i])
		}
	}
	t.Logf("ResetTypes recebidos pelo BMC: %v", b.resets)
	if _, err := c.Reset(context.Background(), "", "PowerCycle"); !errors.Is(err, ErrAcaoInvalida) {
		t.Fatalf("ação inválida deveria ser recusada: %v", err)
	}
	if len(b.resets) != len(acoes) {
		t.Fatal("ação inválida chegou ao BMC")
	}
}

func TestTLSValidaPorPadraoEInsecureSoExplicito(t *testing.T) {
	b := novoBMC(t)
	cfg := b.cfg(t, false)
	cfg.RootCAs = nil // cert self-signed do BMC NÃO está na raiz do sistema
	c, _ := Novo(cfg)
	if _, err := c.Status(context.Background(), "x"); !errors.Is(err, ErrConexao) {
		t.Fatalf("self-signed deveria falhar por padrão: %v", err)
	}
	cfg.Insecure = true
	ci, _ := Novo(cfg)
	if !ci.Insecure() {
		t.Fatal("Insecure() deveria ser true")
	}
	if _, err := ci.Status(context.Background(), "x"); err != nil {
		t.Fatalf("insecure explícito deveria funcionar: %v", err)
	}
	if !strings.Contains(AvisoInsecure, "DESLIGADA") {
		t.Fatal("aviso ausente")
	}
}

func TestErrosDoBMCNaoVazamSenha(t *testing.T) {
	b := novoBMC(t)
	cfg := b.cfg(t, false)
	cfg.Senha = "senha-errada-XYZ"
	c, _ := Novo(cfg)
	_, err := c.Status(context.Background(), "x")
	if !errors.Is(err, ErrAutenticacao) {
		t.Fatalf("401 deveria virar ErrAutenticacao: %v", err)
	}
	if strings.Contains(err.Error(), "senha-errada-XYZ") || strings.Contains(err.Error(), senhaTeste) {
		t.Fatalf("senha vazou no erro: %v", err)
	}
	b.forca = 500
	c2, _ := Novo(b.cfg(t, false))
	_, err = c2.Reset(context.Background(), "x", AcaoOn)
	var eh *ErroHTTP
	if !errors.As(err, &eh) || eh.Status != 500 {
		t.Fatalf("500 deveria virar ErroHTTP: %v", err)
	}
	if strings.Contains(err.Error(), senhaTeste) {
		t.Fatalf("senha vazou no erro 500: %v", err)
	}
	t.Logf("erros: 401=%v | 500=%v", ErrAutenticacao, err)
}

func TestErroDeConexaoNaoTrazURLNemSenha(t *testing.T) {
	b := novoBMC(t)
	cfg := b.cfg(t, true)
	b.Close()
	c, _ := Novo(cfg)
	_, err := c.Status(context.Background(), "x")
	if !errors.Is(err, ErrConexao) || strings.Contains(err.Error(), cfg.Host) || strings.Contains(err.Error(), senhaTeste) {
		t.Fatalf("erro de conexão inadequado: %v", err)
	}
}

func TestValidacoes(t *testing.T) {
	for _, h := range []string{"", "a/b", "h:443", "u@h", "h h", "h?x", "http://h", "fe80::1%eth0"} {
		if _, err := Novo(Config{Host: h}); !errors.Is(err, ErrHostInvalido) {
			t.Errorf("host %q deveria ser inválido", h)
		}
	}
	for _, h := range []string{"10.0.0.5", "bmc01.dc.local", "2001:db8::1"} {
		if _, err := Novo(Config{Host: h}); err != nil {
			t.Errorf("host %q deveria ser válido: %v", h, err)
		}
	}
	if _, err := Novo(Config{Host: "h", Porta: 70000}); err == nil {
		t.Error("porta inválida aceita")
	}
	c, _ := Novo(Config{Host: "10.0.0.5"})
	for _, id := range []string{"../x", "a/b", "a b", strings.Repeat("a", 65)} {
		if _, err := c.Status(context.Background(), id); !errors.Is(err, ErrSystemInvalido) {
			t.Errorf("system_id %q deveria ser inválido: %v", id, err)
		}
	}
}

func TestProibirIPBloqueiaDestino(t *testing.T) {
	b := novoBMC(t)
	cfg := b.cfg(t, true)
	cfg.ProibirIP = func(a netip.Addr) bool { return a.IsLoopback() }
	c, _ := Novo(cfg)
	if _, err := c.Status(context.Background(), "x"); !errors.Is(err, ErrDestinoBloq) {
		t.Fatalf("loopback deveria ser bloqueado: %v", err)
	}
}

func TestNaoSegueRedirect(t *testing.T) {
	alvo := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Error("redirect seguido")
	}))
	defer alvo.Close()
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, alvo.URL, http.StatusFound)
	}))
	defer srv.Close()
	h, p, _ := net.SplitHostPort(srv.Listener.Addr().String())
	porta, _ := strconv.Atoi(p)
	c, _ := Novo(Config{Host: h, Porta: porta, Usuario: "u", Senha: "p", Insecure: true})
	_, err := c.Status(context.Background(), "x")
	var eh *ErroHTTP
	if !errors.As(err, &eh) || eh.Status != 302 {
		t.Fatalf("esperava ErroHTTP 302: %v", err)
	}
}
