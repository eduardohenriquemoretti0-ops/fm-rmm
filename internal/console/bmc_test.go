package console

import (
	"bytes"
	"encoding/json"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strconv"
	"strings"
	"sync"
	"testing"
)

const (
	bmcUser  = "root-bmc"
	bmcSenha = "Sup3r-Segr3d0-BMC-9f8e7d"
)

type bmcMock struct {
	*httptest.Server
	mu     sync.Mutex
	resets []string
	status int // se != 0, resposta de erro nas rotas autenticadas
}

func novoBMCMock(t *testing.T) *bmcMock {
	t.Helper()
	m := &bmcMock{}
	mux := http.NewServeMux()
	auth := func(h http.HandlerFunc) http.HandlerFunc {
		return func(w http.ResponseWriter, r *http.Request) {
			u, p, ok := r.BasicAuth()
			if !ok || u != bmcUser || p != bmcSenha {
				http.Error(w, "negado para senha "+p, http.StatusUnauthorized) // eco hostil
				return
			}
			if m.status != 0 {
				http.Error(w, "falha "+p, m.status)
				return
			}
			h(w, r)
		}
	}
	mux.HandleFunc("GET /redfish/v1/Systems", auth(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{"Members":[{"@odata.id":"/redfish/v1/Systems/System.Embedded.1"}]}`))
	}))
	mux.HandleFunc("GET /redfish/v1/Systems/{id}", auth(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{"PowerState":"Off","Model":"PowerEdge R740","Status":{"Health":"OK"}}`))
	}))
	mux.HandleFunc("POST /redfish/v1/Systems/{id}/Actions/ComputerSystem.Reset", auth(func(w http.ResponseWriter, r *http.Request) {
		var b map[string]string
		_ = json.NewDecoder(r.Body).Decode(&b)
		m.mu.Lock()
		m.resets = append(m.resets, b["ResetType"])
		m.mu.Unlock()
		w.WriteHeader(http.StatusNoContent)
	}))
	m.Server = httptest.NewTLSServer(mux)
	t.Cleanup(m.Close)
	return m
}

// cenarioBMC: cenário de ações + técnico tA com o grupo bmc + console apontado ao mock.
func novoCenarioBMC(t *testing.T, m *bmcMock, concedeGrupo bool) *cenarioAcao {
	t.Helper()
	c := novoCenarioAcao(t)
	if concedeGrupo {
		if err := c.a.f.st.GrantGroup("tA", GrupoBMC); err != nil {
			t.Fatal(err)
		}
	}
	c.a.c.bmcRoots = m.Client().Transport.(*http.Transport).TLSClientConfig.RootCAs
	c.a.c.bmcProibirIP = func(netip.Addr) bool { return false } // o mock vive em 127.0.0.1
	return c
}

func (m *bmcMock) req(acao string) map[string]any {
	h, p, _ := net.SplitHostPort(m.Listener.Addr().String())
	porta, _ := strconv.Atoi(p)
	return map[string]any{"host": h, "porta": porta, "system_id": "System.Embedded.1",
		"acao": acao, "usuario": bmcUser, "senha": bmcSenha}
}

// capturaLog redireciona o slog padrão para um buffer durante o teste.
func capturaLog(t *testing.T) *bytes.Buffer {
	t.Helper()
	var buf bytes.Buffer
	antigo := slog.Default()
	slog.SetDefault(slog.New(slog.NewTextHandler(&buf, nil)))
	t.Cleanup(func() { slog.SetDefault(antigo) })
	return &buf
}

// semSenhaEmLugarNenhum inspeciona TODAS as entradas de auditoria, o log e as respostas.
func semSenhaEmLugarNenhum(t *testing.T, c *cenarioAcao, logs string, respostas ...string) {
	t.Helper()
	entradas, err := c.a.f.st.AuditEntries()
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range entradas {
		raw, _ := json.Marshal(e)
		if strings.Contains(string(raw), bmcSenha) {
			t.Fatalf("SENHA na auditoria: %s", raw)
		}
	}
	if strings.Contains(logs, bmcSenha) {
		t.Fatalf("SENHA no log: %s", logs)
	}
	for _, r := range respostas {
		if strings.Contains(r, bmcSenha) {
			t.Fatalf("SENHA na resposta: %s", r)
		}
	}
}

func TestBMCStatusLeEstado(t *testing.T) {
	m := novoBMCMock(t)
	c := novoCenarioBMC(t, m, true)
	c.stepUp(t)
	rec := c.envia(t, "/api/bmc/status", m.req(""))
	if rec.Code != 200 || !strings.Contains(rec.Body.String(), `"power_state":"Off"`) {
		t.Fatalf("status: %d %s", rec.Code, rec.Body.String())
	}
	t.Logf("status -> %d %s", rec.Code, strings.TrimSpace(rec.Body.String()))
	semSenhaEmLugarNenhum(t, c, "", rec.Body.String())
}

func TestBMCCadaAcaoEnviaResetTypeEAuditaSemSenha(t *testing.T) {
	logs := capturaLog(t)
	m := novoBMCMock(t)
	c := novoCenarioBMC(t, m, true)
	c.stepUp(t)
	acoes := []string{"On", "ForceOff", "GracefulShutdown", "ForceRestart", "GracefulRestart"}
	var resps []string
	for _, a := range acoes {
		rec := c.envia(t, "/api/bmc/power", m.req(a))
		if rec.Code != 200 {
			t.Fatalf("%s: %d %s", a, rec.Code, rec.Body.String())
		}
		resps = append(resps, rec.Body.String())
	}
	if strings.Join(m.resets, ",") != strings.Join(acoes, ",") {
		t.Fatalf("ResetTypes recebidos: %v", m.resets)
	}
	t.Logf("ResetTypes recebidos pelo BMC: %v", m.resets)
	entradas, _ := c.a.f.st.AuditEntries()
	n := 0
	for _, e := range entradas {
		if e.Event == "console.bmc.power" {
			n++
			t.Logf("auditoria: %s actor=%s data=%s", e.Event, e.Actor, e.Data)
		}
	}
	if n != len(acoes) {
		t.Fatalf("auditoria console.bmc.power: %d, esperado %d", n, len(acoes))
	}
	semSenhaEmLugarNenhum(t, c, logs.String(), resps...)
}

func TestBMCErrosDoBMCSemVazarSenha(t *testing.T) {
	logs := capturaLog(t)
	m := novoBMCMock(t)
	c := novoCenarioBMC(t, m, true)
	c.stepUp(t)

	ruim := m.req("On")
	ruim["senha"] = "errada-" + bmcSenha // contém a senha real como prefixo/sufixo de propósito
	rec401 := c.envia(t, "/api/bmc/power", ruim)
	c.exigeCodigo(t, rec401, http.StatusBadGateway, "bmc_credencial_recusada")

	m.status = 500
	rec500 := c.envia(t, "/api/bmc/power", m.req("ForceOff"))
	c.exigeCodigo(t, rec500, http.StatusBadGateway, "bmc_erro_http_500")
	t.Logf("401 -> %d %s", rec401.Code, strings.TrimSpace(rec401.Body.String()))
	t.Logf("500 -> %d %s", rec500.Code, strings.TrimSpace(rec500.Body.String()))
	if len(m.resets) != 0 {
		t.Fatalf("nenhum reset deveria ter sido aceito: %v", m.resets)
	}
	semSenhaEmLugarNenhum(t, c, logs.String(), rec401.Body.String(), rec500.Body.String())
	if strings.Contains(rec401.Body.String(), "errada-") {
		t.Fatal("senha enviada vazou na resposta")
	}
}

func TestBMCInsecureSoQuandoPedido(t *testing.T) {
	logs := capturaLog(t)
	m := novoBMCMock(t)
	c := novoCenarioBMC(t, m, true)
	c.a.c.bmcRoots = nil // self-signed do mock não é confiável
	c.stepUp(t)

	rec := c.envia(t, "/api/bmc/status", m.req(""))
	c.exigeCodigo(t, rec, http.StatusBadGateway, "bmc_inacessivel")

	r := m.req("")
	r["insecure"] = true
	rec = c.envia(t, "/api/bmc/status", r)
	if rec.Code != 200 || !strings.Contains(rec.Body.String(), "aviso") {
		t.Fatalf("insecure explícito: %d %s", rec.Code, rec.Body.String())
	}
	t.Logf("insecure -> %d %s", rec.Code, strings.TrimSpace(rec.Body.String()))
	if !strings.Contains(logs.String(), "modo inseguro") {
		t.Fatal("aviso no log ausente")
	}
	entradas, _ := c.a.f.st.AuditEntries()
	achou := false
	for _, e := range entradas {
		if e.Event == "console.bmc.status" && strings.Contains(string(e.Data), `"insecure":true`) {
			achou = true
		}
	}
	if !achou {
		t.Fatal("auditoria deveria marcar insecure=true")
	}
	semSenhaEmLugarNenhum(t, c, logs.String(), rec.Body.String())
}

func TestBMCSemStepUpRecusa(t *testing.T) {
	m := novoBMCMock(t)
	c := novoCenarioBMC(t, m, true) // sem stepUp
	for _, rota := range []string{"/api/bmc/power", "/api/bmc/status"} {
		rec := c.envia(t, rota, m.req("ForceOff"))
		c.exigeCodigo(t, rec, http.StatusForbidden, "step_up_necessario")
		t.Logf("%s sem step-up -> %d %s", rota, rec.Code, strings.TrimSpace(rec.Body.String()))
	}
	if len(m.resets) != 0 {
		t.Fatal("BMC foi acionado sem step-up")
	}
	semSenhaEmLugarNenhum(t, c, "")
}

func TestBMCSemGrupoRecusa(t *testing.T) {
	m := novoBMCMock(t)
	c := novoCenarioBMC(t, m, false)
	c.stepUp(t)
	rec := c.envia(t, "/api/bmc/power", m.req("ForceOff"))
	c.exigeCodigo(t, rec, http.StatusForbidden, "sem_permissao_bmc")
	// curinga '*' NÃO vale
	if err := c.a.f.st.GrantGroup("tA", "*"); err != nil {
		t.Fatal(err)
	}
	rec = c.envia(t, "/api/bmc/power", m.req("ForceOff"))
	c.exigeCodigo(t, rec, http.StatusForbidden, "sem_permissao_bmc")
	if len(m.resets) != 0 {
		t.Fatal("BMC acionado sem o grupo bmc")
	}
	t.Logf("sem grupo bmc -> %d %s", rec.Code, strings.TrimSpace(rec.Body.String()))
}

func TestBMCExigeCertSessaoECSRF(t *testing.T) {
	m := novoBMCMock(t)
	c := novoCenarioBMC(t, m, true)
	c.stepUp(t)
	b, _ := json.Marshal(m.req("On"))
	// sem cert de cliente
	r := httptest.NewRequest(http.MethodPost, "/api/bmc/power", bytes.NewReader(b))
	rec := httptest.NewRecorder()
	c.a.c.Roteador().ServeHTTP(rec, r)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("sem cert: %d", rec.Code)
	}
	// cert sem cookie de sessão
	r = reqTLS(http.MethodPost, "/api/bmc/power", bytes.NewReader(b), c.certA)
	rec = httptest.NewRecorder()
	c.a.c.Roteador().ServeHTTP(rec, r)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("sem sessão: %d", rec.Code)
	}
	// sessão sem CSRF
	r = reqTLS(http.MethodPost, "/api/bmc/power", bytes.NewReader(b), c.certA)
	r.AddCookie(c.ck)
	rec = httptest.NewRecorder()
	c.a.c.Roteador().ServeHTTP(rec, r)
	if rec.Code < 400 {
		t.Fatalf("sem CSRF: %d", rec.Code)
	}
	t.Logf("sem cert=401, sem sessão=401, sem CSRF=%d", rec.Code)
	if len(m.resets) != 0 {
		t.Fatal("BMC acionado sem autenticação completa")
	}
}

func TestBMCEntradasInvalidasEDestinoProibido(t *testing.T) {
	m := novoBMCMock(t)
	c := novoCenarioBMC(t, m, true)
	c.stepUp(t)

	r := m.req("PowerCycle")
	c.exigeCodigo(t, c.envia(t, "/api/bmc/power", r), http.StatusUnprocessableEntity, "acao_invalida")
	r = m.req("On")
	r["host"] = "10.0.0.5/../x"
	c.exigeCodigo(t, c.envia(t, "/api/bmc/power", r), http.StatusUnprocessableEntity, "host_invalido")
	r = m.req("On")
	r["system_id"] = "../../x"
	c.exigeCodigo(t, c.envia(t, "/api/bmc/power", r), http.StatusUnprocessableEntity, "system_id_invalido")
	r = m.req("On")
	delete(r, "senha")
	c.exigeCodigo(t, c.envia(t, "/api/bmc/power", r), http.StatusBadRequest, "credencial_bmc_ausente")
	r = m.req("On")
	r["campo_extra"] = 1
	c.exigeCodigo(t, c.envia(t, "/api/bmc/power", r), http.StatusBadRequest, "requisicao_invalida")

	// política padrão: loopback é recusado (SSRF)
	c.a.c.bmcProibirIP = nil
	rec := c.envia(t, "/api/bmc/status", m.req(""))
	c.exigeCodigo(t, rec, http.StatusUnprocessableEntity, "destino_nao_permitido")
	t.Logf("loopback (política padrão) -> %d %s", rec.Code, strings.TrimSpace(rec.Body.String()))
	if len(m.resets) != 0 {
		t.Fatal("BMC acionado com entrada inválida")
	}
	semSenhaEmLugarNenhum(t, c, "")
}
