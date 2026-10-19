package console

import (
	"context"
	"crypto/x509"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sort"
	"strings"
	"testing"
	"time"
	"unicode/utf8"

	"github.com/eduardohenriquemoretti0-ops/fm-rmm/internal/audit"
	"github.com/eduardohenriquemoretti0-ops/fm-rmm/internal/pki"
	"github.com/eduardohenriquemoretti0-ops/fm-rmm/internal/proto"
	"github.com/eduardohenriquemoretti0-ops/fm-rmm/internal/server"
)

// operadorComTech cria operador ATIVO ligado a um técnico (o RBAC é o do técnico),
// com chave WebAuthn registrada e o cert informado.
func (a *ambiente) operadorComTech(t *testing.T, id, tech string, cert *x509.Certificate) {
	t.Helper()
	k := novoAutSoft(t)
	if err := a.f.st.CreateOperator(server.Operator{
		ID: id, Nome: id, TechName: tech, Status: "pendente", CertThumbprint: CertThumbprint(cert),
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := a.f.registra(t, id, k, 0x45); err != nil {
		t.Fatalf("registro %s: %v", id, err)
	}
	if err := a.f.st.SetOperatorStatus(id, "ativo"); err != nil {
		t.Fatal(err)
	}
}

// cookieDe abre uma sessão para o operador e devolve o cookie (como o login faria).
func (a *ambiente) cookieDe(t *testing.T, id string, cert *x509.Certificate) *http.Cookie {
	t.Helper()
	raw, _, err := a.f.sm.New(id, CertThumbprint(cert))
	if err != nil {
		t.Fatal(err)
	}
	return SessionCookie(NomeCookieSessao, raw, time.Minute)
}

// criaAgente enrola e aprova um agente no grupo informado. visto=true simula
// check-in agora (Online); false deixa nunca visto.
func (a *ambiente) criaAgente(t *testing.T, hostname, grp string, visto bool) string {
	t.Helper()
	st := a.f.st
	_, csrPEM, err := pki.NewAgentKeyAndCSR(hostname)
	if err != nil {
		t.Fatal(err)
	}
	_, token, err := st.NewToken("teste", 10, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	id, _, err := st.Enroll(token, hostname, "linux", csrPEM, "10.0.0.9")
	if err != nil {
		t.Fatal(err)
	}
	if err := st.Approve(id, "cert", "1", 0); err != nil {
		t.Fatal(err)
	}
	if err := st.SetAgentGroup(id, grp); err != nil {
		t.Fatal(err)
	}
	if visto {
		if err := st.Seen(id, "{}", "linux"); err != nil {
			t.Fatal(err)
		}
	}
	return id
}

// cenario monta: técnico tA com grupo gA, técnico tB com grupo gB, operadores
// op-a (tA) e op-b (tB), e agentes em cada grupo. Devolve os certs dos operadores.
type cenario struct {
	a            *ambiente
	certA, certB *x509.Certificate
	ag1, ag2     string // ag1 em gA (visto), ag2 em gB (visto)
	ag3          string // ag3 em gA (nunca visto)
}

func novoCenario(t *testing.T) *cenario {
	t.Helper()
	a := novoAmbiente(t)
	st := a.f.st
	for _, g := range []struct{ tech, grp string }{{"tA", "gA"}, {"tB", "gB"}} {
		if err := st.AddTech(g.tech); err != nil {
			t.Fatal(err)
		}
		if err := st.GrantGroup(g.tech, g.grp); err != nil {
			t.Fatal(err)
		}
	}
	certA, _ := certDe(t, a.ca, a.caK, "op-a")
	certB, _ := certDe(t, a.ca, a.caK, "op-b")
	a.operadorComTech(t, "op-a", "tA", certA)
	a.operadorComTech(t, "op-b", "tB", certB)
	c := &cenario{a: a, certA: certA, certB: certB}
	c.ag1 = a.criaAgente(t, "pc-a1", "gA", true)
	c.ag2 = a.criaAgente(t, "pc-b1", "gB", true)
	c.ag3 = a.criaAgente(t, "pc-a2", "gA", false)
	return c
}

// get faz GET autenticado (cert + cookie) pelo roteador completo.
func (c *cenario) get(t *testing.T, alvo string, cert *x509.Certificate, ck *http.Cookie) *httptest.ResponseRecorder {
	t.Helper()
	r := reqTLS(http.MethodGet, alvo, nil, cert)
	if ck != nil {
		r.AddCookie(ck)
	}
	rec := httptest.NewRecorder()
	c.a.c.Roteador().ServeHTTP(rec, r)
	return rec
}

// idsDaLista extrai os ids de /api/agentes, ordenados.
func idsDaLista(t *testing.T, body string) []string {
	t.Helper()
	var resp struct {
		Agentes []map[string]any `json:"agentes"`
	}
	if err := json.Unmarshal([]byte(body), &resp); err != nil {
		t.Fatalf("JSON da lista inválido: %v: %s", err, body)
	}
	var ids []string
	for _, a := range resp.Agentes {
		ids = append(ids, a["id"].(string))
	}
	sort.Strings(ids)
	return ids
}

// (1) RBAC na lista: operador do grupo A vê só A; do B vê só B; técnico desabilitado não vê nada.
func TestListaFiltradaPorRBAC(t *testing.T) {
	c := novoCenario(t)
	ckA := c.a.cookieDe(t, "op-a", c.certA)
	ckB := c.a.cookieDe(t, "op-b", c.certB)

	rec := c.get(t, "/api/agentes", c.certA, ckA)
	if rec.Code != http.StatusOK {
		t.Fatalf("op-a lista = %d: %s", rec.Code, rec.Body.String())
	}
	quer := []string{c.ag1, c.ag3}
	sort.Strings(quer)
	if got := idsDaLista(t, rec.Body.String()); strings.Join(got, ",") != strings.Join(quer, ",") {
		t.Errorf("op-a (gA) viu %v, quer %v", got, quer)
	}
	if strings.Contains(rec.Body.String(), c.ag2) {
		t.Error("op-a (gA) recebeu agente do grupo B no corpo")
	}

	rec = c.get(t, "/api/agentes", c.certB, ckB)
	if got := idsDaLista(t, rec.Body.String()); len(got) != 1 || got[0] != c.ag2 {
		t.Errorf("op-b (gB) viu %v, quer [%s]", got, c.ag2)
	}

	if err := c.a.f.st.DisableTech("tA", true); err != nil {
		t.Fatal(err)
	}
	rec = c.get(t, "/api/agentes", c.certA, ckA)
	if rec.Code != http.StatusOK {
		t.Fatalf("técnico desabilitado: lista = %d", rec.Code)
	}
	if got := idsDaLista(t, rec.Body.String()); len(got) != 0 {
		t.Errorf("técnico desabilitado viu %v, quer lista vazia", got)
	}
}

// (2) IDOR no detalhe: agente de outro grupo = 404 IGUAL ao de agente inexistente.
func TestDetalheForaDoGrupoEhNotFound(t *testing.T) {
	c := novoCenario(t)
	ckA := c.a.cookieDe(t, "op-a", c.certA)

	fora := c.get(t, "/api/agentes/"+c.ag2, c.certA, ckA)
	inexistente := c.get(t, "/api/agentes/ag-nao-existe", c.certA, ckA)
	if fora.Code != http.StatusNotFound {
		t.Fatalf("agente de outro grupo = %d, quer 404", fora.Code)
	}
	if inexistente.Code != http.StatusNotFound {
		t.Fatalf("agente inexistente = %d, quer 404", inexistente.Code)
	}
	if fora.Body.String() != inexistente.Body.String() {
		t.Errorf("respostas diferem (vaza existência):\nfora=%q\ninex=%q", fora.Body.String(), inexistente.Body.String())
	}
	if strings.Contains(fora.Body.String(), c.ag2) {
		t.Error("404 ecoa o id do agente")
	}

	// dono do grupo vê normalmente
	ok := c.get(t, "/api/agentes/"+c.ag1, c.certA, ckA)
	if ok.Code != http.StatusOK {
		t.Fatalf("agente do próprio grupo = %d: %s", ok.Code, ok.Body.String())
	}
}

// (3) shape JSON da lista: exatamente os campos pedidos, tipos certos.
func TestShapeJSONDaLista(t *testing.T) {
	c := novoCenario(t)
	ck := c.a.cookieDe(t, "op-a", c.certA)
	rec := c.get(t, "/api/agentes", c.certA, ck)

	var resp struct {
		Agentes []map[string]any `json:"agentes"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatal(err)
	}
	chaves := []string{"id", "hostname", "os", "status", "grupo", "online", "ultimo_contato"}
	porID := map[string]map[string]any{}
	for _, a := range resp.Agentes {
		if len(a) != len(chaves) {
			t.Errorf("agente com %d campos, quer %d: %v", len(a), len(chaves), a)
		}
		for _, k := range chaves {
			if _, ok := a[k]; !ok {
				t.Errorf("campo %q ausente: %v", k, a)
			}
		}
		porID[a["id"].(string)] = a
	}

	visto := porID[c.ag1]
	if visto["online"] != true || visto["grupo"] != "gA" || visto["os"] != "linux" || visto["hostname"] != "pc-a1" {
		t.Errorf("agente visto = %v", visto)
	}
	ts, ok := visto["ultimo_contato"].(string)
	if !ok {
		t.Fatalf("ultimo_contato do agente visto não é string: %v", visto["ultimo_contato"])
	}
	if _, err := time.Parse(time.RFC3339, ts); err != nil {
		t.Errorf("ultimo_contato não é RFC3339: %q", ts)
	}
	nunca := porID[c.ag3]
	if nunca["online"] != false || nunca["ultimo_contato"] != nil {
		t.Errorf("agente nunca visto = %v, quer online=false e ultimo_contato=null", nunca)
	}
}

// (4) detalhe traz os últimos resultados de LEITURA finalizados do próprio agente;
// ação que altera a máquina, job ainda na fila e job de outro agente ficam de fora.
func TestDetalheTrazResultadosDeLeitura(t *testing.T) {
	c := novoCenario(t)
	st := c.a.f.st
	ctx := context.Background()
	expira := time.Now().Add(time.Hour).Unix()

	// job de leitura finalizado (deve aparecer)
	saida, _ := json.Marshal(proto.Result{JobID: "job-h1", Status: "ok", ExitCode: 0, Output: `{"cpu":"x86"}`})
	if err := st.AddJob(server.Job{ID: "job-h1", AgentID: c.ag1, Action: "hardware", Params: "{}", Signed: "{}", Issuer: "adm", ExpiresAt: expira}); err != nil {
		t.Fatal(err)
	}
	if _, err := st.TakeQueued(ctx, c.ag1); err != nil {
		t.Fatal(err)
	}
	if err := st.FinishJob(c.ag1, "job-h1", "ok", string(saida)); err != nil {
		t.Fatal(err)
	}

	// ação que ALTERA a máquina finalizada (não pode aparecer como resultado de leitura)
	if err := st.AddJob(server.Job{ID: "job-rs", AgentID: c.ag1, Action: "reiniciar_servico", Params: "{}", Signed: "{}", Issuer: "adm", ExpiresAt: expira}); err != nil {
		t.Fatal(err)
	}
	if _, err := st.TakeQueued(ctx, c.ag1); err != nil {
		t.Fatal(err)
	}
	if err := st.FinishJob(c.ag1, "job-rs", "ok", `{"job_id":"job-rs","status":"ok"}`); err != nil {
		t.Fatal(err)
	}

	// job de leitura ainda na fila (não finalizado): fora
	if err := st.AddJob(server.Job{ID: "job-fila", AgentID: c.ag1, Action: "saude", Params: "{}", Signed: "{}", Issuer: "adm", ExpiresAt: expira}); err != nil {
		t.Fatal(err)
	}

	// job de leitura de OUTRO agente: fora
	saida2, _ := json.Marshal(proto.Result{JobID: "job-b", Status: "ok", Output: "vazamento"})
	if err := st.AddJob(server.Job{ID: "job-b", AgentID: c.ag2, Action: "hardware", Params: "{}", Signed: "{}", Issuer: "adm", ExpiresAt: expira}); err != nil {
		t.Fatal(err)
	}
	if _, err := st.TakeQueued(ctx, c.ag2); err != nil {
		t.Fatal(err)
	}
	if err := st.FinishJob(c.ag2, "job-b", "ok", string(saida2)); err != nil {
		t.Fatal(err)
	}

	ck := c.a.cookieDe(t, "op-a", c.certA)
	rec := c.get(t, "/api/agentes/"+c.ag1, c.certA, ck)
	if rec.Code != http.StatusOK {
		t.Fatalf("detalhe = %d: %s", rec.Code, rec.Body.String())
	}
	var det struct {
		ID         string `json:"id"`
		Resultados []struct {
			Job         string `json:"job"`
			Acao        string `json:"acao"`
			Status      string `json:"status"`
			CodigoSaida int    `json:"codigo_saida"`
			Saida       string `json:"saida"`
			SaidaTrunc  bool   `json:"saida_truncada"`
			TerminadoEm string `json:"terminado_em"`
		} `json:"resultados"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &det); err != nil {
		t.Fatal(err)
	}
	if det.ID != c.ag1 {
		t.Errorf("id = %q, quer %q", det.ID, c.ag1)
	}
	if len(det.Resultados) != 1 {
		t.Fatalf("resultados = %d, quer 1 (só o hardware finalizado): %s", len(det.Resultados), rec.Body.String())
	}
	r := det.Resultados[0]
	if r.Job != "job-h1" || r.Acao != "hardware" || r.Status != "ok" || r.Saida != `{"cpu":"x86"}` || r.SaidaTrunc {
		t.Errorf("resultado = %+v", r)
	}
	if _, err := time.Parse(time.RFC3339, r.TerminadoEm); err != nil {
		t.Errorf("terminado_em inválido: %q", r.TerminadoEm)
	}
	if strings.Contains(rec.Body.String(), "vazamento") {
		t.Error("resultado de outro agente vazou no detalhe")
	}
}

// (5) a saída é truncada sem quebrar UTF-8 e marca saida_truncada.
func TestTruncaSaidaRespeitaUTF8(t *testing.T) {
	entrada := strings.Repeat("á", 20000) // 2 bytes por caractere
	saida, cortou := truncaSaida(entrada, limiteSaida)
	if !cortou {
		t.Fatal("não marcou truncamento")
	}
	if len(saida) > limiteSaida {
		t.Errorf("tamanho %d acima do limite %d", len(saida), limiteSaida)
	}
	if !utf8.ValidString(saida) {
		t.Error("corte quebrou caractere UTF-8")
	}
	if s, c := truncaSaida("curto", limiteSaida); c || s != "curto" {
		t.Errorf("texto curto alterado: %q, %v", s, c)
	}
}

// (6) toda leitura entra na auditoria encadeada, e a cadeia continua íntegra.
func TestLeiturasEntramNaAuditoria(t *testing.T) {
	c := novoCenario(t)
	ck := c.a.cookieDe(t, "op-a", c.certA)
	c.get(t, "/api/agentes", c.certA, ck)
	c.get(t, "/api/agentes/"+c.ag1, c.certA, ck)
	c.get(t, "/api/agentes/"+c.ag2, c.certA, ck) // negada: também fica registrada

	entradas, err := c.a.f.st.AuditEntries()
	if err != nil {
		t.Fatal(err)
	}
	if err := audit.Verify(entradas); err != nil {
		t.Fatalf("cadeia de auditoria quebrada: %v", err)
	}
	achou := map[string]int{}
	for _, e := range entradas {
		if e.Actor != "op-a" {
			continue
		}
		achou[e.Event]++
		if e.Event == "console.agente.consultado" && strings.Contains(string(e.Data), `"permitido":false`) {
			achou["negada"]++
		}
	}
	for _, ev := range []string{"console.agentes.listados", "console.agente.consultado", "negada"} {
		if achou[ev] == 0 {
			t.Errorf("evento %q não encontrado na auditoria de op-a (achou %v)", ev, achou)
		}
	}
}

// Sem sessão, a leitura é recusada (401), mesmo com cert válido.
func TestLeituraSemSessaoRecusada(t *testing.T) {
	c := novoCenario(t)
	rec := c.get(t, "/api/agentes", c.certA, nil)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("lista sem sessão = %d, quer 401", rec.Code)
	}
}
