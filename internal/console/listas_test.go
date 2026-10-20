package console

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/eduardohenriquemoretti0-ops/fm-rmm/internal/server"
	"github.com/eduardohenriquemoretti0-ops/fm-rmm/internal/sign"
)

const (
	corpoSecreto = "echo SEGREDO-DO-CORPO-12345\n"
	pkgSecreto   = "Mozilla.Firefox.PKG-SENSIVEL"
)

func publicaListasTeste(t *testing.T, st *server.Store) {
	t.Helper()
	pub, raiz, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	raw, sig, _, err := server.ConstruirCatalogoSoftware(raiz, 0, []sign.SoftwareItem{
		{ID: "firefox", Nome: "Mozilla Firefox", Gerenciador: sign.GerenciadorWinget, PkgID: pkgSecreto, Publisher: "Mozilla", Versao: "9.9.9"},
		{ID: "htop", Nome: "htop", Gerenciador: sign.GerenciadorApt, PkgID: "htop"},
	}, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := server.PublicarCatalogoSoftware(st, pub, raw, sig, "teste"); err != nil {
		t.Fatal(err)
	}
	raw, sig, _, err = server.ConstruirBibliotecaScripts(raiz, 0, []sign.ScriptEntry{
		{ID: "limpar-temp", Nome: "Limpar temp", Versao: "1.0.0", Interprete: sign.InterpreteBash, Corpo: corpoSecreto},
	}, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := server.PublicarBibliotecaScripts(st, pub, raw, sig, "teste"); err != nil {
		t.Fatal(err)
	}
}

func (c *cenario) sessaoA(t *testing.T) *http.Cookie {
	t.Helper()
	return c.a.cookieDe(t, "op-a", c.certA)
}

func TestListasPublicadasSemSegredo(t *testing.T) {
	c := novoCenario(t)
	publicaListasTeste(t, c.a.f.st)
	ck := c.sessaoA(t)

	rec := c.get(t, "/api/catalogo-software", c.certA, ck)
	if rec.Code != http.StatusOK {
		t.Fatalf("catalogo: %d %s", rec.Code, rec.Body)
	}
	t.Logf("catalogo-software: %s", rec.Body)
	var cat struct {
		Versao int                 `json:"versao"`
		Itens  []map[string]string `json:"itens"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &cat); err != nil {
		t.Fatal(err)
	}
	if cat.Versao != 1 || len(cat.Itens) != 2 || cat.Itens[0]["id"] != "firefox" ||
		cat.Itens[0]["nome"] != "Mozilla Firefox" || cat.Itens[0]["gerenciador"] != "winget" {
		t.Fatalf("catálogo inesperado: %s", rec.Body)
	}
	for _, it := range cat.Itens {
		if len(it) != 3 {
			t.Errorf("item com campos extras: %v", it)
		}
	}
	for _, proibido := range []string{pkgSecreto, "pkg_id", "sha256", "Mozilla\"", "9.9.9"} {
		if strings.Contains(rec.Body.String(), proibido) {
			t.Errorf("catálogo vazou %q: %s", proibido, rec.Body)
		}
	}

	rec = c.get(t, "/api/biblioteca-scripts", c.certA, ck)
	if rec.Code != http.StatusOK {
		t.Fatalf("biblioteca: %d %s", rec.Code, rec.Body)
	}
	t.Logf("biblioteca-scripts: %s", rec.Body)
	var lib struct {
		Versao  int                 `json:"versao"`
		Scripts []map[string]string `json:"scripts"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &lib); err != nil {
		t.Fatal(err)
	}
	if lib.Versao != 1 || len(lib.Scripts) != 1 || lib.Scripts[0]["id"] != "limpar-temp" ||
		lib.Scripts[0]["versao"] != "1.0.0" || lib.Scripts[0]["interprete"] != "bash" || len(lib.Scripts[0]) != 4 {
		t.Fatalf("biblioteca inesperada: %s", rec.Body)
	}
	// o CORPO (e o hash dele) nunca saem, em nenhuma rota de lista
	hash := sign.HashCorpoScript(corpoSecreto)
	for _, rota := range []string{"/api/biblioteca-scripts", "/api/catalogo-software", "/api/acoes-disponiveis"} {
		b := c.get(t, rota, c.certA, ck).Body.String()
		for _, proibido := range []string{"SEGREDO-DO-CORPO", `"corpo"`, "echo ", hash, "sha256"} {
			if strings.Contains(b, proibido) {
				t.Errorf("%s vazou %q: %s", rota, proibido, b)
			}
		}
	}
}

func TestListasVaziasSemPublicacao(t *testing.T) {
	c := novoCenario(t)
	ck := c.sessaoA(t)
	rec := c.get(t, "/api/catalogo-software", c.certA, ck)
	if rec.Code != http.StatusOK || strings.TrimSpace(rec.Body.String()) != `{"versao":0,"itens":[]}` {
		t.Fatalf("catálogo vazio: %d %s", rec.Code, rec.Body)
	}
	rec = c.get(t, "/api/biblioteca-scripts", c.certA, ck)
	if rec.Code != http.StatusOK || strings.TrimSpace(rec.Body.String()) != `{"versao":0,"scripts":[]}` {
		t.Fatalf("biblioteca vazia: %d %s", rec.Code, rec.Body)
	}
}

type paramJSON struct {
	Nome        string              `json:"nome"`
	Obrigatorio bool                `json:"obrigatorio"`
	Tipo        string              `json:"tipo"`
	Valores     map[string][]string `json:"valores_por_so"`
	Formato     string              `json:"formato"`
}
type acaoJSON struct {
	Nome        string      `json:"nome"`
	Origem      string      `json:"origem"`
	Rota        string      `json:"rota"`
	Destrutiva  bool        `json:"destrutiva"`
	ExigeStepUp bool        `json:"exige_step_up"`
	Params      []paramJSON `json:"params"`
}

func acoesDe(t *testing.T, c *cenario, ck *http.Cookie) map[string]acaoJSON {
	t.Helper()
	rec := c.get(t, "/api/acoes-disponiveis", c.certA, ck)
	if rec.Code != http.StatusOK {
		t.Fatalf("acoes: %d %s", rec.Code, rec.Body)
	}
	var r struct {
		Acoes []acaoJSON `json:"acoes"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &r); err != nil {
		t.Fatal(err)
	}
	m := map[string]acaoJSON{}
	for _, a := range r.Acoes {
		m[a.Nome] = a
	}
	return m
}

func TestAcoesDisponiveisFlagsEParams(t *testing.T) {
	c := novoCenario(t)
	ck := c.sessaoA(t)
	m := acoesDe(t, c, ck)

	for _, n := range []string{"wake_on_lan", "forcar_criptografia", "lock_remoto", "wipe_remoto", "instalar_pacote", "desinstalar_pacote", "rodar_script"} {
		a, ok := m[n]
		if !ok {
			t.Fatalf("ação %s ausente", n)
		}
		if !a.ExigeStepUp || a.Origem != "agente" || a.Rota != "/api/acoes" {
			t.Errorf("%s: %+v", n, a)
		}
		if a.Destrutiva != (n == "wipe_remoto") {
			t.Errorf("%s: destrutiva=%v", n, a.Destrutiva)
		}
	}
	// só escrita: ações de leitura não entram
	for _, n := range []string{"info", "inventario", "hardware", "cripto_status"} {
		if _, ok := m[n]; ok {
			t.Errorf("ação de leitura %s listada", n)
		}
	}
	if _, ok := m["bmc_power"]; ok {
		t.Error("bmc_power listado para técnico sem o grupo bmc")
	}
	tipos := func(n string) map[string]string {
		r := map[string]string{}
		for _, p := range m[n].Params {
			r[p.Nome] = p.Tipo
		}
		return r
	}
	if g := tipos("wake_on_lan"); g["mac"] != "texto" || g["broadcast"] != "texto" {
		t.Errorf("wol: %v", g)
	}
	for _, p := range m["wake_on_lan"].Params {
		if p.Nome == "mac" && !p.Obrigatorio || p.Nome == "broadcast" && p.Obrigatorio {
			t.Errorf("obrigatoriedade wol: %+v", p)
		}
	}
	if g := tipos("wipe_remoto"); g["motivo"] != "lista" || g["confirmacao"] != "confirmacao_destrutiva" {
		t.Errorf("wipe: %v", g)
	}
	for _, p := range m["wipe_remoto"].Params {
		if p.Nome == "motivo" && strings.Join(p.Valores["linux"], ",") != "perda,roubo" {
			t.Errorf("motivo: %+v", p)
		}
		if p.Nome == "confirmacao" && p.Formato != "WIPE-{agent_id}" {
			t.Errorf("confirmacao: %+v", p)
		}
	}
	if g := tipos("instalar_pacote"); g["item_id"] != "item_catalogo_software" {
		t.Errorf("instalar: %v", g)
	}
	if g := tipos("rodar_script"); g["script_id"] != "script_biblioteca_id" || g["versao"] != "script_biblioteca_versao" {
		t.Errorf("rodar_script: %v", g)
	}
}

func TestAcoesDisponiveisBMCSoComGrupo(t *testing.T) {
	c := novoCenario(t)
	if err := c.a.f.st.GrantGroup("tA", GrupoBMC); err != nil {
		t.Fatal(err)
	}
	m := acoesDe(t, c, c.sessaoA(t))
	b, ok := m["bmc_power"]
	if !ok || b.Origem != "bmc" || b.Rota != "/api/bmc/power" || !b.ExigeStepUp || b.Destrutiva {
		t.Fatalf("bmc_power: %+v", b)
	}
}

func TestListasExigemCertESessao(t *testing.T) {
	c := novoCenario(t)
	ck := c.sessaoA(t)
	for _, rota := range []string{"/api/catalogo-software", "/api/biblioteca-scripts", "/api/acoes-disponiveis"} {
		// sem sessão
		if rec := c.get(t, rota, c.certA, nil); rec.Code != http.StatusUnauthorized {
			t.Errorf("%s sem sessão: %d", rota, rec.Code)
		}
		// sem cert (TLS sem certificado de cliente)
		r := reqTLS(http.MethodGet, rota, nil, c.certA)
		r.TLS.PeerCertificates = nil
		r.AddCookie(ck)
		rec := httptest.NewRecorder()
		c.a.c.Roteador().ServeHTTP(rec, r)
		if rec.Code != http.StatusUnauthorized {
			t.Errorf("%s sem cert: %d", rota, rec.Code)
		}
		// cert de outro operador com o cookie de op-a (token de outro cliente)
		if rec := c.get(t, rota, c.certB, ck); rec.Code != http.StatusUnauthorized {
			t.Errorf("%s cert trocado: %d", rota, rec.Code)
		}
		// sanidade: com tudo, 200
		if rec := c.get(t, rota, c.certA, ck); rec.Code != http.StatusOK {
			t.Errorf("%s ok esperado: %d", rota, rec.Code)
		}
	}
}

func TestListasAuditadas(t *testing.T) {
	c := novoCenario(t)
	ck := c.sessaoA(t)
	for _, rota := range []string{"/api/catalogo-software", "/api/biblioteca-scripts", "/api/acoes-disponiveis"} {
		c.get(t, rota, c.certA, ck)
	}
	es, err := c.a.f.st.AuditEntries()
	if err != nil {
		t.Fatal(err)
	}
	vistos := map[string]bool{}
	for _, e := range es {
		if e.Actor == "op-a" {
			vistos[e.Event] = true
		}
	}
	for _, ev := range []string{"console.lista.catalogo_software", "console.lista.biblioteca_scripts", "console.lista.acoes_disponiveis"} {
		if !vistos[ev] {
			t.Errorf("evento %s não auditado", ev)
		}
	}
}
