package server

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// nvdFalso simula a NVD API 2.0 (NUNCA a real). Devolve sempre os MESMOS CVEs do
// Chrome, independentemente da versão pedida — assim o teste prova que o filtro de
// faixa roda no cliente. Registra o header apiKey e o virtualMatchString.
type nvdMock struct {
	srv   *httptest.Server
	reqs  atomic.Int32
	mu    sync.Mutex
	keys  []string
	cpes  []string
	falha atomic.Bool
}

const nvdChromeJSON = `{"resultsPerPage":3,"startIndex":0,"totalResults":3,"vulnerabilities":[
 {"cve":{"id":"CVE-2099-0001","vulnStatus":"Analyzed",
  "metrics":{"cvssMetricV31":[{"type":"Primary","cvssData":{"baseScore":9.8,"baseSeverity":"CRITICAL"}}]},
  "configurations":[{"nodes":[{"cpeMatch":[
    {"vulnerable":true,"criteria":"cpe:2.3:a:google:chrome:*:*:*:*:*:*:*:*","versionEndExcluding":"121.0.6167.85"}]}]}]}},
 {"cve":{"id":"CVE-2099-0002","vulnStatus":"Analyzed",
  "metrics":{"cvssMetricV31":[{"type":"Primary","cvssData":{"baseScore":7.5,"baseSeverity":"HIGH"}}]},
  "configurations":[{"nodes":[{"cpeMatch":[
    {"vulnerable":true,"criteria":"cpe:2.3:a:google:chrome:*:*:*:*:*:*:*:*","versionStartIncluding":"130.0.0.0","versionEndExcluding":"131.0.0.0"}]}]}]}},
 {"cve":{"id":"CVE-2099-0003","vulnStatus":"Analyzed",
  "metrics":{"cvssMetricV2":[{"type":"Primary","cvssData":{"baseScore":5.0}}]},
  "configurations":[{"nodes":[{"cpeMatch":[
    {"vulnerable":true,"criteria":"cpe:2.3:a:google:chrome:*:*:*:*:*:*:*:*","versionStartExcluding":"119.0.0.0","versionEndIncluding":"120.0.6099.109"},
    {"vulnerable":true,"criteria":"cpe:2.3:a:outro:produto:*:*:*:*:*:*:*:*","versionEndExcluding":"999"}]}]}]}}
]}`

func novoNVDMock(t *testing.T) *nvdMock {
	t.Helper()
	m := &nvdMock{}
	m.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		m.reqs.Add(1)
		m.mu.Lock()
		m.keys = append(m.keys, r.Header.Get("apiKey"))
		m.cpes = append(m.cpes, r.URL.Query().Get("virtualMatchString"))
		m.mu.Unlock()
		if m.falha.Load() {
			http.Error(w, "indisponivel", 503)
			return
		}
		if r.URL.Path != "/rest/json/cves/2.0" {
			http.NotFound(w, r)
			return
		}
		if strings.Contains(r.URL.Query().Get("virtualMatchString"), ":google:chrome:") {
			_, _ = w.Write([]byte(nvdChromeJSON))
			return
		}
		_, _ = w.Write([]byte(`{"resultsPerPage":0,"startIndex":0,"totalResults":0,"vulnerabilities":[]}`))
	}))
	t.Cleanup(m.srv.Close)
	return m
}

func engineNVD(st *Store, m *nvdMock, chave string) (*Engine, *[]time.Duration) {
	var esperas []time.Duration
	n := &NVD{St: st, Base: m.srv.URL, APIKey: chave, Espera: func(d time.Duration) { esperas = append(esperas, d) }}
	return &Engine{St: st, CPE: n, Espera: func(time.Duration) {}}, &esperas
}

func inv(versaoChrome string) string {
	return `[{"nome":"Google Chrome","versao":"` + versaoChrome + `","fabricante":"Google"},` +
		`{"nome":"Notepad++","versao":"8.6","fabricante":"x"},` +
		`{"nome":"Microsoft .NET Framework 4.8","versao":"4.8.1","fabricante":"MS"}]`
}

func TestNVDChromeVulneravel(t *testing.T) {
	st := novoStoreCVE(t)
	m := novoNVDMock(t)
	agenteComInventario(t, st, "w1", "windows", inv("120.0.6099.109"))
	e, _ := engineNVD(st, m, "")
	r, err := e.Scan(context.Background(), "w1")
	if err != nil {
		t.Fatal(err)
	}
	if r.Resumo.Erro != "" || r.Resumo.Avaliados != 1 || r.Resumo.NaoAvaliados != 2 || len(r.Achados) != 2 {
		t.Fatalf("resumo: %+v achados=%+v", r.Resumo, r.Achados)
	}
	// 0001: end excluding 121.0.6167.85 casa; 0002: start 130 NÃO casa; 0003: (119, 120.0.6099.109] casa (incl. no limite)
	porID := map[string]Achado{}
	for _, a := range r.Achados {
		porID[a.CVEID] = a
	}
	a1, ok := porID["CVE-2099-0001"]
	if !ok || a1.Fonte != "nvd" || a1.Severidade != "CRITICAL" || a1.Pontuacao != 9.8 || a1.FixedVersion != "121.0.6167.85" || a1.Pacote != "Google Chrome" {
		t.Errorf("0001: %+v", a1)
	}
	if _, ok := porID["CVE-2099-0002"]; ok {
		t.Error("faixa start=130 não pode casar com 120")
	}
	a3 := porID["CVE-2099-0003"]
	if a3.Severidade != "MEDIUM" || a3.FixedVersion != "" {
		t.Errorf("0003 (CVSS v2): %+v", a3)
	}
	// consulta enviada: CPE com a versão
	if len(m.cpes) != 1 || m.cpes[0] != "cpe:2.3:a:google:chrome:120.0.6099.109:*:*:*:*:*:*:*" {
		t.Errorf("cpe consultada: %v", m.cpes)
	}
	// produtos sem CPE curada / não avaliáveis seguem como não avaliados, com motivo
	st2, _ := st.ResumoVulns("w1")
	if st2.Fonte != "osv.dev+nvd" || st2.Total != 2 || st2.PorSeveridade["CRITICAL"] != 1 {
		t.Errorf("resumo store: %+v", st2)
	}
	b, _ := json.MarshalIndent(st2, "", "  ")
	t.Logf("RESUMO JSON:\n%s", b)
	var motivos []string
	rs, _, _ := st.UltimoScan("w1")
	for _, n := range rs.NaoAvaliadosRisco {
		motivos = append(motivos, n.Pacote+": "+n.Motivo)
	}
	if len(rs.NaoAvaliadosRisco) != 1 || !strings.Contains(motivos[0], ".NET Framework") {
		t.Errorf("alto risco: %v", motivos)
	}
	// cache 24h: segundo scan não vai à rede
	if _, err := e.Scan(context.Background(), "w1"); err != nil {
		t.Fatal(err)
	}
	if m.reqs.Load() != 1 {
		t.Errorf("cache falhou: %d requisições", m.reqs.Load())
	}
}

func TestNVDSemCPECuradaENaoAvaliado(t *testing.T) {
	st := novoStoreCVE(t)
	m := novoNVDMock(t)
	agenteComInventario(t, st, "w1", "windows", `[{"nome":"Notepad++","versao":"8.6","fabricante":"x"}]`)
	e, _ := engineNVD(st, m, "")
	r, _ := e.Scan(context.Background(), "w1")
	if m.reqs.Load() != 0 || r.Resumo.Avaliados != 0 || r.Resumo.NaoAvaliados != 1 {
		t.Errorf("req=%d %+v", m.reqs.Load(), r.Resumo)
	}
	// o motivo propagado ao Engine
	res, _ := e.CPE.Avaliar(context.Background(), "windows", []Item{{Nome: "Notepad++", Versao: "8.6"}})
	if len(res.NaoAvaliados) != 1 || !strings.Contains(res.NaoAvaliados[0].Motivo, "sem CPE curada") {
		t.Errorf("%+v", res)
	}
}

func TestNVDVersaoCorrigidaSemAchado(t *testing.T) {
	st := novoStoreCVE(t)
	m := novoNVDMock(t)
	agenteComInventario(t, st, "w1", "windows", `[{"nome":"Google Chrome","versao":"121.0.6167.85","fabricante":"Google"}]`)
	e, _ := engineNVD(st, m, "")
	r, err := e.Scan(context.Background(), "w1")
	if err != nil {
		t.Fatal(err)
	}
	// 121.0.6167.85 == versionEndExcluding (corrigida); 0002 começa em 130; 0003 acaba em 120.0.6099.109
	if len(r.Achados) != 0 || r.Resumo.Avaliados != 1 || r.Resumo.NaoAvaliados != 0 {
		t.Errorf("%+v %+v", r.Resumo, r.Achados)
	}
	// dentro da faixa start..end de 0002
	agenteComInventario(t, st, "w2", "windows", `[{"nome":"Google Chrome","versao":"130.5.0.0","fabricante":"Google"}]`)
	r, _ = e.Scan(context.Background(), "w2")
	if len(r.Achados) != 1 || r.Achados[0].CVEID != "CVE-2099-0002" || r.Achados[0].FixedVersion != "131.0.0.0" {
		t.Errorf("faixa: %+v", r.Achados)
	}
}

func TestNVDErroDeRedeFailSoft(t *testing.T) {
	st := novoStoreCVE(t)
	m := novoNVDMock(t)
	agenteComInventario(t, st, "w1", "windows", inv("120.0.6099.109"))
	e, _ := engineNVD(st, m, "")
	if _, err := e.Scan(context.Background(), "w1"); err != nil {
		t.Fatal(err)
	}
	m.falha.Store(true)
	if _, err := st.db.Exec(`UPDATE osv_cache SET em=0`); err != nil {
		t.Fatal(err)
	}
	antes := m.reqs.Load()
	r, err := e.Scan(context.Background(), "w1")
	if err != nil {
		t.Fatalf("erro de rede derrubou o scan: %v", err)
	}
	if m.reqs.Load()-antes != nvdTentativas {
		t.Errorf("tentativas = %d", m.reqs.Load()-antes)
	}
	if !strings.Contains(r.Resumo.Erro, "cpe: nvd") {
		t.Errorf("erro não registrado: %q", r.Resumo.Erro)
	}
	res, _ := st.ResumoVulns("w1")
	if res.Total != 2 || res.Erro == "" {
		t.Errorf("achados antigos devem ser preservados: %+v", res)
	}
	var nvdIndisp bool
	for _, n := range res.NaoAvaliadosAltoRisco {
		nvdIndisp = nvdIndisp || (n.Pacote == "Google Chrome" && strings.Contains(n.Motivo, "NVD indisponível"))
	}
	if !nvdIndisp {
		t.Errorf("Chrome deve voltar como não avaliado (NVD indisponível): %+v", res.NaoAvaliadosAltoRisco)
	}
	// servidor fora do ar de vez (conexão recusada)
	m.srv.Close()
	if _, err := e.Scan(context.Background(), "w1"); err != nil {
		t.Fatalf("conexão recusada derrubou o scan: %v", err)
	}
	if res, _ = st.ResumoVulns("w1"); res.Total != 2 {
		t.Errorf("preservar achados: %+v", res)
	}
}

func TestNVDChaveEEspacamento(t *testing.T) {
	st := novoStoreCVE(t)
	m := novoNVDMock(t)
	itens := []Item{{Nome: "Google Chrome", Versao: "120.0.1.0"}, {Nome: "Microsoft Edge", Versao: "120.0.1.0"}}

	t.Setenv(EnvNVDKey, "chave-secreta-teste")
	n := NovaFonteNVD(st)
	n.Base, n.Espera = m.srv.URL, func(d time.Duration) { _ = d }
	var esperas []time.Duration
	n.Espera = func(d time.Duration) { esperas = append(esperas, d) }
	if _, err := n.Avaliar(context.Background(), "windows", itens); err != nil {
		t.Fatal(err)
	}
	for _, k := range m.keys {
		if k != "chave-secreta-teste" {
			t.Errorf("header apiKey = %q", k)
		}
	}
	if len(m.keys) != 2 || len(esperas) != 1 || esperas[0] > nvdIntervaloComChave || esperas[0] < nvdIntervaloComChave/2 {
		t.Errorf("com chave: keys=%v esperas=%v", m.keys, esperas)
	}

	// sem chave: nenhum header e espaçamento >= 5 req/30s (6s)
	t.Setenv(EnvNVDKey, "")
	m.keys, m.cpes = nil, nil
	n2 := NovaFonteNVD(st)
	n2.Base = m.srv.URL
	esperas = nil
	n2.Espera = func(d time.Duration) { esperas = append(esperas, d) }
	if _, err := n2.Avaliar(context.Background(), "windows", []Item{{Nome: "Google Chrome", Versao: "119.0.0.1"}, {Nome: "Microsoft Edge", Versao: "119.0.0.1"}}); err != nil {
		t.Fatal(err)
	}
	for _, k := range m.keys {
		if k != "" {
			t.Errorf("sem chave não deve enviar apiKey: %q", k)
		}
	}
	if len(esperas) != 1 || esperas[0] < 5*time.Second {
		t.Errorf("keyless deve espaçar >=5s: %v", esperas)
	}
}

func TestMapearCPETabela(t *testing.T) {
	casos := []struct {
		nome, versao, vendor, prod, ver string
		motivo                          bool
		curado                          bool
	}{
		{"Google Chrome", "120.0.6099.109", "google", "chrome", "120.0.6099.109", false, true},
		{"Microsoft Edge", "120.0.2210.91", "microsoft", "edge_chromium", "120.0.2210.91", false, true},
		{"Microsoft Edge Update", "1.3.1", "", "", "", false, false},
		{"Mozilla Firefox (x64 pt-BR)", "120.0", "mozilla", "firefox", "120.0", false, true},
		{"Mozilla Firefox ESR (x64 en-US)", "115.5.0", "mozilla", "firefox_esr", "115.5.0", false, true},
		{"Java 8 Update 391 (64-bit)", "8.0.3910.11", "oracle", "jre", "1.8.0.391", false, true},
		{"Java(TM) SE Development Kit 17.0.9 (64-bit)", "17.0.9.0", "oracle", "jdk", "17.0.9", false, true},
		{"Eclipse Temurin JDK with Hotspot 17.0.9+9 (x64)", "17.0.9.9", "oracle", "jdk", "17.0.9", false, true},
		{"Microsoft .NET Runtime - 8.0.0 (x64)", "64.0.1", "microsoft", ".net", "8.0.0", false, true},
		{"Microsoft .NET Framework 4.8", "4.8.1", "", "", "", true, true},
		{"Node.js", "20.10.0", "nodejs", "node.js", "20.10.0", false, true},
		{"Python 3.12.1 (64-bit)", "3.12.1150.0", "python", "python", "3.12.1", false, true},
		{"Python 3.12.1 Standard Library (64-bit)", "3.12.1150.0", "", "", "", true, true},
		{"7-Zip 23.01 (x64 edition)", "23.01", "7-zip", "7-zip", "23.01", false, true},
		{"Adobe Acrobat (64-bit)", "23.008.20470", "adobe", "acrobat_dc", "23.008.20470", false, true},
		{"Adobe Acrobat Reader DC", "23.008.20470", "adobe", "acrobat_reader_dc", "23.008.20470", false, true},
		{"Google Chrome", "?", "", "", "", true, true},
		{"Notepad++", "8.6", "", "", "", false, false},
	}
	for _, c := range casos {
		a, curado, motivo := mapearCPE(Item{Nome: c.nome, Versao: c.versao})
		if curado != c.curado || (motivo != "") != c.motivo || a.Vendor != c.vendor || a.Product != c.prod || a.Versao != c.ver {
			t.Errorf("%q: %+v curado=%v motivo=%q", c.nome, a, curado, motivo)
		}
	}
}

func TestCasaVersaoExataCPE(t *testing.T) {
	a := alvoCPE{"oracle", "jre", "1.8.0.391"}
	ok, _ := casaVersao(nvdMatch{Vulnerable: true, Criteria: "cpe:2.3:a:oracle:jre:1.8.0:update391:*:*:*:*:*:*"}, a)
	nok, _ := casaVersao(nvdMatch{Vulnerable: true, Criteria: "cpe:2.3:a:oracle:jre:1.8.0:update381:*:*:*:*:*:*"}, a)
	nv, _ := casaVersao(nvdMatch{Vulnerable: false, Criteria: "cpe:2.3:a:oracle:jre:1.8.0:update391:*:*:*:*:*:*"}, a)
	if !ok || nok || nv {
		t.Errorf("exata: %v %v %v", ok, nok, nv)
	}
}
