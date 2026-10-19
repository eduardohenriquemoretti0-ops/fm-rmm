package server

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

// Fonte CPE/NVD (T3b) — DEFENSIVO, read-only. Cobre apps Windows/macOS que o OSV
// não indexa, SOMENTE para produtos de TABELA CURADA (produtos abaixo): o nome de
// exibição do inventário é mapeado para vendor:product CPE de forma explícita e a
// versão é extraída de forma conservadora. Sem CPE curada => "não avaliado" (nunca
// match por string solta). Detalhes e limitações: docs/cve-osv.md.

const (
	FonteNVD = "nvd"

	// EnvNVDKey é a variável de ambiente com a chave opcional da NVD API 2.0.
	EnvNVDKey = "FMRMM_NVD_API_KEY"

	nvdBaseURL       = "https://services.nvd.nist.gov"
	nvdCaminho       = "/rest/json/cves/2.0"
	nvdPorPagina     = 2000
	nvdPaginasMax    = 10
	nvdCorpoMax      = 64 << 20
	nvdTentativas    = 3
	nvdTimeoutPadrao = 60 * time.Second
	ttlConsultaNVD   = 24 * time.Hour
	// Limites públicos da NVD: 5 req/30s sem chave, 50 req/30s com chave. O
	// espaçamento fica um pouco acima do mínimo para não encostar no limite.
	nvdIntervaloSemChave = 6500 * time.Millisecond
	nvdIntervaloComChave = 700 * time.Millisecond
)

// ------------------------------------------------------------ tabela curada

// alvoCPE é o resultado do mapeamento curado de um item do inventário.
type alvoCPE struct {
	Vendor, Product string
	Versao          string // versão normalizada para comparar com a NVD
}

func (a alvoCPE) cpe() string {
	return "cpe:2.3:a:" + a.Vendor + ":" + a.Product
}

var (
	reJava8     = regexp.MustCompile(`^java(?:\(tm\))? (\d+) update (\d+)`)
	reJDK8      = regexp.MustCompile(`development kit (\d+) update (\d+)`)
	reJDKN      = regexp.MustCompile(`development kit (\d+(?:\.\d+){1,2})`)
	reDotNet    = regexp.MustCompile(`(\d+\.\d+\.\d+)`)
	rePython    = regexp.MustCompile(`^python (\d+\.\d+\.\d+) (?:core interpreter )?\((?:32|64)-bit\)$`)
	reNumInicio = regexp.MustCompile(`^\d+(\.\d+)*`)
)

// nomeBase: n == base, ou base seguido de " (" / " " + dígito (ex.: "mozilla firefox 120.0").
func nomeBase(n, base string) bool {
	return n == base || strings.HasPrefix(n, base+" (")
}

func comecaDigito(v string) bool { return v != "" && v[0] >= '0' && v[0] <= '9' }

// mapearCPE aplica a tabela curada. Retorna:
//   - curado=false: produto fora da tabela (motivo "sem CPE curada");
//   - curado=true, motivo!="": produto conhecido, mas NÃO avaliável com segurança;
//   - curado=true, motivo=="": alvo pronto para consulta.
//
// Tabela: Google Chrome, Microsoft Edge, Mozilla Firefox (+ESR), Oracle Java
// (JRE/JDK) e OpenJDK/Temurin (como oracle:jdk), .NET Runtime / ASP.NET Core,
// Node.js, Python (Core Interpreter), 7-Zip, Adobe Acrobat / Acrobat Reader.
func mapearCPE(it Item) (alvo alvoCPE, curado bool, motivo string) {
	n := strings.ToLower(strings.TrimSpace(it.Nome))
	v := strings.TrimSpace(it.Versao)
	semVer := "versão do inventário inutilizável para o CPE: " + strconv.Quote(it.Versao)
	switch {
	case nomeBase(n, "google chrome"):
		if !comecaDigito(v) {
			return alvo, true, semVer
		}
		return alvoCPE{"google", "chrome", v}, true, ""
	case nomeBase(n, "microsoft edge"):
		if !comecaDigito(v) {
			return alvo, true, semVer
		}
		return alvoCPE{"microsoft", "edge_chromium", v}, true, ""
	case strings.HasPrefix(n, "mozilla firefox"):
		if !comecaDigito(v) {
			return alvo, true, semVer
		}
		prod := "firefox"
		if strings.Contains(n, "esr") {
			prod = "firefox_esr"
		}
		return alvoCPE{"mozilla", prod, v}, true, ""
	case strings.HasPrefix(n, "java") || strings.Contains(n, "openjdk") || strings.Contains(n, "temurin") || strings.Contains(n, "adoptium"):
		return mapearJava(n, v, semVer)
	case strings.HasPrefix(n, "microsoft .net framework"):
		return alvo, true, ".NET Framework é corrigido por KB do Windows Update; a versão do Framework não indica o nível de patch (evita falso positivo)"
	case strings.HasPrefix(n, "microsoft .net sdk"):
		return alvo, true, "versão do SDK .NET não equivale à do runtime; avaliado pelo item .NET Runtime"
	case strings.HasPrefix(n, "microsoft .net runtime") || strings.HasPrefix(n, "microsoft asp.net core"):
		// A versão de ARP do runtime .NET é opaca (ex.: 64.x); usa a do nome.
		m := reDotNet.FindString(n)
		if m == "" {
			return alvo, true, "versão .NET não encontrada no nome de exibição"
		}
		prod := ".net"
		if strings.Contains(n, "asp.net core") {
			prod = "asp.net_core"
		}
		return alvoCPE{"microsoft", prod, m}, true, ""
	case n == "node.js" || strings.HasPrefix(n, "node.js "):
		v = strings.TrimPrefix(v, "v")
		if !comecaDigito(v) {
			return alvo, true, semVer
		}
		return alvoCPE{"nodejs", "node.js", v}, true, ""
	case strings.HasPrefix(n, "python "):
		if m := rePython.FindStringSubmatch(n); m != nil {
			return alvoCPE{"python", "python", m[1]}, true, ""
		}
		if strings.Contains(n, "launcher") || reDotNet.MatchString(n) {
			return alvo, true, "componente do Python; a versão é avaliada pelo item Core Interpreter"
		}
		return alvo, true, "versão Python não encontrada no nome de exibição"
	case strings.HasPrefix(n, "7-zip"):
		if !comecaDigito(v) {
			return alvo, true, semVer
		}
		return alvoCPE{"7-zip", "7-zip", v}, true, ""
	case strings.HasPrefix(n, "adobe acrobat") || strings.HasPrefix(n, "adobe reader"):
		if !comecaDigito(v) {
			return alvo, true, semVer
		}
		prod := "acrobat_dc"
		if strings.Contains(n, "reader") {
			prod = "acrobat_reader_dc"
		}
		return alvoCPE{"adobe", prod, v}, true, ""
	}
	return alvo, false, ""
}

func mapearJava(n, v, semVer string) (alvoCPE, bool, string) {
	// Java 8 e anteriores: o registro mostra "Update N" no nome; a NVD usa 1.8.0:updateN.
	if m := reJDK8.FindStringSubmatch(n); m != nil {
		return alvoCPE{"oracle", "jdk", "1." + m[1] + ".0." + m[2]}, true, ""
	}
	if m := reJava8.FindStringSubmatch(n); m != nil {
		return alvoCPE{"oracle", "jre", "1." + m[1] + ".0." + m[2]}, true, ""
	}
	if strings.Contains(n, "development kit") {
		if m := reJDKN.FindStringSubmatch(n); m != nil {
			return alvoCPE{"oracle", "jdk", m[1]}, true, ""
		}
		return alvoCPE{}, true, "versão do JDK não encontrada no nome de exibição"
	}
	if strings.Contains(n, "openjdk") || strings.Contains(n, "temurin") || strings.Contains(n, "adoptium") {
		// Distribuições OpenJDK compartilham o código/CVEs do Oracle JDK upstream.
		if !comecaDigito(v) {
			return alvoCPE{}, true, semVer
		}
		p := strings.Split(reNumInicio.FindString(v), ".")
		if len(p) < 3 {
			return alvoCPE{}, true, semVer
		}
		if p[0] == "8" { // 8.0.392.8 -> 1.8.0.392
			return alvoCPE{"oracle", "jdk", "1.8.0." + p[2]}, true, ""
		}
		return alvoCPE{"oracle", "jdk", strings.Join(p[:3], ".")}, true, ""
	}
	return alvoCPE{}, false, ""
}

// -------------------------------------------------------- comparação de versão

func partesVersao(v string) []int {
	var out []int
	for _, s := range regexp.MustCompile(`\d+`).FindAllString(v, -1) {
		n, _ := strconv.Atoi(s)
		out = append(out, n)
	}
	return out
}

// cmpVersao compara versões numéricas dotted (zeros à direita são irrelevantes).
func cmpVersao(a, b string) int {
	pa, pb := partesVersao(a), partesVersao(b)
	for i := 0; i < max(len(pa), len(pb)); i++ {
		var x, y int
		if i < len(pa) {
			x = pa[i]
		}
		if i < len(pb) {
			y = pb[i]
		}
		if x != y {
			if x < y {
				return -1
			}
			return 1
		}
	}
	return 0
}

// ------------------------------------------------------------------ NVD JSON

type nvdMatch struct {
	Vulnerable            bool   `json:"vulnerable"`
	Criteria              string `json:"criteria"`
	VersionStartIncluding string `json:"versionStartIncluding"`
	VersionStartExcluding string `json:"versionStartExcluding"`
	VersionEndIncluding   string `json:"versionEndIncluding"`
	VersionEndExcluding   string `json:"versionEndExcluding"`
}

type nvdMetrica struct {
	Type     string `json:"type"`
	CvssData struct {
		BaseScore    float64 `json:"baseScore"`
		BaseSeverity string  `json:"baseSeverity"`
	} `json:"cvssData"`
	BaseSeverity string `json:"baseSeverity"` // CVSS v2 traz aqui
}

type nvdCVE struct {
	ID         string `json:"id"`
	VulnStatus string `json:"vulnStatus"`
	Metrics    struct {
		V40 []nvdMetrica `json:"cvssMetricV40"`
		V31 []nvdMetrica `json:"cvssMetricV31"`
		V30 []nvdMetrica `json:"cvssMetricV30"`
		V2  []nvdMetrica `json:"cvssMetricV2"`
	} `json:"metrics"`
	Configurations []struct {
		Nodes []struct {
			CPEMatch []nvdMatch `json:"cpeMatch"`
		} `json:"nodes"`
	} `json:"configurations"`
}

type nvdResp struct {
	ResultsPerPage  int `json:"resultsPerPage"`
	StartIndex      int `json:"startIndex"`
	TotalResults    int `json:"totalResults"`
	Vulnerabilities []struct {
		CVE nvdCVE `json:"cve"`
	} `json:"vulnerabilities"`
}

// casaVersao diz se a versão cai na faixa/versão exata do cpeMatch para o alvo.
// Retorna também o fixed (versionEndExcluding) quando for esse o limite.
func casaVersao(m nvdMatch, a alvoCPE) (casou bool, fixed string) {
	if !m.Vulnerable {
		return false, ""
	}
	p := strings.Split(m.Criteria, ":") // cpe:2.3:part:vendor:product:version:update:...
	if len(p) < 7 || p[3] != a.Vendor || p[4] != a.Product {
		return false, ""
	}
	ver, upd := p[5], p[6]
	switch ver {
	case "-":
		return false, "" // "não aplicável": não diz nada sobre a versão
	case "*":
		temFaixa := m.VersionStartIncluding != "" || m.VersionStartExcluding != "" ||
			m.VersionEndIncluding != "" || m.VersionEndExcluding != ""
		if !temFaixa {
			return true, "" // todas as versões
		}
		if m.VersionStartIncluding != "" && cmpVersao(a.Versao, m.VersionStartIncluding) < 0 {
			return false, ""
		}
		if m.VersionStartExcluding != "" && cmpVersao(a.Versao, m.VersionStartExcluding) <= 0 {
			return false, ""
		}
		if m.VersionEndIncluding != "" && cmpVersao(a.Versao, m.VersionEndIncluding) > 0 {
			return false, ""
		}
		if m.VersionEndExcluding != "" && cmpVersao(a.Versao, m.VersionEndExcluding) >= 0 {
			return false, ""
		}
		return true, m.VersionEndExcluding
	}
	// versão exata no CPE (ex.: 1.8.0:update391 -> 1.8.0.391)
	cv := ver
	if strings.HasPrefix(upd, "update") {
		cv += "." + strings.TrimPrefix(upd, "update")
	}
	return cmpVersao(a.Versao, cv) == 0, ""
}

// achadoNVD converte um CVE da NVD em achado se alguma cpeMatch casar com o alvo.
func achadoNVD(c nvdCVE, a alvoCPE, it Item) (Achado, bool) {
	if strings.EqualFold(c.VulnStatus, "Rejected") {
		return Achado{}, false
	}
	var casou bool
	var fixed string
	for _, cfg := range c.Configurations {
		for _, nd := range cfg.Nodes {
			for _, m := range nd.CPEMatch {
				if ok, f := casaVersao(m, a); ok {
					casou = true
					if fixed == "" || (f != "" && cmpVersao(f, fixed) < 0) {
						fixed = f
					}
				}
			}
		}
	}
	if !casou {
		return Achado{}, false
	}
	ach := Achado{VulnID: c.ID, CVEID: c.ID, Pacote: it.Nome, Versao: it.Versao,
		Fonte: FonteNVD, Severidade: "DESCONHECIDA", FixedVersion: fixed}
	// CVSS: v4.0 > v3.1 > v3.0 > v2 (v2 nunca passa de HIGH). Prefere a métrica "Primary" (NVD).
	for i, grupo := range [][]nvdMetrica{c.Metrics.V40, c.Metrics.V31, c.Metrics.V30, c.Metrics.V2} {
		if len(grupo) == 0 {
			continue
		}
		mt := grupo[0]
		for _, x := range grupo {
			if x.Type == "Primary" {
				mt = x
				break
			}
		}
		ach.Pontuacao = mt.CvssData.BaseScore
		ach.Severidade = severidadeDe(mt.CvssData.BaseScore)
		if ach.Severidade == "CRITICAL" && i == 3 {
			ach.Severidade = "HIGH"
		}
		if s := strings.ToUpper(mt.CvssData.BaseSeverity); ach.Severidade == "DESCONHECIDA" && s != "" {
			ach.Severidade = s
		}
		break
	}
	return ach, true
}

// ------------------------------------------------------------------ FonteNVD

// NVD implementa FonteCPE sobre a NVD API 2.0, com cache em SQLite, espaçamento
// de requisições (rate limit), retries e fail-soft.
type NVD struct {
	St     *Store
	HTTP   *http.Client // padrão: timeout de 60s
	Base   string       // padrão https://services.nvd.nist.gov (testes: httptest)
	APIKey string       // opcional; NovaFonteNVD lê FMRMM_NVD_API_KEY
	// Intervalo mínimo entre requisições; 0 = padrão (6,5 s sem chave, 0,7 s com chave).
	Intervalo time.Duration
	Agora     func() time.Time
	Espera    func(time.Duration) // testes injetam no-op/registro

	mu     sync.Mutex
	ultima time.Time
}

// NovaFonteNVD cria a fonte lendo a chave opcional do ambiente.
func NovaFonteNVD(st *Store) *NVD {
	return &NVD{St: st, APIKey: strings.TrimSpace(os.Getenv(EnvNVDKey))}
}

func (n *NVD) agora() time.Time {
	if n.Agora != nil {
		return n.Agora()
	}
	return time.Now()
}

func (n *NVD) espera(d time.Duration) {
	if n.Espera != nil {
		n.Espera(d)
		return
	}
	time.Sleep(d)
}

func (n *NVD) base() string {
	if n.Base != "" {
		return strings.TrimRight(n.Base, "/")
	}
	return nvdBaseURL
}

func (n *NVD) cliente() *http.Client {
	if n.HTTP != nil {
		return n.HTTP
	}
	return &http.Client{Timeout: nvdTimeoutPadrao}
}

func (n *NVD) intervalo() time.Duration {
	switch {
	case n.Intervalo != 0:
		return n.Intervalo
	case n.APIKey != "":
		return nvdIntervaloComChave
	}
	return nvdIntervaloSemChave
}

// aguardarVez espaça as requisições (serializado) respeitando o limite da NVD.
func (n *NVD) aguardarVez() {
	n.mu.Lock()
	defer n.mu.Unlock()
	if !n.ultima.IsZero() {
		if falta := n.intervalo() - time.Since(n.ultima); falta > 0 {
			n.espera(falta)
		}
	}
	n.ultima = time.Now()
}

// Avaliar consulta a NVD para os itens da tabela curada. Itens fora da tabela
// voltam em NaoAvaliados. Erro de rede interrompe a rodada: o restante volta
// como não avaliado e o erro é devolvido (o Engine preserva achados antigos).
func (n *NVD) Avaliar(ctx context.Context, goos string, itens []Item) (ResultadoCPE, error) {
	var res ResultadoCPE
	if goos == "linux" {
		for _, it := range itens {
			res.NaoAvaliados = append(res.NaoAvaliados, NaoAvaliado{it.Nome, it.Versao, "pacote Linux: CPE/NVD curada cobre apenas apps Windows/macOS (use o ecossistema OSV)"})
		}
		return res, nil
	}
	type pronto struct {
		it Item
		a  alvoCPE
	}
	var fila []pronto
	for _, it := range itens {
		a, curado, motivo := mapearCPE(it)
		switch {
		case !curado:
			res.NaoAvaliados = append(res.NaoAvaliados, NaoAvaliado{it.Nome, it.Versao, "sem CPE curada para o produto (OSV também não cobre)"})
		case motivo != "":
			res.NaoAvaliados = append(res.NaoAvaliados, NaoAvaliado{it.Nome, it.Versao, motivo})
		default:
			fila = append(fila, pronto{it, a})
		}
	}
	vistos := map[string]bool{}
	for i, p := range fila {
		hits, err := n.consultar(ctx, p.a)
		if err != nil {
			for _, r := range fila[i:] {
				res.NaoAvaliados = append(res.NaoAvaliados, NaoAvaliado{r.it.Nome, r.it.Versao, "NVD indisponível: " + err.Error()})
			}
			return res, fmt.Errorf("nvd: %w", err)
		}
		res.Avaliados = append(res.Avaliados, p.it)
		for _, c := range hits {
			ach, ok := achadoNVD(c, p.a, p.it)
			if !ok {
				continue
			}
			k := ach.VulnID + "\x00" + ach.Pacote + "\x00" + ach.Versao
			if !vistos[k] {
				vistos[k] = true
				res.Achados = append(res.Achados, ach)
			}
		}
	}
	return res, nil
}

func chaveNVD(a alvoCPE) string { return "nvd:" + a.cpe() + ":" + a.Versao }

// consultar devolve os CVEs da NVD para o alvo (cache 24h por CPE+versão). O
// cache guarda só os CVEs que JÁ casaram a faixa de versão (compacto).
func (n *NVD) consultar(ctx context.Context, a alvoCPE) ([]nvdCVE, error) {
	agora := n.agora()
	if v, ok := n.St.cacheGet(chaveNVD(a), ttlConsultaNVD, agora); ok {
		var out []nvdCVE
		if json.Unmarshal([]byte(v), &out) == nil {
			return out, nil
		}
	}
	var out []nvdCVE
	for pag := 0; pag < nvdPaginasMax; pag++ {
		q := url.Values{}
		q.Set("virtualMatchString", a.cpe()+":"+a.Versao+":*:*:*:*:*:*:*")
		q.Set("resultsPerPage", strconv.Itoa(nvdPorPagina))
		q.Set("startIndex", strconv.Itoa(pag*nvdPorPagina))
		var r nvdResp
		if err := n.chamar(ctx, nvdCaminho+"?"+q.Encode(), &r); err != nil {
			return nil, err
		}
		for _, v := range r.Vulnerabilities {
			// filtro de faixa de versão no cliente (não confia só no filtro do servidor)
			if _, ok := achadoNVD(v.CVE, a, Item{}); ok {
				out = append(out, v.CVE)
			}
		}
		if (pag+1)*nvdPorPagina >= r.TotalResults || len(r.Vulnerabilities) == 0 {
			break
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	b, _ := json.Marshal(out)
	_ = n.St.cachePut(chaveNVD(a), string(b), agora)
	return out, nil
}

// chamar faz GET com retries (rede/5xx/429/403 de limite), header apiKey quando houver.
func (n *NVD) chamar(ctx context.Context, caminho string, saida any) error {
	var ultimo error
	for t := 0; t < nvdTentativas; t++ {
		if t > 0 {
			n.espera(time.Duration(t) * 2 * n.intervalo())
		}
		if err := ctx.Err(); err != nil {
			return err
		}
		n.aguardarVez()
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, n.base()+caminho, nil)
		if err != nil {
			return err
		}
		req.Header.Set("User-Agent", "fm-rmm-cve/1")
		if n.APIKey != "" {
			req.Header.Set("apiKey", n.APIKey)
		}
		resp, err := n.cliente().Do(req)
		if err != nil {
			ultimo = errors.New("falha de rede") // sem detalhes da URL (nada sensível)
			continue
		}
		b, rerr := io.ReadAll(io.LimitReader(resp.Body, nvdCorpoMax))
		resp.Body.Close()
		switch {
		case rerr != nil:
			ultimo = errors.New("leitura da resposta falhou")
		case resp.StatusCode == http.StatusTooManyRequests || resp.StatusCode == http.StatusForbidden || resp.StatusCode >= 500:
			// a NVD responde 403 quando o limite é excedido
			ultimo = fmt.Errorf("HTTP %d", resp.StatusCode)
			if s, err := strconv.Atoi(resp.Header.Get("Retry-After")); err == nil && s > 0 {
				n.espera(time.Duration(min(s, 60)) * time.Second)
			}
		case resp.StatusCode != http.StatusOK:
			return fmt.Errorf("HTTP %d", resp.StatusCode)
		default:
			if err := json.Unmarshal(b, saida); err != nil {
				return fmt.Errorf("resposta inválida: %w", err)
			}
			return nil
		}
	}
	return fmt.Errorf("indisponível após %d tentativas: %w", nvdTentativas, ultimo)
}
