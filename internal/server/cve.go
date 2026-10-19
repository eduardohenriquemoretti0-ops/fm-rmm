package server

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/eduardohenriquemoretti0-ops/fm-rmm/internal/proto"
)

// Engine de vulnerabilidades (T3a, Plano v2 §3.3 fase 2) — DEFENSIVO, read-only.
//
// O AGENTE não sabe de CVE: só reporta o inventário (ação `software`). O
// SERVIDOR pega o último inventário, mapeia o que o OSV.dev sabe cruzar
// (ecossistema + nome + versão) e consulta POST /v1/querybatch. Detalhe
// (severidade, versão corrigida) vem de GET /v1/vulns/{id}. Respostas são
// cacheadas no SQLite. Limitações de cobertura: docs/cve-osv.md.
//
// Regra de ouro: NÃO inventar match. Item que o OSV não cobre (apps Windows por
// nome de exibição, apps macOS) vira "não avaliado" — com marca de ALTO RISCO
// quando for navegador/Java/runtime — e passa pela FonteCPE (NVD, tabela curada; cve_nvd.go).

const (
	FonteOSV = "osv.dev"

	osvBaseURL       = "https://api.osv.dev"
	osvLoteMax       = 500
	osvPaginasMax    = 5
	osvCorpoMax      = 8 << 20
	ttlConsultaOSV   = 24 * time.Hour
	ttlDetalheOSV    = 7 * 24 * time.Hour
	osvTentativas    = 3
	osvTimeoutPadrao = 20 * time.Second
)

// ErrSemInventario: o agente nunca devolveu um inventário `software` válido.
var ErrSemInventario = errors.New("sem inventário de software finalizado para o agente")

// Item é um software do inventário.
type Item struct {
	Nome, Versao, Fabricante string
}

// ResultadoCPE é o que uma FonteCPE devolve: achados, os itens que ela de fato
// avaliou (podem ter zero achados = sem vulnerabilidade) e os que não conseguiu
// avaliar (com motivo). Itens que não aparecem em nenhuma lista mantêm o motivo
// original do OSV.
type ResultadoCPE struct {
	Achados      []Achado
	Avaliados    []Item
	NaoAvaliados []NaoAvaliado
}

// FonteCPE é a fonte baseada em CPE/NVD (implementação: NVD em cve_nvd.go).
// Recebe só o que o OSV não cobre. Em erro, devolve o ResultadoCPE parcial e o
// erro (o Engine registra o aviso e preserva os achados anteriores).
type FonteCPE interface {
	Avaliar(ctx context.Context, os string, itens []Item) (ResultadoCPE, error)
}

// Engine cruza inventário x OSV. Campos zerados usam padrões seguros.
type Engine struct {
	St   *Store
	HTTP *http.Client // padrão: timeout de 20s
	Base string       // padrão https://api.osv.dev (testes apontam para httptest)
	// EcossistemaLinux é o ecossistema OSV das distros (ex.: "Debian:12",
	// "Ubuntu:24.04"). O inventário não informa a release da distro; sem isso
	// os pacotes Linux ficam "não avaliados" (não adivinhamos).
	EcossistemaLinux string
	CPE              FonteCPE
	Agora            func() time.Time
	Espera           func(time.Duration) // backoff; testes injetam no-op
}

func (e *Engine) agora() time.Time {
	if e.Agora != nil {
		return e.Agora()
	}
	return time.Now()
}

func (e *Engine) base() string {
	if e.Base != "" {
		return strings.TrimRight(e.Base, "/")
	}
	return osvBaseURL
}

func (e *Engine) cliente() *http.Client {
	if e.HTTP != nil {
		return e.HTTP
	}
	return &http.Client{Timeout: osvTimeoutPadrao}
}

func (e *Engine) espera(d time.Duration) {
	if e.Espera != nil {
		e.Espera(d)
		return
	}
	time.Sleep(d)
}

// --------------------------------------------------------------- inventário

// ParseInventario converte a saída da ação `software` em itens. Windows emite
// JSON (array, ou objeto único quando há 1 item); Linux/macOS emitem
// "nome<TAB>versão" por linha.
func ParseInventario(goos, saida string) []Item {
	saida = strings.TrimSpace(strings.TrimPrefix(saida, "\xef\xbb\xbf"))
	if saida == "" {
		return nil
	}
	var out []Item
	if saida[0] == '[' || saida[0] == '{' {
		type jitem struct {
			Nome       string `json:"nome"`
			Versao     string `json:"versao"`
			Fabricante string `json:"fabricante"`
		}
		var arr []jitem
		if saida[0] == '{' {
			var one jitem
			if json.Unmarshal([]byte(saida), &one) == nil {
				arr = []jitem{one}
			}
		} else if json.Unmarshal([]byte(saida), &arr) != nil {
			arr = nil
		}
		for _, it := range arr {
			if n := strings.TrimSpace(it.Nome); n != "" {
				out = append(out, Item{Nome: n, Versao: strings.TrimSpace(it.Versao), Fabricante: strings.TrimSpace(it.Fabricante)})
			}
		}
		return out
	}
	for _, ln := range strings.Split(saida, "\n") {
		ln = strings.TrimRight(ln, "\r")
		nome, ver, ok := strings.Cut(ln, "\t")
		if !ok || strings.TrimSpace(nome) == "" {
			continue
		}
		out = append(out, Item{Nome: strings.TrimSpace(nome), Versao: strings.TrimSpace(ver)})
	}
	return out
}

// altoRisco marca software cujo atraso de patch é crítico (navegadores, Java,
// runtimes). Serve para destacar o que ficou SEM avaliação.
func altoRisco(nome string) bool {
	n := strings.ToLower(nome)
	for _, p := range []string{"chrome", "firefox", "edge", "opera", "brave", "chromium",
		"java", "jre", "jdk", "openjdk", "node.js", "nodejs", ".net", "python", "php", "ruby",
		"adobe reader", "acrobat", "flash", "silverlight", "openssl", "winrar", "7-zip"} {
		if strings.Contains(n, p) {
			return true
		}
	}
	return false
}

type consulta struct {
	Item      Item
	Ecossis   string
	Nome, Ver string
}

// mapear separa itens consultáveis no OSV dos "não avaliados" (com motivo).
func (e *Engine) mapear(goos string, itens []Item) (cons []consulta, nao []NaoAvaliado) {
	for _, it := range itens {
		switch {
		case it.Versao == "" || it.Versao == "?":
			nao = append(nao, NaoAvaliado{it.Nome, it.Versao, "sem versão no inventário"})
		case goos == "linux" && e.EcossistemaLinux != "":
			cons = append(cons, consulta{Item: it, Ecossis: e.EcossistemaLinux, Nome: it.Nome, Ver: it.Versao})
		case goos == "linux":
			nao = append(nao, NaoAvaliado{it.Nome, it.Versao, "release da distro desconhecida (ecossistema OSV não configurado)"})
		case goos == "windows":
			nao = append(nao, NaoAvaliado{it.Nome, it.Versao, "OSV não cobre aplicativo Windows por nome de exibição (gancho CPE/NVD)"})
		default:
			nao = append(nao, NaoAvaliado{it.Nome, it.Versao, "sem mapeamento OSV para " + goos + " (gancho CPE/NVD)"})
		}
	}
	return cons, nao
}

// ------------------------------------------------------------------- scan

// ResultadoScan é o que Scan devolve (e persiste).
type ResultadoScan struct {
	Resumo  ResumoScan
	Achados []Achado
}

// Scan cruza o último inventário `software` do agente e grava os achados.
// Fail-soft: erro de rede/OSV NÃO é erro de Scan — fica em Resumo.Erro, os
// achados anteriores são preservados e nada derruba o dashboard.
func (e *Engine) Scan(ctx context.Context, agentID string) (ResultadoScan, error) {
	ag, err := e.St.Agent(agentID)
	if err != nil {
		return ResultadoScan{}, err
	}
	job, ok, err := e.St.UltimoInventarioSoftware(agentID)
	if err != nil {
		return ResultadoScan{}, err
	}
	if !ok {
		return ResultadoScan{}, ErrSemInventario
	}
	var res proto.Result
	if err := json.Unmarshal([]byte(job.Result), &res); err != nil {
		return ResultadoScan{}, fmt.Errorf("resultado do job %s ilegível: %w", job.ID, err)
	}
	itens := ParseInventario(ag.OS, res.Output)
	cons, nao := e.mapear(ag.OS, itens)

	var achados []Achado
	var erros []string
	avaliados := 0
	completo := true
	if len(cons) > 0 {
		a, err := e.consultarOSV(ctx, cons)
		if err != nil {
			erros = append(erros, "osv: "+err.Error())
			completo = false
		} else {
			achados = append(achados, a...)
			avaliados = len(cons)
		}
	}

	// fonte CPE/NVD: depois do OSV, só para o que o OSV não cobre
	if e.CPE != nil && len(nao) > 0 {
		naoSet := map[string]bool{}
		for _, n := range nao {
			naoSet[n.Pacote+"\x00"+n.Versao] = true
		}
		var para []Item
		for _, it := range itens {
			if naoSet[it.Nome+"\x00"+it.Versao] && it.Versao != "" && it.Versao != "?" {
				para = append(para, it)
			}
		}
		r, err := e.CPE.Avaliar(ctx, ag.OS, para)
		if err != nil {
			erros = append(erros, "cpe: "+err.Error())
			completo = false
		}
		achados = append(achados, r.Achados...)
		feito := map[string]bool{}
		for _, it := range r.Avaliados {
			feito[it.Nome+"\x00"+it.Versao] = true
		}
		motivo := map[string]string{}
		for _, n := range r.NaoAvaliados {
			motivo[n.Pacote+"\x00"+n.Versao] = n.Motivo
		}
		var resto []NaoAvaliado
		for _, n := range nao {
			k := n.Pacote + "\x00" + n.Versao
			switch {
			case feito[k]:
				avaliados++
			case motivo[k] != "":
				n.Motivo = motivo[k]
				resto = append(resto, n)
			default:
				resto = append(resto, n)
			}
		}
		nao = resto
	}

	var risco []NaoAvaliado
	for _, n := range nao {
		if altoRisco(n.Pacote) {
			risco = append(risco, n)
		}
	}
	rs := ResumoScan{
		AgentID: agentID, JobID: job.ID, ItensTotal: len(itens), Avaliados: avaliados,
		NaoAvaliados: len(nao), NaoAvaliadosRisco: risco, Erro: strings.Join(erros, "; "),
	}
	agora := e.agora()
	if err := e.St.SalvarScan(rs, achados, completo, agora); err != nil {
		return ResultadoScan{}, err
	}
	rs.EscaneadoEm = agora.Unix()
	return ResultadoScan{Resumo: rs, Achados: achados}, nil
}

// ---------------------------------------------------------------- OSV API

type osvQuery struct {
	Package struct {
		Name      string `json:"name"`
		Ecosystem string `json:"ecosystem"`
	} `json:"package"`
	Version   string `json:"version"`
	PageToken string `json:"page_token,omitempty"`
}

type osvBatchResp struct {
	Results []struct {
		Vulns []struct {
			ID string `json:"id"`
		} `json:"vulns"`
		NextPageToken string `json:"next_page_token"`
	} `json:"results"`
}

func chaveConsulta(c consulta) string { return "q:" + c.Ecossis + "|" + c.Nome + "|" + c.Ver }

// consultarOSV devolve os achados das consultas. Usa cache por (eco,nome,versão);
// só o que falta vai ao querybatch. Qualquer falha de rede aborta (o chamador
// trata como fail-soft e mantém os achados antigos).
func (e *Engine) consultarOSV(ctx context.Context, cons []consulta) ([]Achado, error) {
	agora := e.agora()
	idsPor := map[int][]string{} // índice em cons -> vuln ids
	var faltam []int
	for i, c := range cons {
		if v, ok := e.St.cacheGet(chaveConsulta(c), ttlConsultaOSV, agora); ok {
			var ids []string
			if json.Unmarshal([]byte(v), &ids) == nil {
				idsPor[i] = ids
				continue
			}
		}
		faltam = append(faltam, i)
	}
	for ini := 0; ini < len(faltam); ini += osvLoteMax {
		fim := min(ini+osvLoteMax, len(faltam))
		lote := faltam[ini:fim]
		ids, err := e.querybatch(ctx, cons, lote)
		if err != nil {
			return nil, err
		}
		for k, idx := range lote {
			idsPor[idx] = ids[k]
			b, _ := json.Marshal(ids[k])
			_ = e.St.cachePut(chaveConsulta(cons[idx]), string(b), agora)
		}
	}
	var out []Achado
	for i, c := range cons {
		for _, id := range idsPor[i] {
			v, err := e.detalhe(ctx, id)
			if err != nil {
				return nil, err
			}
			out = append(out, achadoDe(v, c))
		}
	}
	return out, nil
}

// querybatch consulta um lote e segue next_page_token (limitado).
func (e *Engine) querybatch(ctx context.Context, cons []consulta, lote []int) ([][]string, error) {
	qs := make([]osvQuery, len(lote))
	for k, idx := range lote {
		qs[k].Package.Name, qs[k].Package.Ecosystem, qs[k].Version = cons[idx].Nome, cons[idx].Ecossis, cons[idx].Ver
	}
	ids := make([][]string, len(lote))
	pend := make([]int, len(lote))
	for k := range pend {
		pend[k] = k
	}
	for pag := 0; pag < osvPaginasMax && len(pend) > 0; pag++ {
		corpo := struct {
			Queries []osvQuery `json:"queries"`
		}{}
		for _, k := range pend {
			corpo.Queries = append(corpo.Queries, qs[k])
		}
		var resp osvBatchResp
		if err := e.chamar(ctx, http.MethodPost, "/v1/querybatch", corpo, &resp); err != nil {
			return nil, err
		}
		if len(resp.Results) != len(pend) {
			return nil, fmt.Errorf("querybatch devolveu %d resultados para %d consultas", len(resp.Results), len(pend))
		}
		var prox []int
		for j, r := range resp.Results {
			k := pend[j]
			for _, v := range r.Vulns {
				ids[k] = append(ids[k], v.ID)
			}
			if r.NextPageToken != "" {
				qs[k].PageToken = r.NextPageToken
				prox = append(prox, k)
			}
		}
		pend = prox
	}
	return ids, nil
}

type osvVuln struct {
	ID       string   `json:"id"`
	Aliases  []string `json:"aliases"`
	Severity []struct {
		Type  string `json:"type"`
		Score string `json:"score"`
	} `json:"severity"`
	DatabaseSpecific struct {
		Severity string `json:"severity"`
	} `json:"database_specific"`
	Affected []struct {
		Package struct {
			Name      string `json:"name"`
			Ecosystem string `json:"ecosystem"`
		} `json:"package"`
		Ranges []struct {
			Events []map[string]string `json:"events"`
		} `json:"ranges"`
	} `json:"affected"`
}

func (e *Engine) detalhe(ctx context.Context, id string) (osvVuln, error) {
	var v osvVuln
	if c, ok := e.St.cacheGet("v:"+id, ttlDetalheOSV, e.agora()); ok && json.Unmarshal([]byte(c), &v) == nil {
		return v, nil
	}
	var raw json.RawMessage
	if err := e.chamar(ctx, http.MethodGet, "/v1/vulns/"+url.PathEscape(id), nil, &raw); err != nil {
		return v, err
	}
	if err := json.Unmarshal(raw, &v); err != nil {
		return v, fmt.Errorf("vuln %s: %w", id, err)
	}
	_ = e.St.cachePut("v:"+id, string(raw), e.agora())
	return v, nil
}

// chamar faz a requisição com retries moderados (rede/5xx/429), corpo limitado.
func (e *Engine) chamar(ctx context.Context, metodo, caminho string, corpo, saida any) error {
	var payload []byte
	if corpo != nil {
		var err error
		if payload, err = json.Marshal(corpo); err != nil {
			return err
		}
	}
	var ultimo error
	for t := 0; t < osvTentativas; t++ {
		if t > 0 {
			e.espera(time.Duration(t) * 500 * time.Millisecond)
		}
		if err := ctx.Err(); err != nil {
			return err
		}
		req, err := http.NewRequestWithContext(ctx, metodo, e.base()+caminho, bytes.NewReader(payload))
		if err != nil {
			return err
		}
		if corpo != nil {
			req.Header.Set("Content-Type", "application/json")
		}
		resp, err := e.cliente().Do(req)
		if err != nil {
			ultimo = err
			continue
		}
		b, rerr := io.ReadAll(io.LimitReader(resp.Body, osvCorpoMax))
		resp.Body.Close()
		switch {
		case rerr != nil:
			ultimo = rerr
		case resp.StatusCode == http.StatusTooManyRequests || resp.StatusCode >= 500:
			ultimo = fmt.Errorf("osv: HTTP %d", resp.StatusCode)
		case resp.StatusCode != http.StatusOK:
			return fmt.Errorf("osv: HTTP %d", resp.StatusCode) // 4xx: não adianta repetir
		default:
			if err := json.Unmarshal(b, saida); err != nil {
				return fmt.Errorf("osv: resposta inválida: %w", err)
			}
			return nil
		}
	}
	return fmt.Errorf("osv indisponível após %d tentativas: %w", osvTentativas, ultimo)
}

// achadoDe monta o achado a partir do detalhe OSV e da consulta que casou.
func achadoDe(v osvVuln, c consulta) Achado {
	a := Achado{VulnID: v.ID, CVEID: v.ID, Pacote: c.Item.Nome, Versao: c.Item.Versao, Fonte: FonteOSV, Severidade: "DESCONHECIDA"}
	for _, al := range v.Aliases {
		if strings.HasPrefix(al, "CVE-") {
			a.CVEID = al
			break
		}
	}
	for _, s := range v.Severity {
		if strings.HasPrefix(s.Type, "CVSS_V3") {
			if p, ok := cvss3Base(s.Score); ok {
				a.Pontuacao, a.Severidade = p, severidadeDe(p)
				break
			}
		}
	}
	if a.Severidade == "DESCONHECIDA" {
		switch s := strings.ToUpper(v.DatabaseSpecific.Severity); s {
		case "CRITICAL", "HIGH", "LOW":
			a.Severidade = s
		case "MODERATE", "MEDIUM":
			a.Severidade = "MEDIUM"
		}
	}
fixed:
	for _, af := range v.Affected {
		if af.Package.Name != c.Nome || af.Package.Ecosystem != c.Ecossis {
			continue
		}
		for _, r := range af.Ranges {
			for _, ev := range r.Events {
				if f := ev["fixed"]; f != "" {
					a.FixedVersion = f
					break fixed
				}
			}
		}
	}
	return a
}

func severidadeDe(p float64) string {
	switch {
	case p >= 9.0:
		return "CRITICAL"
	case p >= 7.0:
		return "HIGH"
	case p >= 4.0:
		return "MEDIUM"
	case p > 0:
		return "LOW"
	}
	return "DESCONHECIDA"
}

// cvss3Base calcula a nota base CVSS v3.x a partir do vetor (FIRST, seção 7).
func cvss3Base(vetor string) (float64, bool) {
	m := map[string]string{}
	for i, p := range strings.Split(vetor, "/") {
		k, v, ok := strings.Cut(p, ":")
		if !ok {
			return 0, false
		}
		if i == 0 && k != "CVSS" {
			return 0, false
		}
		m[k] = v
	}
	av := map[string]float64{"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.2}[m["AV"]]
	ac := map[string]float64{"L": 0.77, "H": 0.44}[m["AC"]]
	ui := map[string]float64{"N": 0.85, "R": 0.62}[m["UI"]]
	cia := map[string]float64{"H": 0.56, "L": 0.22, "N": 0}
	c, ci := cia[m["C"]], m["C"] != ""
	i, ii := cia[m["I"]], m["I"] != ""
	a, ai := cia[m["A"]], m["A"] != ""
	mudou := m["S"] == "C"
	pr := map[string]float64{"N": 0.85, "L": 0.62, "H": 0.27}[m["PR"]]
	if mudou {
		pr = map[string]float64{"N": 0.85, "L": 0.68, "H": 0.5}[m["PR"]]
	}
	if av == 0 || ac == 0 || ui == 0 || pr == 0 || !ci || !ii || !ai || (m["S"] != "C" && m["S"] != "U") {
		return 0, false
	}
	iss := 1 - (1-c)*(1-i)*(1-a)
	var imp float64
	if mudou {
		imp = 7.52*(iss-0.029) - 3.25*math.Pow(iss-0.02, 15)
	} else {
		imp = 6.42 * iss
	}
	if imp <= 0 {
		return 0, true
	}
	exp := 8.22 * av * ac * pr * ui
	var base float64
	if mudou {
		base = roundup(math.Min(1.08*(imp+exp), 10))
	} else {
		base = roundup(math.Min(imp+exp, 10))
	}
	return base, true
}

func roundup(x float64) float64 {
	n := int(math.Round(x * 100000))
	if n%10000 == 0 {
		return float64(n) / 100000
	}
	return (math.Floor(float64(n)/10000) + 1) / 10
}

// ---------------------------------------------------------------- resumo

// ResumoVulnerabilidades é o JSON exposto ao console (somente leitura do banco;
// nunca chama a rede).
type ResumoVulnerabilidades struct {
	Agente                string         `json:"agente"`
	Escaneado             bool           `json:"escaneado"`
	EscaneadoEm           *string        `json:"escaneado_em"`
	Fonte                 string         `json:"fonte"`
	ItensTotal            int            `json:"itens_total"`
	Avaliados             int            `json:"avaliados"`
	NaoAvaliados          int            `json:"nao_avaliados"`
	Total                 int            `json:"total"`
	PorSeveridade         map[string]int `json:"por_severidade"`
	Vulnerabilidades      []ItemVuln     `json:"vulnerabilidades"`
	NaoAvaliadosAltoRisco []NaoAvaliado  `json:"nao_avaliados_alto_risco"`
	Erro                  string         `json:"erro,omitempty"`
}

// ItemVuln é um achado como o console o mostra.
type ItemVuln struct {
	Achado
	VistoEm string `json:"visto_em"`
}

// ResumoVulns monta o resumo a partir do que está no banco.
func (s *Store) ResumoVulns(agentID string) (ResumoVulnerabilidades, error) {
	r := ResumoVulnerabilidades{
		Agente: agentID, Fonte: FonteOSV, PorSeveridade: map[string]int{},
		Vulnerabilidades: []ItemVuln{}, NaoAvaliadosAltoRisco: []NaoAvaliado{},
	}
	sc, ok, err := s.UltimoScan(agentID)
	if err != nil {
		return r, err
	}
	if !ok {
		return r, nil
	}
	achados, err := s.Achados(agentID)
	if err != nil {
		return r, err
	}
	t := time.Unix(sc.EscaneadoEm, 0).UTC().Format(time.RFC3339)
	r.Escaneado, r.EscaneadoEm = true, &t
	r.ItensTotal, r.Avaliados, r.NaoAvaliados, r.Erro = sc.ItensTotal, sc.Avaliados, sc.NaoAvaliados, sc.Erro
	if sc.NaoAvaliadosRisco != nil {
		r.NaoAvaliadosAltoRisco = sc.NaoAvaliadosRisco
	}
	for _, a := range achados {
		r.PorSeveridade[a.Severidade]++
		r.Vulnerabilidades = append(r.Vulnerabilidades, ItemVuln{Achado: a, VistoEm: time.Unix(a.VistoEm, 0).UTC().Format(time.RFC3339)})
	}
	r.Total = len(achados)
	for _, a := range achados {
		if a.Fonte == FonteNVD {
			r.Fonte = FonteOSV + "+" + FonteNVD
			break
		}
	}
	return r, nil
}
