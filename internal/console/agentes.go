// Endpoints read-only de agentes do console (T4).
//
//	GET /api/agentes        lista os agentes que o operador pode ver (RBAC)
//	GET /api/agentes/{id}   detalhe + últimos resultados de ações de leitura
//
// Regras:
//   - RBAC: o operador vê o agente se o TÉCNICO dele (op.TechName) tem o grupo
//     do agente (CanAccess). Sem permissão = 404, igual a "não existe", para
//     não vazar existência de agente de outro grupo;
//   - toda leitura é gravada na auditoria encadeada ANTES de responder (fail-closed:
//     se a auditoria falhar, não há dado para o operador);
//   - resultados: só ações read-only do catálogo (Changes == false) e só jobs
//     já finalizados. Nenhuma escrita sai daqui.
//   - saída de comando vem do agente (dado não confiável): vai como texto JSON,
//     truncada; o SPA precisa escapá-la (sem innerHTML).
package console

import (
	"encoding/json"
	"errors"
	"net/http"
	"time"
	"unicode/utf8"

	"github.com/eduardohenriquemoretti0-ops/fm-rmm/internal/catalog"
	"github.com/eduardohenriquemoretti0-ops/fm-rmm/internal/proto"
	"github.com/eduardohenriquemoretti0-ops/fm-rmm/internal/server"
)

const (
	// limiteResultados: quantos resultados de leitura o detalhe traz (os mais novos).
	limiteResultados = 5
	// limiteSaida: teto da saída de cada resultado no JSON (bytes).
	limiteSaida = 16 << 10
	// limiteIDAuditoria: id vindo da URL é gravado na auditoria só até este tamanho.
	limiteIDAuditoria = 64
)

// agenteView são os campos de lista (e a base do detalhe).
type agenteView struct {
	ID            string  `json:"id"`
	Hostname      string  `json:"hostname"`
	OS            string  `json:"os"`
	Status        string  `json:"status"`
	Grupo         string  `json:"grupo"`
	Online        bool    `json:"online"`
	UltimoContato *string `json:"ultimo_contato"` // RFC3339 UTC; null se nunca deu check-in
}

// resultadoView é um resultado de ação de leitura já finalizada.
type resultadoView struct {
	Job           string `json:"job"`
	Acao          string `json:"acao"`
	Status        string `json:"status"` // ok | erro | recusado
	CodigoSaida   int    `json:"codigo_saida"`
	Saida         string `json:"saida"`
	SaidaTruncada bool   `json:"saida_truncada"`
	Erro          string `json:"erro,omitempty"`
	TerminadoEm   string `json:"terminado_em"`
}

// agenteDetalhe junta os campos de lista e os últimos resultados.
type agenteDetalhe struct {
	agenteView
	Resultados []resultadoView `json:"resultados"`
}

// listarAgentes responde GET /api/agentes com os agentes visíveis ao operador.
func (c *Console) listarAgentes(w http.ResponseWriter, r *http.Request) {
	op, _, ok := OperadorDoContexto(r.Context())
	if !ok {
		negado(w)
		return
	}
	todos, err := c.st.Agents("")
	if err != nil {
		erroInterno(w)
		return
	}
	visiveis := []agenteView{}
	for _, a := range todos {
		err := c.st.CanAccess(op.TechName, a.ID)
		if errors.Is(err, server.ErrAccessDenied) || errors.Is(err, server.ErrNotFound) {
			continue // fora do RBAC: não entra na lista, nem na contagem
		}
		if err != nil {
			erroInterno(w)
			return
		}
		visiveis = append(visiveis, c.visaoDe(a))
	}
	if err := c.st.Audit("console.agentes.listados", op.ID, map[string]any{
		"total_agentes": len(todos), "retornados": len(visiveis),
	}); err != nil {
		erroInterno(w)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"agentes": visiveis})
}

// detalheAgente responde GET /api/agentes/{id}. Sem permissão ou inexistente:
// mesma resposta 404 (não vaza existência).
func (c *Console) detalheAgente(w http.ResponseWriter, r *http.Request) {
	op, _, ok := OperadorDoContexto(r.Context())
	if !ok {
		negado(w)
		return
	}
	id := r.PathValue("id")
	idAud := id
	if len(idAud) > limiteIDAuditoria {
		idAud = idAud[:limiteIDAuditoria]
	}

	err := c.st.CanAccess(op.TechName, id)
	permitido := err == nil
	if err != nil && !errors.Is(err, server.ErrAccessDenied) && !errors.Is(err, server.ErrNotFound) {
		erroInterno(w)
		return
	}
	if err := c.st.Audit("console.agente.consultado", op.ID, map[string]any{
		"agente": idAud, "permitido": permitido,
	}); err != nil {
		erroInterno(w)
		return
	}
	if !permitido {
		naoEncontrado(w)
		return
	}

	a, err := c.st.Agent(id)
	if errors.Is(err, server.ErrNotFound) {
		naoEncontrado(w)
		return
	}
	if err != nil {
		erroInterno(w)
		return
	}
	jobs, err := c.st.ResultadosDeLeitura(a.ID, acoesDeLeitura(a.OS), limiteResultados)
	if err != nil {
		erroInterno(w)
		return
	}
	res := make([]resultadoView, 0, len(jobs))
	for _, j := range jobs {
		res = append(res, resultadoDe(j))
	}
	writeJSON(w, http.StatusOK, agenteDetalhe{agenteView: c.visaoDe(a), Resultados: res})
}

// visaoDe monta os campos de lista a partir do agente.
func (c *Console) visaoDe(a server.Agent) agenteView {
	v := agenteView{
		ID:       a.ID,
		Hostname: a.Hostname,
		OS:       a.OS,
		Status:   a.Status,
		Grupo:    a.Grupo,
		Online:   a.Online(c.intervalo, c.agora()),
	}
	if a.LastSeen > 0 {
		s := time.Unix(a.LastSeen, 0).UTC().Format(time.RFC3339)
		v.UltimoContato = &s
	}
	return v
}

// acoesDeLeitura lista as ações do catálogo que NÃO alteram a máquina e existem
// para o sistema do agente. É o filtro dos resultados exibidos.
func acoesDeLeitura(goos string) []string {
	var out []string
	for _, nome := range catalog.Names() {
		a, ok := catalog.Get(nome)
		if !ok || a.Changes {
			continue
		}
		if _, ok := a.Scripts[goos]; ok {
			out = append(out, nome)
		}
	}
	return out
}

// resultadoDe converte o job persistido. Se o JSON do resultado não puder ser
// lido, devolve só os metadados do job (sem saída), sem derrubar a resposta.
func resultadoDe(j server.Job) resultadoView {
	v := resultadoView{
		Job:         j.ID,
		Acao:        j.Action,
		Status:      j.Status,
		TerminadoEm: time.Unix(j.FinishedAt, 0).UTC().Format(time.RFC3339),
	}
	var r proto.Result
	if j.Result == "" || json.Unmarshal([]byte(j.Result), &r) != nil {
		return v
	}
	v.CodigoSaida = r.ExitCode
	v.Saida, v.SaidaTruncada = truncaSaida(r.Output, limiteSaida)
	v.SaidaTruncada = v.SaidaTruncada || r.Truncated
	v.Erro = r.Error
	return v
}

// truncaSaida corta s em no máximo max bytes, sem quebrar um caractere UTF-8.
func truncaSaida(s string, max int) (string, bool) {
	if len(s) <= max {
		return s, false
	}
	corte := max
	for corte > 0 && !utf8.RuneStart(s[corte]) {
		corte--
	}
	return s[:corte], true
}

func naoEncontrado(w http.ResponseWriter) {
	writeJSON(w, http.StatusNotFound, map[string]string{"erro": "agente não encontrado"})
}

func erroInterno(w http.ResponseWriter) {
	writeJSON(w, http.StatusInternalServerError, map[string]string{"erro": "falha interna"})
}
