// Listas read-only para a UI montar as AÇÕES DE ESCRITA por item/id (o operador
// escolhe de listas; nunca digita comando, corpo ou id de pacote).
//
//	GET /api/catalogo-software   itens do catálogo PUBLICADO (id, nome, gerenciador)
//	GET /api/biblioteca-scripts  entradas PUBLICADAS (id, nome, versao, interprete)
//	GET /api/acoes-disponiveis   ações de escrita + metadados de formulário
//
// Regras:
//   - cert + sessão (rotas GET: sem CSRF), como o resto da leitura;
//   - o catálogo/biblioteca guardados no banco foram verificados contra a RAIZ
//     na publicação (Publicar*); aqui só se PROJETAM os campos seguros. A chave
//     raiz não existe no console (nem deve existir);
//   - FICAM DE FORA, por construção (o tipo de saída nem tem o campo): corpo do
//     script, sha256, pkg_id exato, publisher, versão fixada do pacote, e
//     qualquer script/comando/receita do catálogo de ações;
//   - não há RBAC por agente aqui (as listas são globais); o RBAC por agente e o
//     step-up continuam sendo aplicados em POST /api/acoes, que é quem escreve;
//   - toda leitura é auditada ANTES de responder (fail-closed).
package console

import (
	"encoding/json"
	"net/http"
	"sort"

	"github.com/eduardohenriquemoretti0-ops/fm-rmm/internal/catalog"
	"github.com/eduardohenriquemoretti0-ops/fm-rmm/internal/redfish"
	"github.com/eduardohenriquemoretti0-ops/fm-rmm/internal/sign"
)

// softwareItemView: só o que a UI precisa para oferecer o item.
type softwareItemView struct {
	ID          string `json:"id"`
	Nome        string `json:"nome"`
	Gerenciador string `json:"gerenciador"`
}

type catalogoSoftwareView struct {
	Versao int                `json:"versao"` // 0 = nada publicado
	Itens  []softwareItemView `json:"itens"`
}

// scriptView: NUNCA tem corpo nem sha256.
type scriptView struct {
	ID         string `json:"id"`
	Nome       string `json:"nome"`
	Versao     string `json:"versao"`
	Interprete string `json:"interprete"`
}

type bibliotecaScriptsView struct {
	Versao  int          `json:"versao"` // 0 = nada publicado
	Scripts []scriptView `json:"scripts"`
}

// operadorLeitura devolve o operador do contexto ou responde 401.
func operadorLeitura(w http.ResponseWriter, r *http.Request) (string, bool) {
	op, _, ok := OperadorDoContexto(r.Context())
	if !ok {
		negado(w)
		return "", false
	}
	return op.ID, true
}

func (c *Console) listarCatalogoSoftware(w http.ResponseWriter, r *http.Request) {
	opID, ok := operadorLeitura(w, r)
	if !ok {
		return
	}
	versao, raw, _, err := c.st.CatalogoSoftwareAtual()
	if err != nil {
		erroInterno(w)
		return
	}
	out := catalogoSoftwareView{Versao: versao, Itens: []softwareItemView{}}
	if versao > 0 {
		var cat sign.SoftwareCatalog
		if err := json.Unmarshal(raw, &cat); err != nil {
			erroInterno(w)
			return
		}
		for _, it := range cat.Items {
			out.Itens = append(out.Itens, softwareItemView{ID: it.ID, Nome: it.Nome, Gerenciador: it.Gerenciador})
		}
	}
	if err := c.st.Audit("console.lista.catalogo_software", opID, map[string]any{"versao": versao, "itens": len(out.Itens)}); err != nil {
		erroInterno(w)
		return
	}
	writeJSON(w, http.StatusOK, out)
}

func (c *Console) listarBibliotecaScripts(w http.ResponseWriter, r *http.Request) {
	opID, ok := operadorLeitura(w, r)
	if !ok {
		return
	}
	versao, raw, _, err := c.st.BibliotecaScriptsAtual()
	if err != nil {
		erroInterno(w)
		return
	}
	out := bibliotecaScriptsView{Versao: versao, Scripts: []scriptView{}}
	if versao > 0 {
		var lib sign.ScriptLibrary
		if err := json.Unmarshal(raw, &lib); err != nil {
			erroInterno(w)
			return
		}
		for _, s := range lib.Scripts {
			out.Scripts = append(out.Scripts, scriptView{ID: s.ID, Nome: s.Nome, Versao: s.Versao, Interprete: s.Interprete})
		}
	}
	if err := c.st.Audit("console.lista.biblioteca_scripts", opID, map[string]any{"versao": versao, "scripts": len(out.Scripts)}); err != nil {
		erroInterno(w)
		return
	}
	writeJSON(w, http.StatusOK, out)
}

// ------------------------------------------------------------ ações

// Tipos de campo que a UI sabe montar.
const (
	campoTexto         = "texto"                  // entrada livre validada no envio (ex.: MAC)
	campoLista         = "lista"                  // escolhe de valores_por_so
	campoItemSoftware  = "item_catalogo_software" // escolhe de GET /api/catalogo-software (id)
	campoScriptID      = "script_biblioteca_id"   // escolhe de GET /api/biblioteca-scripts (id)
	campoScriptVersao  = "script_biblioteca_versao"
	campoConfirmWipe   = "confirmacao_destrutiva" // a UI exige digitar "WIPE-<id do agente>"
	origemAgente       = "agente"                 // POST /api/acoes (job assinado)
	origemBMC          = "bmc"                    // POST /api/bmc/power
	formatoConfirmWipe = "WIPE-{agent_id}"
)

type paramView struct {
	Nome        string              `json:"nome"`
	Rotulo      string              `json:"rotulo"`
	Obrigatorio bool                `json:"obrigatorio"`
	Tipo        string              `json:"tipo"`
	Valores     map[string][]string `json:"valores_por_so,omitempty"` // só em tipo=lista
	Formato     string              `json:"formato,omitempty"`        // só em confirmação
}

type acaoView struct {
	Nome        string      `json:"nome"`
	Rotulo      string      `json:"rotulo"`
	Origem      string      `json:"origem"`
	Rota        string      `json:"rota"`
	Destrutiva  bool        `json:"destrutiva"`
	ExigeStepUp bool        `json:"exige_step_up"`
	SO          []string    `json:"so,omitempty"` // SOs suportados (vazio em BMC)
	Params      []paramView `json:"params"`
}

// tipoDoParam decide o tipo de campo para a UI. Ações/params ligados às listas
// publicadas viram seletores por id; o resto segue a forma do catálogo.
func tipoDoParam(acao, param string, p catalog.Param) string {
	switch {
	case (acao == "instalar_pacote" || acao == "desinstalar_pacote") && param == "item_id":
		return campoItemSoftware
	case acao == "rodar_script" && param == "script_id":
		return campoScriptID
	case acao == "rodar_script" && param == "versao":
		return campoScriptVersao
	case acao == "wipe_remoto" && param == "confirmacao":
		return campoConfirmWipe
	case len(p.Allowed) > 0:
		return campoLista
	}
	return campoTexto
}

// acoesDisponiveis monta a lista a partir do catálogo FECHADO (Changes==true).
// Só nome/rótulo/flags/params: nada de Scripts, Timeout ou padrões (regex).
// BMC entra só para quem tem o grupo bmc. Step-up: POST /api/acoes e o BMC o
// exigem para QUALQUER ação de escrita, por isso é true em todas.
func (c *Console) acoesDisponiveis(tech string) ([]acaoView, error) {
	out := []acaoView{}
	for _, nome := range catalog.Names() {
		a, ok := catalog.Get(nome)
		if !ok || !a.Changes {
			continue
		}
		v := acaoView{
			Nome: a.Name, Rotulo: a.Desc, Origem: origemAgente, Rota: "/api/acoes",
			Destrutiva: a.Destructive, ExigeStepUp: true, Params: []paramView{},
		}
		for so := range a.Scripts {
			v.SO = append(v.SO, so)
		}
		sort.Strings(v.SO)
		pn := make([]string, 0, len(a.Params))
		for k := range a.Params {
			pn = append(pn, k)
		}
		sort.Strings(pn)
		for _, k := range pn {
			p := a.Params[k]
			pv := paramView{Nome: k, Rotulo: p.Desc, Obrigatorio: !p.Optional, Tipo: tipoDoParam(a.Name, k, p)}
			switch pv.Tipo {
			case campoLista:
				pv.Valores = p.Allowed
			case campoConfirmWipe:
				pv.Formato = formatoConfirmWipe
			}
			v.Params = append(v.Params, pv)
		}
		out = append(out, v)
	}
	tem, err := c.st.TechTemGrupo(tech, GrupoBMC)
	if err != nil {
		return nil, err
	}
	if tem {
		acoes := []string{redfish.AcaoOn, redfish.AcaoForceOff, redfish.AcaoGracefulShutdown, redfish.AcaoForceRestart, redfish.AcaoGracefulRestart}
		out = append(out, acaoView{
			Nome: "bmc_power", Rotulo: "Controle de energia do servidor por BMC/Redfish (credencial do BMC informada a cada ação, nunca guardada)",
			Origem: origemBMC, Rota: "/api/bmc/power", ExigeStepUp: true,
			Params: []paramView{
				{Nome: "host", Rotulo: "host ou IP do BMC", Obrigatorio: true, Tipo: campoTexto},
				{Nome: "porta", Rotulo: "porta (padrão 443)", Tipo: campoTexto},
				{Nome: "system_id", Rotulo: "id do sistema Redfish", Tipo: campoTexto},
				{Nome: "acao", Rotulo: "ação de energia", Obrigatorio: true, Tipo: campoLista, Valores: map[string][]string{"bmc": acoes}},
				{Nome: "usuario", Rotulo: "usuário do BMC", Obrigatorio: true, Tipo: campoTexto},
				{Nome: "senha", Rotulo: "senha do BMC", Obrigatorio: true, Tipo: campoTexto},
			},
		})
	}
	return out, nil
}

func (c *Console) listarAcoesDisponiveis(w http.ResponseWriter, r *http.Request) {
	op, _, ok := OperadorDoContexto(r.Context())
	if !ok {
		negado(w)
		return
	}
	acoes, err := c.acoesDisponiveis(op.TechName)
	if err != nil {
		erroInterno(w)
		return
	}
	if err := c.st.Audit("console.lista.acoes_disponiveis", op.ID, map[string]any{"acoes": len(acoes)}); err != nil {
		erroInterno(w)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"acoes": acoes})
}
