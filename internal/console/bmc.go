// Controle de energia de servidor por BMC/Redfish (Plano v2, §3.2), independente
// do SO. Rotas (todas atrás de cert + sessão + CSRF, e STEP-UP):
//
//	POST /api/bmc/status   host/porta/system_id + credencial do BMC -> estado de energia
//	POST /api/bmc/power    idem + acao                              -> envia o Reset
//
// DECISÃO DE SEGURANÇA: o console NÃO armazena credencial de BMC. O operador
// informa usuário+senha do BMC A CADA AÇÃO; a credencial é usada na hora e
// descartada: não vai ao banco, nem ao log, nem à auditoria, nem ao erro, nem à
// resposta. Só host/porta/system_id/ação/resultado entram na auditoria.
//
// Autorização (todas as camadas são exigidas):
//  1. o técnico do operador pertence EXATAMENTE ao grupo GrupoBMC (capacidade
//     sensível; o curinga '*' não vale; `techs grant NOME bmc`);
//  2. step-up válido;
//  3. o host:porta alvo está no INVENTÁRIO (`fmrmm-server bmc-hosts add ...`) e o
//     técnico pertence ao grupo daquele host (ou '*', como no acesso remoto).
//     Host fora do inventário e host de outro grupo respondem IGUAL (404
//     bmc_host_nao_encontrado), para não revelar quais BMCs existem; a auditoria
//     distingue o motivo.
//
// Brute-force: falhas (credencial recusada pelo BMC, host não permitido) são
// contadas por operador e por host; excedido o limite => 429 (bmc_limite.go).
// Requisições bem-sucedidas não contam.
//
// SSRF: o servidor disca para um destino informado pelo operador, então o host é
// validado (IP/hostname simples) e a conexão recusa loopback, link-local,
// multicast e não-especificado (checado no IP já resolvido, na hora do connect).
package console

import (
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"net/netip"
	"strconv"
	"time"

	"github.com/eduardohenriquemoretti0-ops/fm-rmm/internal/redfish"
	"github.com/eduardohenriquemoretti0-ops/fm-rmm/internal/server"
)

// GrupoBMC é o grupo de técnico que autoriza o controle de energia por BMC.
const GrupoBMC = "bmc"

const (
	limiteCorpoBMC   = 8 << 10
	timeoutBMC       = 20 * time.Second
	limiteCredencial = 256
)

// bmcReq é o corpo de /api/bmc/*. Usuario/Senha existem só durante a requisição.
type bmcReq struct {
	Host     string `json:"host"`
	Porta    int    `json:"porta"`
	SystemID string `json:"system_id"`
	Acao     string `json:"acao"`
	Usuario  string `json:"usuario"`
	Senha    string `json:"senha"`
	Insecure bool   `json:"insecure"`
}

// destinoProibidoPadrao: BMCs vivem em rede privada (permitida); o que se recusa é
// o que daria acesso ao próprio servidor ou a metadados/serviços de link-local.
func destinoProibidoPadrao(a netip.Addr) bool {
	return a.IsLoopback() || a.IsUnspecified() || a.IsLinkLocalUnicast() ||
		a.IsLinkLocalMulticast() || a.IsMulticast()
}

// auditaBMC registra SEM credencial (os campos são escolhidos a dedo, nunca o req inteiro).
func (c *Console) auditaBMC(evento, opID string, req bmcReq, resultado, motivo string) error {
	porta := req.Porta
	if porta == 0 {
		porta = 443
	}
	d := map[string]any{
		"host": truncaAud(req.Host), "porta": porta, "system_id": truncaAud(req.SystemID),
		"acao": truncaAud(req.Acao), "resultado": resultado, "insecure": req.Insecure,
	}
	if motivo != "" {
		d["motivo"] = motivo
	}
	return c.st.Audit(evento, opID, d)
}

func (c *Console) bmcStatus(w http.ResponseWriter, r *http.Request) { c.bmcHandler(w, r, false) }
func (c *Console) bmcPower(w http.ResponseWriter, r *http.Request)  { c.bmcHandler(w, r, true) }

func (c *Console) bmcHandler(w http.ResponseWriter, r *http.Request, poder bool) {
	op, thumb, ok := OperadorDoContexto(r.Context())
	_, tok, okS := SessaoDoContexto(r.Context())
	if !ok || !okS {
		negado(w)
		return
	}
	evento := "console.bmc.status"
	if poder {
		evento = "console.bmc.power"
	}
	var req bmcReq
	dec := json.NewDecoder(http.MaxBytesReader(w, r.Body, limiteCorpoBMC))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&req); err != nil {
		c.recusaBMC(w, op.ID, http.StatusBadRequest, "requisicao_invalida", evento, bmcReq{})
		return
	}
	senha, usuario := req.Senha, req.Usuario
	req.Senha, req.Usuario = "", "" // a partir daqui req é seguro de auditar/logar

	// 1. RBAC: grupo explícito
	if tem, err := c.st.TechTemGrupo(op.TechName, GrupoBMC); err != nil {
		erroInterno(w)
		return
	} else if !tem {
		c.recusaBMC(w, op.ID, http.StatusForbidden, "sem_permissao_bmc", evento, req)
		return
	}
	// 1b. lockout por operador (antes de qualquer trabalho)
	if esp := c.bmcLim.bloqueado(chaveOp(op.ID), c.agora()); esp > 0 {
		c.recusaBMC429(w, op.ID, esp, "operador", evento, req)
		return
	}
	// 2. step-up (também no status: evita usar o console para adivinhar senha de BMC)
	if !c.sessoes.StepUpValido(tok, thumb) {
		c.recusaBMC(w, op.ID, http.StatusForbidden, "step_up_necessario", evento, req)
		return
	}
	// 3. entradas
	if usuario == "" || senha == "" || len(usuario) > limiteCredencial || len(senha) > limiteCredencial {
		c.recusaBMC(w, op.ID, http.StatusBadRequest, "credencial_bmc_ausente", evento, req)
		return
	}
	if poder {
		if _, err := redfish.ValidaAcao(req.Acao); err != nil {
			c.recusaBMC(w, op.ID, http.StatusUnprocessableEntity, "acao_invalida", evento, req)
			return
		}
	} else {
		req.Acao = ""
	}
	if err := redfish.ValidaSystemID(req.SystemID); err != nil {
		c.recusaBMC(w, op.ID, http.StatusUnprocessableEntity, "system_id_invalido", evento, req)
		return
	}
	// 3b. inventário: host cadastrado E permitido a este técnico
	if err := c.st.BMCHostPermitido(req.Host, req.Porta, op.TechName); err != nil {
		if !errors.Is(err, server.ErrBMCHostDesconhecido) && !errors.Is(err, server.ErrBMCHostNegado) {
			erroInterno(w)
			return
		}
		motivo := "host_fora_do_inventario"
		if errors.Is(err, server.ErrBMCHostNegado) {
			motivo = "host_de_outro_grupo"
		}
		c.bmcLim.falha(chaveOp(op.ID), c.agora())
		_ = c.auditaBMC("console.bmc.recusada", op.ID, req, "recusado", motivo+" ("+evento+")")
		writeJSON(w, http.StatusNotFound, map[string]any{"erro": "bmc_host_nao_encontrado"})
		return
	}
	hk := chaveHost(req.Host, req.Porta)
	if esp := c.bmcLim.bloqueado(hk, c.agora()); esp > 0 {
		c.recusaBMC429(w, op.ID, esp, "host", evento, req)
		return
	}
	proibir := c.bmcProibirIP
	if proibir == nil {
		proibir = destinoProibidoPadrao
	}
	cli, err := redfish.Novo(redfish.Config{
		Host: req.Host, Porta: req.Porta, Usuario: usuario, Senha: senha,
		Insecure: req.Insecure, Timeout: timeoutBMC, RootCAs: c.bmcRoots, ProibirIP: proibir,
	})
	usuario, senha = "", "" // o cliente já guarda o que precisa; descarta as cópias locais
	if err != nil {
		c.recusaBMC(w, op.ID, http.StatusUnprocessableEntity, "host_invalido", evento, req)
		return
	}
	if req.Insecure {
		slog.Warn("bmc: modo inseguro (certificado do BMC NÃO validado)", "operador", op.ID, "host", req.Host)
	}

	// 4. executa
	ctx, cancel := context.WithTimeout(r.Context(), timeoutBMC)
	defer cancel()
	resp := map[string]any{"host": req.Host}
	if req.Insecure {
		resp["aviso"] = redfish.AvisoInsecure
	}
	var erroBMC error
	if poder {
		var id string
		id, erroBMC = cli.Reset(ctx, req.SystemID, req.Acao)
		req.SystemID = id
		resp["acao"], resp["system_id"] = req.Acao, id
	} else {
		var e redfish.Estado
		e, erroBMC = cli.Status(ctx, req.SystemID)
		req.SystemID = e.SystemID
		resp["estado"] = e
	}
	status, resultado := classificaBMC(erroBMC)
	if errors.Is(erroBMC, redfish.ErrAutenticacao) { // só credencial errada conta p/ lockout
		c.bmcLim.falha(chaveOp(op.ID), c.agora())
		c.bmcLim.falha(hk, c.agora())
	}
	if erroBMC != nil {
		resp = map[string]any{"erro": resultado}
		if req.Insecure {
			resp["aviso"] = redfish.AvisoInsecure
		}
	} else {
		resp["resultado"] = resultado
	}
	if err := c.auditaBMC(evento, op.ID, req, resultado, ""); err != nil {
		// a ação pode ter sido executada: falhar alto, sem esconder isso do operador
		writeJSON(w, http.StatusInternalServerError, map[string]string{"erro": "falha_de_auditoria", "resultado": resultado})
		return
	}
	writeJSON(w, status, resp)
}

// classificaBMC traduz o erro do cliente em status HTTP + código estável, sem texto do BMC.
func classificaBMC(err error) (int, string) {
	var eh *redfish.ErroHTTP
	switch {
	case err == nil:
		return http.StatusOK, "ok"
	case errors.Is(err, redfish.ErrAutenticacao):
		return http.StatusBadGateway, "bmc_credencial_recusada"
	case errors.Is(err, redfish.ErrDestinoBloq):
		return http.StatusUnprocessableEntity, "destino_nao_permitido"
	case errors.Is(err, redfish.ErrConexao):
		return http.StatusBadGateway, "bmc_inacessivel"
	case errors.As(err, &eh):
		return http.StatusBadGateway, "bmc_erro_http_" + strconv.Itoa(eh.Status)
	default:
		return http.StatusBadGateway, "bmc_resposta_invalida"
	}
}

func (c *Console) recusaBMC(w http.ResponseWriter, opID string, status int, codigo, evento string, req bmcReq) {
	_ = c.auditaBMC("console.bmc.recusada", opID, req, "recusado", codigo+" ("+evento+")")
	resp := map[string]any{"erro": codigo}
	if codigo == "step_up_necessario" {
		resp["step_up"] = true
	}
	writeJSON(w, status, resp)
}

// recusaBMC429 responde 429 + Retry-After e audita (sem credencial).
func (c *Console) recusaBMC429(w http.ResponseWriter, opID string, espera time.Duration, alvo, evento string, req bmcReq) {
	_ = c.auditaBMC("console.bmc.recusada", opID, req, "recusado", "limite_de_tentativas_"+alvo+" ("+evento+")")
	seg := int(espera.Round(time.Second) / time.Second)
	if seg < 1 {
		seg = 1
	}
	w.Header().Set("Retry-After", strconv.Itoa(seg))
	writeJSON(w, http.StatusTooManyRequests, map[string]any{"erro": "muitas_tentativas", "retry_after_s": seg})
}
