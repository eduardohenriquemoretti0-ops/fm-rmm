// Ações de escrita do console (T5c): POST /api/acoes e o registro da chave de
// assinatura do operador.
//
// Princípio inegociável: o operador assina NO NAVEGADOR. O servidor NÃO assina e
// NÃO guarda chave de assinatura: recebe o job/concessão JÁ ASSINADO, confere e
// ENFILEIRA o objeto com a assinatura original do operador. O agente verifica
// contra o trust-set (raiz + lista de operadores). Formato exato dos bytes
// assinados: docs/console-assinatura-acao.md.
//
// Ordem das checagens (fail-closed, cada uma auditada ao recusar):
//
//	cert+sessão+CSRF -> chave do operador/key_id -> assinatura Ed25519 sobre os
//	bytes exatos -> forma canônica (json.Marshal da struct == bytes) -> regras do
//	payload (VerifyJobAny/VerifyGrantAny: versão, agente, TTL, expiração) ->
//	vínculo com o operador (issuer, technician) -> RBAC (404 igual a "não
//	existe") -> catálogo/relay -> step-up -> nonce (anti-replay) + enfileirar.
package console

import (
	"bytes"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"net/http"
	"regexp"

	"github.com/eduardohenriquemoretti0-ops/fm-rmm/internal/catalog"
	"github.com/eduardohenriquemoretti0-ops/fm-rmm/internal/proto"
	"github.com/eduardohenriquemoretti0-ops/fm-rmm/internal/server"
	"github.com/eduardohenriquemoretti0-ops/fm-rmm/internal/sign"
)

const (
	TipoAcaoJob   = "job"
	TipoAcaoGrant = "grant"

	// limiteCorpoAcao: teto do corpo de /api/acoes (um job/concessão é pequeno).
	limiteCorpoAcao = 64 << 10
	// minRelayToken: o token do relay (gerado no navegador) precisa de entropia.
	minRelayToken = 32
	// ProvaChaveContexto prefixa a mensagem da prova de posse da chave pública.
	ProvaChaveContexto = "fmrmm-signing-pub-v1"
)

// nonceValido: o nonce é o job_id/session_id escolhido pelo navegador.
var nonceValido = regexp.MustCompile(`^[A-Za-z0-9_-]{8,64}$`)

// ConfigurarRelay define o único relay (wss://) aceito em concessões de sessão
// remota. Sem isso, concessões são recusadas (o operador não escolhe o relay).
func (c *Console) ConfigurarRelay(relayBase string) { c.relayBase = relayBase }

// acaoReq é o corpo de POST /api/acoes. Payload são os BYTES EXATOS assinados
// (base64 padrão, como []byte do Go); nada é re-serializado antes de verificar.
type acaoReq struct {
	Tipo    string `json:"tipo"` // job | grant
	Payload []byte `json:"payload"`
	Sig     []byte `json:"sig"`
	KeyID   string `json:"key_id"`
}

// recusaAcao audita (melhor esforço) e responde sem detalhe além do necessário.
func (c *Console) recusaAcao(w http.ResponseWriter, opID string, status int, codigo string, extra map[string]any) {
	dados := map[string]any{"motivo": codigo}
	for k, v := range extra {
		dados[k] = v
	}
	_ = c.st.Audit("console.acao.recusada", opID, dados)
	resp := map[string]any{"erro": codigo}
	if codigo == "step_up_necessario" {
		resp["step_up"] = true
	}
	writeJSON(w, status, resp)
}

func (c *Console) criarAcao(w http.ResponseWriter, r *http.Request) {
	op, thumb, ok := OperadorDoContexto(r.Context())
	_, tok, okS := SessaoDoContexto(r.Context())
	if !ok || !okS {
		negado(w)
		return
	}
	var req acaoReq
	dec := json.NewDecoder(http.MaxBytesReader(w, r.Body, limiteCorpoAcao))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&req); err != nil || (req.Tipo != TipoAcaoJob && req.Tipo != TipoAcaoGrant) {
		c.recusaAcao(w, op.ID, http.StatusBadRequest, "requisicao_invalida", nil)
		return
	}

	// 1. a chave do operador vem do STORE (nunca do corpo); key_id precisa bater
	if op.SigningPub == "" {
		c.recusaAcao(w, op.ID, http.StatusForbidden, "operador_sem_chave_de_assinatura", nil)
		return
	}
	pub, err := sign.DecodePub(op.SigningPub)
	if err != nil {
		c.recusaAcao(w, op.ID, http.StatusInternalServerError, "chave_do_operador_invalida", nil)
		return
	}
	if req.KeyID != sign.KeyID(pub) {
		c.recusaAcao(w, op.ID, http.StatusUnauthorized, "assinatura_invalida", map[string]any{"key_id": truncaAud(req.KeyID)})
		return
	}
	// 1b. revogação efetiva: a chave precisa estar na lista PUBLICADA (a que o
	// agente confia), não só ativa no banco. Senão o agente descartaria a ação.
	publicada, err := c.st.OperadorNaListaPublicada(req.KeyID, c.agora())
	if err != nil {
		c.recusaAcao(w, op.ID, http.StatusInternalServerError, "lista_indisponivel", nil)
		return
	}
	if !publicada {
		c.recusaAcao(w, op.ID, http.StatusForbidden, "operador_nao_publicado", map[string]any{"key_id": truncaAud(req.KeyID)})
		return
	}
	// 2. assinatura sobre os bytes exatos
	if len(req.Sig) != ed25519.SignatureSize || !ed25519.Verify(pub, req.Payload, req.Sig) {
		c.recusaAcao(w, op.ID, http.StatusUnauthorized, "assinatura_invalida", map[string]any{"key_id": req.KeyID})
		return
	}

	switch req.Tipo {
	case TipoAcaoJob:
		c.acaoJob(w, op, pub, thumb, tok, req)
	default:
		c.acaoGrant(w, op, pub, thumb, tok, req)
	}
}

func (c *Console) acaoJob(w http.ResponseWriter, op server.Operator, pub ed25519.PublicKey, thumb, tok string, req acaoReq) {
	var p proto.JobPayload
	if !decodificaCanonico(req.Payload, &p) {
		c.recusaAcao(w, op.ID, http.StatusBadRequest, "payload_nao_canonico", nil)
		return
	}
	sj := proto.SignedJob{Payload: req.Payload, Sig: req.Sig, KeyID: req.KeyID}
	if _, err := sign.VerifyJobAny(sign.SingleKey(pub), sj, p.AgentID, c.agora()); err != nil {
		c.recusaAcao(w, op.ID, statusRegra(err), codigoRegra(err), map[string]any{"job": truncaAud(p.JobID)})
		return
	}
	if p.Issuer != op.ID || !nonceValido.MatchString(p.JobID) {
		c.recusaAcao(w, op.ID, http.StatusForbidden, "emissor_ou_nonce_invalido", map[string]any{"job": truncaAud(p.JobID)})
		return
	}
	a, okRBAC := c.rbac(w, op, p.AgentID)
	if !okRBAC {
		return
	}
	if a.Status != "approved" {
		c.recusaAcao(w, op.ID, http.StatusConflict, "agente_indisponivel", map[string]any{"agente": p.AgentID})
		return
	}
	if _, err := catalog.Validate(p.Action, a.OS, p.Params); err != nil {
		c.recusaAcao(w, op.ID, http.StatusUnprocessableEntity, "acao_fora_do_catalogo", map[string]any{"acao": truncaAud(p.Action)})
		return
	}
	if !c.sessoes.StepUpValido(tok, thumb) {
		c.recusaAcao(w, op.ID, http.StatusForbidden, "step_up_necessario", map[string]any{"job": p.JobID})
		return
	}
	if err := c.st.EnfileirarJobDoOperador(op.ID, p, sj); err != nil {
		c.falhaEnfileirar(w, op.ID, err, p.JobID)
		return
	}
	if err := c.st.Audit("console.acao.enfileirada", op.ID, map[string]any{
		"tipo": TipoAcaoJob, "job": p.JobID, "agente": p.AgentID, "acao": p.Action, "params": p.Params, "chave": req.KeyID,
	}); err != nil {
		erroInterno(w)
		return
	}
	writeJSON(w, http.StatusAccepted, map[string]string{"job": p.JobID, "estado": "enfileirado"})
}

func (c *Console) acaoGrant(w http.ResponseWriter, op server.Operator, pub ed25519.PublicKey, thumb, tok string, req acaoReq) {
	var g proto.RemoteGrant
	if !decodificaCanonico(req.Payload, &g) {
		c.recusaAcao(w, op.ID, http.StatusBadRequest, "payload_nao_canonico", nil)
		return
	}
	sg := proto.SignedGrant{Payload: req.Payload, Sig: req.Sig, KeyID: req.KeyID}
	if _, err := sign.VerifyGrantAny(sign.SingleKey(pub), sg, g.AgentID, c.agora()); err != nil {
		c.recusaAcao(w, op.ID, statusRegra(err), codigoRegra(err), map[string]any{"sessao": truncaAud(g.SessionID)})
		return
	}
	// a concessão é do PRÓPRIO operador: issuer e technician amarrados a ele
	if g.Issuer != op.ID || g.Technician != op.TechName || !nonceValido.MatchString(g.SessionID) {
		c.recusaAcao(w, op.ID, http.StatusForbidden, "emissor_ou_nonce_invalido", map[string]any{"sessao": truncaAud(g.SessionID)})
		return
	}
	a, okRBAC := c.rbac(w, op, g.AgentID)
	if !okRBAC {
		return
	}
	if a.Status != "approved" {
		c.recusaAcao(w, op.ID, http.StatusConflict, "agente_indisponivel", map[string]any{"agente": g.AgentID})
		return
	}
	// o operador não escolhe o relay: só o configurado; token com entropia
	if c.relayBase == "" || g.RelayURL != c.relayBase || len(g.RelayToken) < minRelayToken {
		c.recusaAcao(w, op.ID, http.StatusUnprocessableEntity, "relay_invalido", map[string]any{"sessao": g.SessionID})
		return
	}
	if !c.sessoes.StepUpValido(tok, thumb) {
		c.recusaAcao(w, op.ID, http.StatusForbidden, "step_up_necessario", map[string]any{"sessao": g.SessionID})
		return
	}
	if err := c.st.EnfileirarGrantDoOperador(op.ID, g, sg); err != nil {
		c.falhaEnfileirar(w, op.ID, err, g.SessionID)
		return
	}
	// sem relay_token/media_secret na auditoria
	if err := c.st.Audit("console.acao.enfileirada", op.ID, map[string]any{
		"tipo": TipoAcaoGrant, "sessao": g.SessionID, "agente": g.AgentID, "tecnico": g.Technician,
		"modo": g.Mode, "motor": g.Engine, "chave": req.KeyID, "indicador": "sempre visível",
	}); err != nil {
		erroInterno(w)
		return
	}
	writeJSON(w, http.StatusAccepted, map[string]string{"sessao": g.SessionID, "estado": "enfileirado"})
}

// rbac confere CanAccess(op.TechName, agente). Sem permissão ou agente
// inexistente: a MESMA resposta 404 (não vaza existência).
func (c *Console) rbac(w http.ResponseWriter, op server.Operator, agentID string) (server.Agent, bool) {
	err := c.st.CanAccess(op.TechName, agentID)
	if errors.Is(err, server.ErrAccessDenied) || errors.Is(err, server.ErrNotFound) {
		c.recusaAcao(w, op.ID, http.StatusNotFound, "agente_nao_encontrado", map[string]any{"agente": truncaAud(agentID)})
		return server.Agent{}, false
	}
	if err != nil {
		erroInterno(w)
		return server.Agent{}, false
	}
	a, err := c.st.Agent(agentID)
	if err != nil {
		c.recusaAcao(w, op.ID, http.StatusNotFound, "agente_nao_encontrado", map[string]any{"agente": truncaAud(agentID)})
		return server.Agent{}, false
	}
	return a, true
}

func (c *Console) falhaEnfileirar(w http.ResponseWriter, opID string, err error, id string) {
	if errors.Is(err, server.ErrReplay) {
		c.recusaAcao(w, opID, http.StatusConflict, "nonce_repetido", map[string]any{"id": truncaAud(id)})
		return
	}
	erroInterno(w)
}

// decodificaCanonico interpreta raw em v (campos desconhecidos recusados) e
// exige que json.Marshal(v) devolva EXATAMENTE raw: uma só representação válida.
func decodificaCanonico(raw []byte, v any) bool {
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	if err := dec.Decode(v); err != nil {
		return false
	}
	again, err := json.Marshal(v)
	return err == nil && bytes.Equal(again, raw)
}

func statusRegra(err error) int {
	switch {
	case errors.Is(err, sign.ErrExpired):
		return http.StatusGone
	case errors.Is(err, sign.ErrSignature):
		return http.StatusUnauthorized
	}
	return http.StatusUnprocessableEntity
}

func codigoRegra(err error) string {
	switch {
	case errors.Is(err, sign.ErrExpired):
		return "acao_expirada"
	case errors.Is(err, sign.ErrSignature):
		return "assinatura_invalida"
	case errors.Is(err, sign.ErrNotYet):
		return "acao_emitida_no_futuro"
	case errors.Is(err, sign.ErrTTL), errors.Is(err, sign.ErrGrantTTL):
		return "validade_acima_do_maximo"
	}
	return "payload_invalido"
}

func truncaAud(s string) string {
	if len(s) > limiteIDAuditoria {
		return s[:limiteIDAuditoria]
	}
	return s
}

// ---------------------------------------------------- chave de assinatura

// MensagemProvaChave é o que a chave de assinatura assina para provar posse ao
// se registrar: "fmrmm-signing-pub-v1\n<operator_id>\n<pub base64 padrão>".
func MensagemProvaChave(operatorID, pubB64 string) []byte {
	return []byte(ProvaChaveContexto + "\n" + operatorID + "\n" + pubB64)
}

type chaveReq struct {
	SigningPub string `json:"signing_pub"` // Ed25519, base64 padrão
	Prova      []byte `json:"prova"`       // assinatura de MensagemProvaChave pela própria chave
}

// registrarChaveAssinatura cadastra a pública de assinatura do PRÓPRIO operador
// (o navegador gera o par; a privada nunca sai de lá). Regras:
//   - mTLS + sessão + CSRF + step-up recente;
//   - prova de posse: a pública assina "contexto\noperador\npub";
//   - só a PRIMEIRA vez: se já existe chave, 409. Troca/rotação é do admin, fora
//     de banda (um token de sessão roubado não consegue trocar a chave);
//   - registrar NÃO concede confiança no agente: o agente só aceita a chave
//     depois que o admin a inclui na lista de signers assinada offline pela raiz.
func (c *Console) registrarChaveAssinatura(w http.ResponseWriter, r *http.Request) {
	op, thumb, ok := OperadorDoContexto(r.Context())
	_, tok, okS := SessaoDoContexto(r.Context())
	if !ok || !okS {
		negado(w)
		return
	}
	var req chaveReq
	dec := json.NewDecoder(http.MaxBytesReader(w, r.Body, limiteCorpo))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&req); err != nil {
		c.recusaChave(w, op.ID, http.StatusBadRequest, "requisicao_invalida")
		return
	}
	pub, err := sign.DecodePub(req.SigningPub)
	if err != nil || req.SigningPub != sign.EncodePub(pub) {
		c.recusaChave(w, op.ID, http.StatusBadRequest, "chave_invalida")
		return
	}
	if len(req.Prova) != ed25519.SignatureSize || !ed25519.Verify(pub, MensagemProvaChave(op.ID, req.SigningPub), req.Prova) {
		c.recusaChave(w, op.ID, http.StatusUnauthorized, "prova_de_posse_invalida")
		return
	}
	if !c.sessoes.StepUpValido(tok, thumb) {
		c.recusaChave(w, op.ID, http.StatusForbidden, "step_up_necessario")
		return
	}
	if err := c.st.DefinirChaveAssinaturaSeVazia(op.ID, req.SigningPub); err != nil {
		if errors.Is(err, server.ErrChaveJaDefinida) {
			c.recusaChave(w, op.ID, http.StatusConflict, "chave_ja_definida")
			return
		}
		c.recusaChave(w, op.ID, http.StatusConflict, "chave_indisponivel") // ex.: já usada por outro operador
		return
	}
	if err := c.st.Audit("console.chave_assinatura.registrada", op.ID, map[string]any{"key_id": sign.KeyID(pub)}); err != nil {
		erroInterno(w)
		return
	}
	writeJSON(w, http.StatusCreated, map[string]string{"key_id": sign.KeyID(pub)})
}

func (c *Console) recusaChave(w http.ResponseWriter, opID string, status int, codigo string) {
	_ = c.st.Audit("console.chave_assinatura.recusada", opID, map[string]any{"motivo": codigo})
	resp := map[string]any{"erro": codigo}
	if codigo == "step_up_necessario" {
		resp["step_up"] = true
	}
	writeJSON(w, status, resp)
}
