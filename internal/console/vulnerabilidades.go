// GET /api/agentes/{id}/vulnerabilidades — resumo de vulnerabilidades conhecidas
// (T3a). Somente leitura do banco: nunca chama o OSV (o scan roda no servidor,
// `fmrmm-server cve scan`), então uma queda do OSV não afeta o dashboard.
// RBAC e auditoria idênticos ao detalhe do agente (sem permissão = 404 igual a
// inexistente).
package console

import (
	"errors"
	"net/http"

	"github.com/eduardohenriquemoretti0-ops/fm-rmm/internal/server"
)

func (c *Console) vulnerabilidadesAgente(w http.ResponseWriter, r *http.Request) {
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
	if err := c.st.Audit("console.agente.vulnerabilidades", op.ID, map[string]any{
		"agente": idAud, "permitido": permitido,
	}); err != nil {
		erroInterno(w)
		return
	}
	if !permitido {
		naoEncontrado(w)
		return
	}
	res, err := c.st.ResumoVulns(id)
	if err != nil {
		erroInterno(w)
		return
	}
	writeJSON(w, http.StatusOK, res)
}
