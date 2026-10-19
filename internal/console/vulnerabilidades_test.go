package console

import (
	"encoding/json"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/eduardohenriquemoretti0-ops/fm-rmm/internal/server"
)

// GET /api/agentes/{id}/vulnerabilidades: shape, RBAC (404 igual a inexistente)
// e agente nunca escaneado (200 com escaneado=false, sem rede).
func TestVulnerabilidadesEndpoint(t *testing.T) {
	c := novoCenario(t)
	st := c.a.f.st
	err := st.SalvarScan(server.ResumoScan{
		AgentID: c.ag1, JobID: "j1", ItensTotal: 3, Avaliados: 1, NaoAvaliados: 2,
		NaoAvaliadosRisco: []server.NaoAvaliado{{Pacote: "Google Chrome", Versao: "120", Motivo: "sem fonte"}},
	}, []server.Achado{{
		VulnID: "DSA-1", CVEID: "CVE-2099-1", Pacote: "openssl", Versao: "3.0.1",
		Severidade: "CRITICAL", Pontuacao: 9.8, FixedVersion: "3.0.11", Fonte: server.FonteOSV,
	}}, true, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	ckA := c.a.cookieDe(t, "op-a", c.certA)

	rec := c.get(t, "/api/agentes/"+c.ag1+"/vulnerabilidades", c.certA, ckA)
	if rec.Code != http.StatusOK {
		t.Fatalf("= %d: %s", rec.Code, rec.Body.String())
	}
	var r struct {
		Escaneado        bool           `json:"escaneado"`
		Total            int            `json:"total"`
		PorSeveridade    map[string]int `json:"por_severidade"`
		Vulnerabilidades []struct {
			CVEID        string `json:"cve_id"`
			FixedVersion string `json:"fixed_version"`
			VistoEm      string `json:"visto_em"`
		} `json:"vulnerabilidades"`
		NaoAvaliadosAltoRisco []map[string]string `json:"nao_avaliados_alto_risco"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &r); err != nil {
		t.Fatal(err)
	}
	if !r.Escaneado || r.Total != 1 || r.PorSeveridade["CRITICAL"] != 1 ||
		r.Vulnerabilidades[0].CVEID != "CVE-2099-1" || r.Vulnerabilidades[0].FixedVersion != "3.0.11" ||
		r.Vulnerabilidades[0].VistoEm == "" || len(r.NaoAvaliadosAltoRisco) != 1 {
		t.Errorf("shape inesperado: %s", rec.Body.String())
	}

	// nunca escaneado (ag3, mesmo grupo): 200 vazio
	rec = c.get(t, "/api/agentes/"+c.ag3+"/vulnerabilidades", c.certA, ckA)
	if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), `"escaneado":false`) ||
		!strings.Contains(rec.Body.String(), `"vulnerabilidades":[]`) {
		t.Errorf("nunca escaneado: %d %s", rec.Code, rec.Body.String())
	}

	// RBAC: agente de outro grupo == inexistente (404 idêntico)
	fora := c.get(t, "/api/agentes/"+c.ag2+"/vulnerabilidades", c.certA, ckA)
	inex := c.get(t, "/api/agentes/ag-nao-existe/vulnerabilidades", c.certA, ckA)
	if fora.Code != http.StatusNotFound || fora.Body.String() != inex.Body.String() {
		t.Errorf("fora=%d %q inex=%d %q", fora.Code, fora.Body.String(), inex.Code, inex.Body.String())
	}
	// sem sessão: negado
	if sem := c.get(t, "/api/agentes/"+c.ag1+"/vulnerabilidades", c.certA, nil); sem.Code == http.StatusOK {
		t.Errorf("sem sessão = %d", sem.Code)
	}
}
