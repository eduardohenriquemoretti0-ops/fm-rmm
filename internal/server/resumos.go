// Resumos compactos para o grid do console (§3.4): só LEEM o que já está no
// banco (último scan de CVE e último resultado de `atualizacoes`/`saude`).
// Nunca disparam scan nem job. Os parsers são tolerantes: entrada inesperada
// devolve o que deu para extrair + Aviso, nunca erro nem panic.
package server

import (
	"database/sql"
	"encoding/json"
	"errors"
	"strconv"
	"strings"
	"time"

	"github.com/eduardohenriquemoretti0-ops/fm-rmm/internal/proto"
)

// VulnCompacto é o resumo de CVE do grid.
type VulnCompacto struct {
	Escaneado     bool           `json:"escaneado"`
	EscaneadoEm   *string        `json:"escaneado_em"`
	Total         int            `json:"total"`
	PorSeveridade map[string]int `json:"por_severidade"`
}

// UpdatesResumo: Pendentes/ReinicioPendente nil = desconhecido.
type UpdatesResumo struct {
	Pendentes        *int   `json:"pendentes"`
	ReinicioPendente *bool  `json:"reinicio_pendente"`
	Aviso            string `json:"aviso,omitempty"`
}

// SaudeResumo: Estavel/Eventos nil = desconhecido.
type SaudeResumo struct {
	Estavel *bool  `json:"estavel"`
	Eventos *int   `json:"eventos"`
	Aviso   string `json:"aviso,omitempty"`
}

// ResumoVulnsCompacto lê só o cabeçalho do scan e a contagem por severidade
// (sem carregar a lista de achados). Nunca escaneado: Escaneado=false, Total=0.
func (s *Store) ResumoVulnsCompacto(agentID string) (VulnCompacto, error) {
	r := VulnCompacto{PorSeveridade: map[string]int{}}
	sc, ok, err := s.UltimoScan(agentID)
	if err != nil || !ok {
		return r, err
	}
	t := timeRFC3339(sc.EscaneadoEm)
	r.Escaneado, r.EscaneadoEm = true, &t
	rows, err := s.db.Query(`SELECT severidade, COUNT(*) FROM vulnerabilidades WHERE agent_id=? GROUP BY severidade`, agentID)
	if err != nil {
		return r, err
	}
	defer rows.Close()
	for rows.Next() {
		var sev string
		var n int
		if err := rows.Scan(&sev, &n); err != nil {
			return r, err
		}
		r.PorSeveridade[sev] = n
		r.Total += n
	}
	return r, rows.Err()
}

// UltimoResultadoOK devolve o job finalizado com status ok mais novo da ação.
func (s *Store) UltimoResultadoOK(agentID, acao string) (Job, bool, error) {
	j, err := scanJob(s.db.QueryRow(`SELECT `+jobCols+` FROM jobs WHERE agent_id=? AND action=? AND status='ok' AND finished_at>0
		ORDER BY finished_at DESC, id DESC LIMIT 1`, agentID, acao))
	if errors.Is(err, sql.ErrNoRows) {
		return j, false, nil
	}
	return j, err == nil, err
}

// ResumoUpdates e ResumoSaude leem o último resultado ok; sem resultado, tudo nil.
func (s *Store) ResumoUpdates(agentID string) (UpdatesResumo, error) {
	j, ok, err := s.UltimoResultadoOK(agentID, "atualizacoes")
	if err != nil || !ok {
		return UpdatesResumo{}, err
	}
	return ParseAtualizacoes(saidaDe(j.Result)), nil
}

func (s *Store) ResumoSaude(agentID string) (SaudeResumo, error) {
	j, ok, err := s.UltimoResultadoOK(agentID, "saude")
	if err != nil || !ok {
		return SaudeResumo{}, err
	}
	return ParseSaude(saidaDe(j.Result)), nil
}

// saidaDe extrai Output do proto.Result gravado; JSON inválido vira "".
func saidaDe(result string) string {
	var r proto.Result
	if json.Unmarshal([]byte(result), &r) != nil {
		return ""
	}
	return r.Output
}

func ptr[T any](v T) *T { return &v }

// semBOM tira BOM UTF-8 e espaços (PowerShell costuma emitir BOM).
func semBOM(s string) string {
	return strings.TrimSpace(strings.TrimPrefix(strings.TrimSpace(s), "\ufeff"))
}

// simNao interpreta "sim"/"nao"/true/false.
func simNao(v string) (bool, bool) {
	switch strings.ToLower(strings.TrimSpace(v)) {
	case "sim", "true", "yes":
		return true, true
	case "nao", "não", "false", "no":
		return false, true
	}
	return false, false
}

// ParseAtualizacoes aceita o JSON do Windows (reinicio_pendente; opcionalmente
// `pendentes`/`upgradable` como lista ou número) e o texto do Linux/macOS.
func ParseAtualizacoes(out string) UpdatesResumo {
	out = semBOM(out)
	var r UpdatesResumo
	if out == "" {
		r.Aviso = "saída vazia"
		return r
	}
	if out[0] == '{' {
		var m map[string]json.RawMessage
		if err := json.Unmarshal([]byte(out), &m); err != nil {
			r.Aviso = "JSON inválido"
			return r
		}
		if raw, ok := m["reinicio_pendente"]; ok {
			var b bool
			if json.Unmarshal(raw, &b) == nil {
				r.ReinicioPendente = &b
			}
		}
		for _, k := range []string{"pendentes", "upgradable"} {
			raw, ok := m[k]
			if !ok {
				continue
			}
			var lista []json.RawMessage
			var n int
			if json.Unmarshal(raw, &lista) == nil {
				r.Pendentes = ptr(len(lista))
			} else if json.Unmarshal(raw, &n) == nil {
				r.Pendentes = ptr(n)
			}
			break
		}
		if r.Pendentes == nil {
			r.Aviso = "lista de pendentes não coletada neste sistema"
		}
		return r
	}
	// Texto (Linux/macOS).
	var secao string // "" | "pend" | "outra"
	n, achouSecao := 0, false
	for _, l := range strings.Split(out, "\n") {
		l = strings.TrimRight(l, "\r")
		t := strings.TrimSpace(l)
		if strings.HasPrefix(t, "reinicio_pendente:") {
			if b, ok := simNao(strings.TrimPrefix(t, "reinicio_pendente:")); ok {
				r.ReinicioPendente = &b
			}
			continue
		}
		if strings.HasPrefix(t, "== ") {
			if strings.HasPrefix(t, "== Pendentes") {
				secao, achouSecao = "pend", true
			} else {
				secao = "outra"
			}
			continue
		}
		if secao != "pend" || t == "" {
			continue
		}
		if linhaPendente(t) {
			n++
		}
	}
	if achouSecao {
		r.Pendentes = &n
	} else {
		r.Aviso = "seção de pendentes ausente (gerenciador de pacotes não reconhecido?)"
	}
	return r
}

// linhaPendente reconhece uma linha de pacote em apt ("pkg/rel ver arch [upgradable
// from: x]"), dnf ("pkg.arch ver repo") ou softwareupdate ("* Label").
func linhaPendente(t string) bool {
	switch {
	case strings.HasPrefix(t, "Listing"), strings.HasPrefix(t, "Listando"),
		strings.HasPrefix(t, "WARNING"), strings.HasPrefix(t, "Obsoleting"),
		strings.HasPrefix(t, "Software Update"), strings.HasPrefix(t, "No new software"),
		strings.HasPrefix(t, "Finding"), strings.HasPrefix(t, "Last metadata"):
		return false
	case strings.HasPrefix(t, "* "):
		return true
	}
	if strings.Contains(t, "/") && strings.Contains(t, "[") { // apt
		return strings.Contains(t, "upgradable") || strings.Contains(t, "atualiz")
	}
	f := strings.Fields(t)
	return len(f) == 3 && strings.Contains(f[0], ".") && !strings.Contains(t, "/") // dnf
}

// ParseSaude aceita o JSON do Windows e o texto "chave: valor" de Linux/macOS.
func ParseSaude(out string) SaudeResumo {
	out = semBOM(out)
	var r SaudeResumo
	if out == "" {
		r.Aviso = "saída vazia"
		return r
	}
	if out[0] == '{' {
		var m map[string]json.RawMessage
		if err := json.Unmarshal([]byte(out), &m); err != nil {
			r.Aviso = "JSON inválido"
			return r
		}
		var n int
		if json.Unmarshal(m["eventos_instabilidade"], &n) == nil {
			r.Eventos = &n
		}
		var b bool
		if json.Unmarshal(m["estavel"], &b) == nil {
			r.Estavel = &b
		}
		r.completa()
		return r
	}
	for _, l := range strings.Split(out, "\n") {
		k, v, ok := strings.Cut(strings.TrimSpace(l), ":")
		if !ok {
			continue
		}
		v = strings.TrimSpace(v)
		switch strings.TrimSpace(k) {
		case "eventos_instabilidade", "panics":
			if n, err := strconv.Atoi(v); err == nil {
				r.Eventos = &n
			}
		case "estavel":
			if b, ok := simNao(v); ok {
				r.Estavel = &b
			}
		}
	}
	r.completa()
	return r
}

// completa deriva o campo faltante quando dá (estavel <-> eventos==0).
func (r *SaudeResumo) completa() {
	if r.Estavel == nil && r.Eventos != nil {
		r.Estavel = ptr(*r.Eventos == 0)
	}
	if r.Estavel == nil && r.Eventos == nil {
		r.Aviso = "campos de saúde não reconhecidos"
	}
}

func timeRFC3339(unix int64) string { return time.Unix(unix, 0).UTC().Format(time.RFC3339) }
