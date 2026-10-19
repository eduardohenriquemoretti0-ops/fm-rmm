package server

import (
	"database/sql"
	"encoding/json"
	"errors"
	"time"
)

// Store de achados de vulnerabilidade por agente (T3a, Plano v2 §3.3 fase 2).
//
// Os achados são DERIVADOS (o servidor cruza o inventário `software` contra o
// OSV.dev); o agente nunca vê nem informa CVE. Tudo aqui é idempotente: rodar o
// mesmo scan duas vezes deixa o banco igual (só visto_em avança).

const cveSchema = `
CREATE TABLE IF NOT EXISTS vulnerabilidades (
  agent_id TEXT NOT NULL REFERENCES agents(id),
  vuln_id TEXT NOT NULL,              -- id OSV (GHSA-..., DSA-..., CVE-...)
  cve_id TEXT NOT NULL,               -- CVE-... se houver alias; senão = vuln_id
  pacote TEXT NOT NULL, versao TEXT NOT NULL,
  severidade TEXT NOT NULL DEFAULT 'DESCONHECIDA',
  pontuacao REAL NOT NULL DEFAULT 0,  -- CVSS v3 base (0 = não calculada)
  fixed_version TEXT NOT NULL DEFAULT '',
  fonte TEXT NOT NULL, visto_em INTEGER NOT NULL,
  PRIMARY KEY (agent_id, vuln_id, pacote, versao)
);
CREATE TABLE IF NOT EXISTS cve_scan (
  agent_id TEXT PRIMARY KEY REFERENCES agents(id),
  job_id TEXT NOT NULL DEFAULT '', escaneado_em INTEGER NOT NULL,
  itens_total INTEGER NOT NULL, avaliados INTEGER NOT NULL, nao_avaliados INTEGER NOT NULL,
  nao_avaliados_risco TEXT NOT NULL DEFAULT '[]',
  erro TEXT NOT NULL DEFAULT ''
);
-- cache de respostas do OSV (por consulta e por vuln id), para não repetir chamadas
CREATE TABLE IF NOT EXISTS osv_cache (
  chave TEXT PRIMARY KEY, valor TEXT NOT NULL, em INTEGER NOT NULL
);
`

func (s *Store) initCVE() error {
	_, err := s.db.Exec(cveSchema)
	return err
}

// Achado é uma vulnerabilidade conhecida numa máquina.
type Achado struct {
	VulnID       string  `json:"osv_id"`
	CVEID        string  `json:"cve_id"`
	Pacote       string  `json:"pacote"`
	Versao       string  `json:"versao"`
	Severidade   string  `json:"severidade"`
	Pontuacao    float64 `json:"pontuacao,omitempty"`
	FixedVersion string  `json:"fixed_version"`
	Fonte        string  `json:"fonte"`
	VistoEm      int64   `json:"-"`
}

// NaoAvaliado é um item do inventário que nenhuma fonte soube cruzar.
type NaoAvaliado struct {
	Pacote string `json:"pacote"`
	Versao string `json:"versao"`
	Motivo string `json:"motivo"`
}

// ResumoScan são os metadados da última varredura de um agente.
type ResumoScan struct {
	AgentID           string
	JobID             string
	EscaneadoEm       int64
	ItensTotal        int
	Avaliados         int
	NaoAvaliados      int
	NaoAvaliadosRisco []NaoAvaliado
	Erro              string
}

// SalvarScan grava o resultado de uma varredura numa transação. Se completo,
// os achados do agente são SUBSTITUÍDOS (o que foi corrigido some); se não
// (erro de rede parcial), os achados antigos ficam e só o resumo registra o erro.
func (s *Store) SalvarScan(r ResumoScan, achados []Achado, completo bool, agora time.Time) error {
	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if completo {
		if _, err := tx.Exec(`DELETE FROM vulnerabilidades WHERE agent_id=?`, r.AgentID); err != nil {
			return err
		}
	}
	for _, a := range achados {
		if _, err := tx.Exec(`INSERT INTO vulnerabilidades(agent_id, vuln_id, cve_id, pacote, versao, severidade, pontuacao, fixed_version, fonte, visto_em)
			VALUES (?,?,?,?,?,?,?,?,?,?)
			ON CONFLICT(agent_id, vuln_id, pacote, versao) DO UPDATE SET
			  cve_id=excluded.cve_id, severidade=excluded.severidade, pontuacao=excluded.pontuacao,
			  fixed_version=excluded.fixed_version, fonte=excluded.fonte, visto_em=excluded.visto_em`,
			r.AgentID, a.VulnID, a.CVEID, a.Pacote, a.Versao, a.Severidade, a.Pontuacao, a.FixedVersion, a.Fonte, agora.Unix()); err != nil {
			return err
		}
	}
	risco, _ := json.Marshal(r.NaoAvaliadosRisco)
	if r.NaoAvaliadosRisco == nil {
		risco = []byte("[]")
	}
	if _, err := tx.Exec(`INSERT INTO cve_scan(agent_id, job_id, escaneado_em, itens_total, avaliados, nao_avaliados, nao_avaliados_risco, erro)
		VALUES (?,?,?,?,?,?,?,?)
		ON CONFLICT(agent_id) DO UPDATE SET job_id=excluded.job_id, escaneado_em=excluded.escaneado_em,
		  itens_total=excluded.itens_total, avaliados=excluded.avaliados, nao_avaliados=excluded.nao_avaliados,
		  nao_avaliados_risco=excluded.nao_avaliados_risco, erro=excluded.erro`,
		r.AgentID, r.JobID, agora.Unix(), r.ItensTotal, r.Avaliados, r.NaoAvaliados, string(risco), r.Erro); err != nil {
		return err
	}
	return tx.Commit()
}

// Achados devolve os achados do agente, mais graves primeiro.
func (s *Store) Achados(agentID string) ([]Achado, error) {
	rows, err := s.db.Query(`SELECT vuln_id, cve_id, pacote, versao, severidade, pontuacao, fixed_version, fonte, visto_em
		FROM vulnerabilidades WHERE agent_id=?
		ORDER BY CASE severidade WHEN 'CRITICAL' THEN 0 WHEN 'HIGH' THEN 1 WHEN 'MEDIUM' THEN 2 WHEN 'LOW' THEN 3 ELSE 4 END,
		  pontuacao DESC, pacote, vuln_id`, agentID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Achado
	for rows.Next() {
		var a Achado
		if err := rows.Scan(&a.VulnID, &a.CVEID, &a.Pacote, &a.Versao, &a.Severidade, &a.Pontuacao, &a.FixedVersion, &a.Fonte, &a.VistoEm); err != nil {
			return nil, err
		}
		out = append(out, a)
	}
	return out, rows.Err()
}

// UltimoScan devolve o resumo da última varredura; ok=false se nunca houve.
func (s *Store) UltimoScan(agentID string) (ResumoScan, bool, error) {
	var r ResumoScan
	var risco string
	err := s.db.QueryRow(`SELECT agent_id, job_id, escaneado_em, itens_total, avaliados, nao_avaliados, nao_avaliados_risco, erro
		FROM cve_scan WHERE agent_id=?`, agentID).
		Scan(&r.AgentID, &r.JobID, &r.EscaneadoEm, &r.ItensTotal, &r.Avaliados, &r.NaoAvaliados, &risco, &r.Erro)
	if errors.Is(err, sql.ErrNoRows) {
		return r, false, nil
	}
	if err != nil {
		return r, false, err
	}
	_ = json.Unmarshal([]byte(risco), &r.NaoAvaliadosRisco)
	return r, true, nil
}

// UltimoInventarioSoftware devolve o job `software` finalizado (status ok) mais novo.
func (s *Store) UltimoInventarioSoftware(agentID string) (Job, bool, error) {
	j, err := scanJob(s.db.QueryRow(`SELECT `+jobCols+` FROM jobs WHERE agent_id=? AND action='software' AND status='ok' AND finished_at>0
		ORDER BY finished_at DESC, id DESC LIMIT 1`, agentID))
	if errors.Is(err, sql.ErrNoRows) {
		return j, false, nil
	}
	return j, err == nil, err
}

// cacheGet devolve o valor em cache se tiver menos de ttl.
func (s *Store) cacheGet(chave string, ttl time.Duration, agora time.Time) (string, bool) {
	var v string
	var em int64
	if err := s.db.QueryRow(`SELECT valor, em FROM osv_cache WHERE chave=?`, chave).Scan(&v, &em); err != nil {
		return "", false
	}
	if agora.Sub(time.Unix(em, 0)) > ttl {
		return "", false
	}
	return v, true
}

func (s *Store) cachePut(chave, valor string, agora time.Time) error {
	_, err := s.db.Exec(`INSERT INTO osv_cache(chave, valor, em) VALUES (?,?,?)
		ON CONFLICT(chave) DO UPDATE SET valor=excluded.valor, em=excluded.em`, chave, valor, agora.Unix())
	return err
}
