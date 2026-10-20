package server

import (
	"database/sql"
	"errors"
	"time"
)

// RBAC do acesso remoto: nem todo técnico acessa toda máquina (requisito 10).
// Um técnico recebe acesso a grupos; cada agente pertence a um grupo. O grupo
// "*" dá acesso a todas as máquinas.
//
// O schema do RBAC é criado aqui para manter o do store principal enxuto.

const rbacSchema = `
CREATE TABLE IF NOT EXISTS techs (
  name TEXT PRIMARY KEY, created_at INTEGER NOT NULL, disabled INTEGER NOT NULL DEFAULT 0
);
CREATE TABLE IF NOT EXISTS tech_groups (
  tech TEXT NOT NULL REFERENCES techs(name), grp TEXT NOT NULL,
  PRIMARY KEY (tech, grp)
);
-- agents.grp: grupo do agente (default 'default'); coluna adicionada abaixo.
`

func (s *Store) initRBAC() error {
	if _, err := s.db.Exec(rbacSchema); err != nil {
		return err
	}
	// coluna grp em agents (idempotente: ignora "duplicate column")
	_, err := s.db.Exec(`ALTER TABLE agents ADD COLUMN grp TEXT NOT NULL DEFAULT 'default'`)
	if err != nil && !isDupColumn(err) {
		return err
	}
	return nil
}

func isDupColumn(err error) bool {
	return err != nil && (contains(err.Error(), "duplicate column") || contains(err.Error(), "already exists"))
}

func contains(s, sub string) bool {
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return true
		}
	}
	return false
}

func (s *Store) AddTech(name string) error {
	_, err := s.db.Exec(`INSERT OR IGNORE INTO techs(name, created_at) VALUES (?,?)`, name, time.Now().Unix())
	return err
}

func (s *Store) DisableTech(name string, disabled bool) error {
	d := 0
	if disabled {
		d = 1
	}
	r, err := s.db.Exec(`UPDATE techs SET disabled=? WHERE name=?`, d, name)
	return oneRow(r, err)
}

// GrantGroup dá a um técnico acesso a um grupo ("*" = todos).
func (s *Store) GrantGroup(tech, grp string) error {
	if _, err := s.db.Exec(`INSERT OR IGNORE INTO techs(name, created_at) VALUES (?,?)`, tech, time.Now().Unix()); err != nil {
		return err
	}
	_, err := s.db.Exec(`INSERT OR IGNORE INTO tech_groups(tech, grp) VALUES (?,?)`, tech, grp)
	return err
}

func (s *Store) RevokeGroup(tech, grp string) error {
	r, err := s.db.Exec(`DELETE FROM tech_groups WHERE tech=? AND grp=?`, tech, grp)
	return oneRow(r, err)
}

func (s *Store) SetAgentGroup(agentID, grp string) error {
	r, err := s.db.Exec(`UPDATE agents SET grp=? WHERE id=?`, grp, agentID)
	return oneRow(r, err)
}

// AgentGroup devolve o grupo do agente.
func (s *Store) AgentGroup(agentID string) (string, error) {
	var g string
	err := s.db.QueryRow(`SELECT grp FROM agents WHERE id=?`, agentID).Scan(&g)
	if errors.Is(err, sql.ErrNoRows) {
		return "", ErrNotFound
	}
	return g, err
}

// ErrAccessDenied: o técnico não tem permissão para a máquina.
var ErrAccessDenied = errors.New("técnico sem permissão para esta máquina")

// CanAccess diz se o técnico pode acessar o agente (grupo do agente ou "*").
// Técnico desabilitado ou inexistente nunca acessa.
func (s *Store) CanAccess(tech, agentID string) error {
	var disabled int
	err := s.db.QueryRow(`SELECT disabled FROM techs WHERE name=?`, tech).Scan(&disabled)
	if errors.Is(err, sql.ErrNoRows) {
		return ErrAccessDenied
	}
	if err != nil {
		return err
	}
	if disabled != 0 {
		return ErrAccessDenied
	}
	grp, err := s.AgentGroup(agentID)
	if err != nil {
		return err
	}
	var n int
	if err := s.db.QueryRow(`SELECT COUNT(*) FROM tech_groups WHERE tech=? AND (grp=? OR grp='*')`, tech, grp).Scan(&n); err != nil {
		return err
	}
	if n == 0 {
		return ErrAccessDenied
	}
	return nil
}

type TechPerm struct {
	Name     string
	Disabled bool
	Groups   []string
}

func (s *Store) Techs() ([]TechPerm, error) {
	rows, err := s.db.Query(`SELECT name, disabled FROM techs ORDER BY name`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []TechPerm
	for rows.Next() {
		var t TechPerm
		var d int
		if err := rows.Scan(&t.Name, &d); err != nil {
			return nil, err
		}
		t.Disabled = d != 0
		out = append(out, t)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	for i := range out {
		g, err := s.db.Query(`SELECT grp FROM tech_groups WHERE tech=? ORDER BY grp`, out[i].Name)
		if err != nil {
			return nil, err
		}
		for g.Next() {
			var grp string
			if err := g.Scan(&grp); err != nil {
				g.Close()
				return nil, err
			}
			out[i].Groups = append(out[i].Groups, grp)
		}
		g.Close()
	}
	return out, nil
}

// TechTemGrupo informa se o técnico (ativo) pertence EXATAMENTE ao grupo grp.
// Diferente de CanAccess, o curinga '*' NÃO vale: serve a capacidades sensíveis
// (ex.: controle de energia via BMC) que exigem concessão explícita.
func (s *Store) TechTemGrupo(tech, grp string) (bool, error) {
	var n int
	err := s.db.QueryRow(`SELECT COUNT(*) FROM tech_groups g JOIN techs t ON t.name=g.tech
		WHERE g.tech=? AND g.grp=? AND t.disabled=0`, tech, grp).Scan(&n)
	return n > 0, err
}
