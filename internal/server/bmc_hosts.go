package server

import (
	"database/sql"
	"errors"
	"fmt"
	"net/netip"
	"strings"
	"time"
)

// Inventário de hosts BMC (Plano v2, §3.2). O console só conecta a BMCs
// CADASTRADOS aqui, cada um ligado a um grupo de técnicos. A credencial do BMC
// NÃO faz parte do inventário (nunca é persistida).

const bmcHostsSchema = `
CREATE TABLE IF NOT EXISTS bmc_hosts (
  host TEXT NOT NULL, porta INTEGER NOT NULL DEFAULT 443, grp TEXT NOT NULL,
  nome TEXT NOT NULL, criado_em INTEGER NOT NULL,
  PRIMARY KEY (host, porta)
);
`

// PortaBMCPadrao é a porta HTTPS usada quando nenhuma é informada.
const PortaBMCPadrao = 443

var (
	// ErrBMCHostDesconhecido: o host/porta não está no inventário.
	ErrBMCHostDesconhecido = errors.New("host BMC não cadastrado")
	// ErrBMCHostNegado: cadastrado, mas o técnico não tem o grupo do host.
	ErrBMCHostNegado = errors.New("técnico sem o grupo deste host BMC")
)

// BMCHost é uma linha do inventário.
type BMCHost struct {
	Host     string
	Porta    int
	Grupo    string
	Nome     string
	CriadoEm time.Time
}

func (s *Store) initBMCHosts() error {
	_, err := s.db.Exec(bmcHostsSchema)
	return err
}

// NormalizaBMCHost devolve a forma canônica do host (minúsculo; IPs na forma
// canônica, sem colchetes) para que cadastro e consulta casem sempre.
func NormalizaBMCHost(host string) (string, error) {
	h := strings.ToLower(strings.TrimSpace(host))
	h = strings.TrimSuffix(strings.TrimPrefix(h, "["), "]")
	if h == "" || len(h) > 253 || strings.ContainsAny(h, " \t/@?#\\") {
		return "", errors.New("host BMC inválido")
	}
	if a, err := netip.ParseAddr(h); err == nil {
		return a.Unmap().String(), nil
	}
	if strings.Contains(h, ":") {
		return "", errors.New("host BMC inválido (porta vai em campo separado)")
	}
	return h, nil
}

func normalizaPortaBMC(porta int) (int, error) {
	if porta == 0 {
		return PortaBMCPadrao, nil
	}
	if porta < 1 || porta > 65535 {
		return 0, errors.New("porta BMC inválida")
	}
	return porta, nil
}

// AdicionarBMCHost cadastra (ou atualiza grupo/nome de) um host BMC.
func (s *Store) AdicionarBMCHost(host string, porta int, grupo, nome string) error {
	h, err := NormalizaBMCHost(host)
	if err != nil {
		return err
	}
	if porta, err = normalizaPortaBMC(porta); err != nil {
		return err
	}
	grupo, nome = strings.TrimSpace(grupo), strings.TrimSpace(nome)
	if grupo == "" || grupo == "*" || nome == "" {
		return errors.New("grupo (diferente de '*') e nome são obrigatórios")
	}
	_, err = s.db.Exec(`INSERT INTO bmc_hosts(host, porta, grp, nome, criado_em) VALUES (?,?,?,?,?)
		ON CONFLICT(host, porta) DO UPDATE SET grp=excluded.grp, nome=excluded.nome`,
		h, porta, grupo, nome, time.Now().Unix())
	return err
}

// RemoverBMCHost remove o host do inventário (ErrNotFound se não existir).
func (s *Store) RemoverBMCHost(host string, porta int) error {
	h, err := NormalizaBMCHost(host)
	if err != nil {
		return err
	}
	if porta, err = normalizaPortaBMC(porta); err != nil {
		return err
	}
	r, err := s.db.Exec(`DELETE FROM bmc_hosts WHERE host=? AND porta=?`, h, porta)
	return oneRow(r, err)
}

// ListarBMCHosts lista o inventário completo.
func (s *Store) ListarBMCHosts() ([]BMCHost, error) {
	rows, err := s.db.Query(`SELECT host, porta, grp, nome, criado_em FROM bmc_hosts ORDER BY host, porta`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []BMCHost
	for rows.Next() {
		var h BMCHost
		var ts int64
		if err := rows.Scan(&h.Host, &h.Porta, &h.Grupo, &h.Nome, &ts); err != nil {
			return nil, err
		}
		h.CriadoEm = time.Unix(ts, 0)
		out = append(out, h)
	}
	return out, rows.Err()
}

// BMCHostPermitido confere que host:porta está cadastrado E que o técnico (ativo)
// pertence ao grupo do host (ou ao curinga '*', como em CanAccess). Devolve nil,
// ErrBMCHostDesconhecido ou ErrBMCHostNegado. É ADICIONAL ao grupo `bmc`
// (capacidade), que o console continua exigindo.
func (s *Store) BMCHostPermitido(host string, porta int, techName string) error {
	h, err := NormalizaBMCHost(host)
	if err != nil {
		return ErrBMCHostDesconhecido
	}
	if porta, err = normalizaPortaBMC(porta); err != nil {
		return ErrBMCHostDesconhecido
	}
	var grp string
	err = s.db.QueryRow(`SELECT grp FROM bmc_hosts WHERE host=? AND porta=?`, h, porta).Scan(&grp)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return ErrBMCHostDesconhecido
		}
		return fmt.Errorf("inventário BMC: %w", err)
	}
	var n int
	if err := s.db.QueryRow(`SELECT COUNT(*) FROM tech_groups g JOIN techs t ON t.name=g.tech
		WHERE g.tech=? AND (g.grp=? OR g.grp='*') AND t.disabled=0`, techName, grp).Scan(&n); err != nil {
		return fmt.Errorf("inventário BMC: %w", err)
	}
	if n == 0 {
		return ErrBMCHostNegado
	}
	return nil
}
