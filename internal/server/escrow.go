package server

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"time"

	"github.com/eduardohenriquemoretti0-ops/fm-rmm/internal/escrow"
	"github.com/eduardohenriquemoretti0-ops/fm-rmm/internal/proto"
)

// ActionEscrow é a ação nativa cujo resultado pode carregar um registro de escrow.
const ActionEscrow = "forcar_criptografia"

const schemaEscrow = `
CREATE TABLE IF NOT EXISTS escrow (
  id INTEGER PRIMARY KEY AUTOINCREMENT, agent_id TEXT NOT NULL, job_id TEXT NOT NULL,
  volume TEXT NOT NULL, blob_selado TEXT NOT NULL, metodo TEXT NOT NULL, criado_em INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS escrow_agente ON escrow(agent_id);
`

func (s *Store) initEscrow() error { _, err := s.db.Exec(schemaEscrow); return err }

// EscrowRow é um registro de escrow: SÓ ciphertext (blob_selado) + metadados.
type EscrowRow struct {
	ID                                   int64
	AgentID, JobID, Volume, Blob, Metodo string
	CriadoEm                             int64
}

// AddEscrow guarda o blob selado. Valida forma (base64, tamanho) sem poder
// abrir: o servidor não tem a privada.
func (s *Store) AddEscrow(agentID, jobID string, r proto.EscrowRecord) error {
	if r.Volume == "" || len(r.Volume) > 64 || r.Metodo == "" || len(r.Metodo) > 32 {
		return errors.New("escrow: metadados inválidos")
	}
	if r.Blob == "" || len(r.Blob) > escrow.MaxBlob {
		return errors.New("escrow: blob ausente ou grande demais")
	}
	if b, err := base64.StdEncoding.DecodeString(r.Blob); err != nil || len(b) < 48 {
		return errors.New("escrow: blob não parece um SealAnonymous válido")
	}
	_, err := s.db.Exec(`INSERT INTO escrow(agent_id, job_id, volume, blob_selado, metodo, criado_em) VALUES (?,?,?,?,?,?)`,
		agentID, jobID, r.Volume, r.Blob, r.Metodo, time.Now().Unix())
	return err
}

// Escrows lista os registros (read-only), do mais novo ao mais antigo.
// agentID vazio = todos.
func (s *Store) Escrows(agentID string) ([]EscrowRow, error) {
	q := `SELECT id, agent_id, job_id, volume, blob_selado, metodo, criado_em FROM escrow`
	var args []any
	if agentID != "" {
		q += ` WHERE agent_id=?`
		args = append(args, agentID)
	}
	rows, err := s.db.Query(q+` ORDER BY id DESC`, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []EscrowRow
	for rows.Next() {
		var e EscrowRow
		if err := rows.Scan(&e.ID, &e.AgentID, &e.JobID, &e.Volume, &e.Blob, &e.Metodo, &e.CriadoEm); err != nil {
			return nil, err
		}
		out = append(out, e)
	}
	return out, rows.Err()
}

// EscrowByID devolve um registro.
func (s *Store) EscrowByID(id int64) (EscrowRow, error) {
	var e EscrowRow
	err := s.db.QueryRow(`SELECT id, agent_id, job_id, volume, blob_selado, metodo, criado_em FROM escrow WHERE id=?`, id).
		Scan(&e.ID, &e.AgentID, &e.JobID, &e.Volume, &e.Blob, &e.Metodo, &e.CriadoEm)
	return e, err
}

// impressao do blob para a auditoria (nunca o blob inteiro).
func blobFingerprint(b string) string {
	h := sha256.Sum256([]byte(b))
	return hex.EncodeToString(h[:6])
}
