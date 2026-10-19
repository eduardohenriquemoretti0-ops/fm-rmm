package server

import (
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/eduardohenriquemoretti0-ops/fm-rmm/internal/proto"
	"github.com/eduardohenriquemoretti0-ops/fm-rmm/internal/sign"
)

// Ações de operador (T5c): o console recebe jobs/concessões JÁ ASSINADOS pelo
// operador no navegador e os enfileira. O servidor não assina nada: guarda o
// SignedJob/SignedGrant com a assinatura original do operador.
//
// Anti-replay server-side: cada ação carrega um nonce (job_id / session_id,
// escolhido pelo navegador) que só pode ser usado UMA vez por operador. O
// nonce é gravado na MESMA transação que enfileira a ação: ou entram os dois
// ou nenhum. O registro de nonce expira junto com a janela de validade da ação
// (depois disso a própria expiração do payload barra o replay).

const acoesSchema = `
CREATE TABLE IF NOT EXISTS acao_nonces (
  operator_id TEXT NOT NULL, nonce TEXT NOT NULL, expires_at INTEGER NOT NULL,
  PRIMARY KEY (operator_id, nonce)
);
CREATE INDEX IF NOT EXISTS acao_nonces_exp ON acao_nonces(expires_at);`

// ErrReplay: o nonce já foi usado por este operador (ou o id da ação já existe).
var ErrReplay = errors.New("nonce já utilizado")

// ErrChaveJaDefinida: o operador já tem chave de assinatura; troca é do admin.
var ErrChaveJaDefinida = errors.New("operador já possui chave de assinatura")

func (s *Store) initAcoes() error {
	_, err := s.db.Exec(acoesSchema)
	return err
}

// nonceRetencao é quanto o nonce é lembrado depois do vencimento da ação
// (cobre a tolerância de relógio usada na verificação de expiração).
const nonceRetencao = proto.ClockSkew + time.Minute

// EnfileirarJobDoOperador grava o nonce e enfileira o job assinado numa só
// transação. Nonce repetido -> ErrReplay. Não assina nem re-assina.
func (s *Store) EnfileirarJobDoOperador(opID string, p proto.JobPayload, sj proto.SignedJob) error {
	signed, err := json.Marshal(sj)
	if err != nil {
		return err
	}
	pj, _ := json.Marshal(p.Params)
	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if err := consomeNonce(tx, opID, p.JobID, p.ExpiresAt.Add(nonceRetencao)); err != nil {
		return err
	}
	if _, err := tx.Exec(`INSERT INTO jobs(id, agent_id, action, params, signed, issuer, status, created_at, expires_at) VALUES (?,?,?,?,?,?,?,?,?)`,
		p.JobID, p.AgentID, p.Action, string(pj), string(signed), p.Issuer, "queued", time.Now().Unix(), p.ExpiresAt.Unix()); err != nil {
		return fmt.Errorf("%w: %v", ErrReplay, err) // id de job já existe
	}
	return tx.Commit()
}

// EnfileirarGrantDoOperador é o equivalente para concessões de sessão remota.
// O token do relay vai só como hash (como em CreateSession).
func (s *Store) EnfileirarGrantDoOperador(opID string, g proto.RemoteGrant, sg proto.SignedGrant) error {
	signed, err := json.Marshal(sg)
	if err != nil {
		return err
	}
	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if err := consomeNonce(tx, opID, g.SessionID, g.ExpiresAt.Add(nonceRetencao)); err != nil {
		return err
	}
	if _, err := tx.Exec(`INSERT INTO sessions(id, agent_id, technician, mode, relay_token_hash, signed, status, created_at, expires_at)
		VALUES (?,?,?,?,?,?,?,?,?)`, g.SessionID, g.AgentID, g.Technician, g.Mode, hashSecret(g.RelayToken), string(signed), "queued",
		time.Now().Unix(), g.ExpiresAt.Unix()); err != nil {
		return fmt.Errorf("%w: %v", ErrReplay, err)
	}
	return tx.Commit()
}

// consomeNonce registra o nonce; chave primária repetida = replay. Aproveita
// para varrer nonces vencidos (o store não cresce sem limite).
func consomeNonce(tx *sql.Tx, opID, nonce string, expira time.Time) error {
	if _, err := tx.Exec(`DELETE FROM acao_nonces WHERE expires_at < ?`, time.Now().Unix()); err != nil {
		return err
	}
	if _, err := tx.Exec(`INSERT INTO acao_nonces(operator_id, nonce, expires_at) VALUES (?,?,?)`, opID, nonce, expira.Unix()); err != nil {
		return ErrReplay
	}
	return nil
}

// DefinirChaveAssinaturaSeVazia grava a chave pública de assinatura do operador
// SÓ se ainda não houver uma (atômico). Troca/rotação é do administrador
// (SetOperatorSigningPub, fora de banda).
func (s *Store) DefinirChaveAssinaturaSeVazia(id, pubB64 string) error {
	pub, err := sign.DecodePub(pubB64)
	if err != nil {
		return fmt.Errorf("chave de assinatura do operador: %w", err)
	}
	r, err := s.db.Exec(`UPDATE operators SET signing_pub=? WHERE id=? AND signing_pub=''`, sign.EncodePub(pub), id)
	if err != nil {
		return err // inclui violação do índice único (chave de outro operador)
	}
	n, _ := r.RowsAffected()
	if n == 0 {
		return ErrChaveJaDefinida
	}
	return nil
}
