package server

import (
	"crypto/ed25519"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/eduardohenriquemoretti0-ops/fm-rmm/internal/proto"
	"github.com/eduardohenriquemoretti0-ops/fm-rmm/internal/sign"
)

const sessionSchema = `
CREATE TABLE IF NOT EXISTS sessions (
  id TEXT PRIMARY KEY, agent_id TEXT NOT NULL REFERENCES agents(id),
  technician TEXT NOT NULL, mode TEXT NOT NULL, relay_token_hash TEXT NOT NULL,
  signed TEXT NOT NULL, status TEXT NOT NULL,
  created_at INTEGER NOT NULL, expires_at INTEGER NOT NULL,
  started_at INTEGER NOT NULL DEFAULT 0, ended_at INTEGER NOT NULL DEFAULT 0
);
CREATE INDEX IF NOT EXISTS sessions_fila ON sessions(agent_id, status);`

func (s *Store) initSessions() error {
	_, err := s.db.Exec(sessionSchema)
	return err
}

type Session struct {
	ID, AgentID, Technician, Mode, Signed, Status string
	CreatedAt, ExpiresAt, StartedAt, EndedAt      int64
}

// CreateSession checa RBAC, assina a concessão e enfileira para o agente.
// relayBase é o wss:// do relay; cada sessão ganha um token de relay próprio.
func CreateSession(st *Store, priv ed25519.PrivateKey, signers map[string]ed25519.PublicKey, agentID, technician, mode, engine, relayBase string, ttl time.Duration, issuer string) (proto.RemoteGrant, string, error) {
	var g proto.RemoteGrant
	if mode != proto.ModeView && mode != proto.ModeControl {
		return g, "", sign.ErrGrantMode
	}
	if engine != proto.EngineScreenshot && engine != proto.EngineRustDesk {
		return g, "", sign.ErrEngine
	}
	if ttl <= 0 || ttl > proto.MaxGrantTTL {
		return g, "", fmt.Errorf("validade deve estar entre 1s e %s", proto.MaxGrantTTL)
	}
	if _, ok := signers[sign.KeyID(priv.Public().(ed25519.PublicKey))]; !ok {
		return g, "", errors.New("esta chave de administrador não está cadastrada no servidor")
	}
	a, err := st.Agent(agentID)
	if err != nil {
		return g, "", fmt.Errorf("agente %s: %w", agentID, err)
	}
	if a.Status != "approved" {
		return g, "", fmt.Errorf("agente %s está %s", agentID, a.Status)
	}
	if err := st.CanAccess(technician, agentID); err != nil {
		return g, "", err
	}
	now := time.Now().UTC()
	relayToken := randSecret()
	// rustdesk: senha de uso único da sessão (o agente arma o RustDesk com ela)
	mediaSecret := ""
	if engine == proto.EngineRustDesk {
		mediaSecret = randHex(6) // 12 hex, suficiente p/ senha de sessão curta
	}
	g = proto.RemoteGrant{
		V: proto.Version, SessionID: "ses-" + randHex(8), AgentID: agentID, Technician: technician,
		Mode: mode, Engine: engine, MediaSecret: mediaSecret, RelayURL: relayBase, RelayToken: relayToken,
		IssuedAt: now, ExpiresAt: now.Add(ttl), Issuer: issuer,
	}
	sg, err := sign.SignGrant(priv, g)
	if err != nil {
		return g, "", err
	}
	raw, _ := json.Marshal(sg)
	_, err = st.db.Exec(`INSERT INTO sessions(id, agent_id, technician, mode, relay_token_hash, signed, status, created_at, expires_at)
		VALUES (?,?,?,?,?,?,?,?,?)`, g.SessionID, agentID, technician, mode, hashSecret(relayToken), string(raw), "queued", now.Unix(), g.ExpiresAt.Unix())
	if err != nil {
		return g, "", err
	}
	return g, relayToken, st.Audit("sessao.autorizada", issuer, map[string]any{
		"sessao": g.SessionID, "agente": agentID, "tecnico": technician, "modo": mode, "motor": engine, "indicador": "sempre visível",
	})
}

// TakeSessions entrega as concessões em fila do agente (marca como entregues).
func (s *Store) TakeSessions(agentID string) ([]proto.SignedGrant, error) {
	now := time.Now().Unix()
	if _, err := s.db.Exec(`UPDATE sessions SET status='expired' WHERE agent_id=? AND status='queued' AND expires_at<=?`, agentID, now); err != nil {
		return nil, err
	}
	rows, err := s.db.Query(`SELECT id, signed FROM sessions WHERE agent_id=? AND status='queued' ORDER BY created_at`, agentID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var ids []string
	var out []proto.SignedGrant
	for rows.Next() {
		var id, signed string
		if err := rows.Scan(&id, &signed); err != nil {
			return nil, err
		}
		var sg proto.SignedGrant
		if err := json.Unmarshal([]byte(signed), &sg); err != nil {
			continue
		}
		out = append(out, sg)
		ids = append(ids, id)
	}
	rows.Close()
	for _, id := range ids {
		if _, err := s.db.Exec(`UPDATE sessions SET status='delivered' WHERE id=?`, id); err != nil {
			return nil, err
		}
	}
	return out, nil
}

// MarkSession registra evento de sessão vindo do agente.
func (s *Store) MarkSession(agentID, sessionID, event string) error {
	switch event {
	case "iniciada":
		r, err := s.db.Exec(`UPDATE sessions SET status='active', started_at=? WHERE id=? AND agent_id=? AND status='delivered'`, time.Now().Unix(), sessionID, agentID)
		return oneRow(r, err)
	case "encerrada":
		r, err := s.db.Exec(`UPDATE sessions SET status='ended', ended_at=? WHERE id=? AND agent_id=? AND status IN ('delivered','active')`, time.Now().Unix(), sessionID, agentID)
		return oneRow(r, err)
	case "recusada":
		r, err := s.db.Exec(`UPDATE sessions SET status='refused', ended_at=? WHERE id=? AND agent_id=?`, time.Now().Unix(), sessionID, agentID)
		return oneRow(r, err)
	}
	return nil // indicador_on e outros: só auditados, sem mudar status
}

// CheckRelayToken confere o token de relay de uma sessão ainda válida.
func (s *Store) CheckRelayToken(sessionID, token string) (Session, error) {
	var ses Session
	var hash string
	err := s.db.QueryRow(`SELECT id, agent_id, technician, mode, status, relay_token_hash, expires_at FROM sessions WHERE id=?`, sessionID).
		Scan(&ses.ID, &ses.AgentID, &ses.Technician, &ses.Mode, &ses.Status, &hash, &ses.ExpiresAt)
	if errors.Is(err, sql.ErrNoRows) {
		return ses, ErrNotFound
	}
	if err != nil {
		return ses, err
	}
	if !eqHash(hash, hashSecret(token)) || time.Now().Unix() > ses.ExpiresAt {
		return ses, ErrNotFound
	}
	return ses, nil
}

func (s *Store) Sessions(limit int) ([]Session, error) {
	rows, err := s.db.Query(`SELECT id, agent_id, technician, mode, status, created_at, started_at, ended_at FROM sessions ORDER BY created_at DESC LIMIT ?`, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Session
	for rows.Next() {
		var x Session
		if err := rows.Scan(&x.ID, &x.AgentID, &x.Technician, &x.Mode, &x.Status, &x.CreatedAt, &x.StartedAt, &x.EndedAt); err != nil {
			return nil, err
		}
		out = append(out, x)
	}
	return out, rows.Err()
}

// EnqueueSignedGrantForTest insere uma concessão já assinada na fila. Existe
// só para testes do agente (forjar concessão). Não é usada em produção.
func (s *Store) EnqueueSignedGrantForTest(agentID, sessionID string, sg proto.SignedGrant, relayToken string, ttl time.Duration) error {
	raw, _ := json.Marshal(sg)
	now := time.Now().UTC()
	_, err := s.db.Exec(`INSERT INTO sessions(id, agent_id, technician, mode, relay_token_hash, signed, status, created_at, expires_at)
		VALUES (?,?,?,?,?,?,?,?,?)`, sessionID, agentID, "teste", proto.ModeView, hashSecret(relayToken), string(raw), "queued", now.Unix(), now.Add(ttl).Unix())
	return err
}
