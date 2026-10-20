package server

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"database/sql"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	_ "modernc.org/sqlite"

	"github.com/eduardohenriquemoretti0-ops/fm-rmm/internal/audit"
	"github.com/eduardohenriquemoretti0-ops/fm-rmm/internal/proto"
	"github.com/eduardohenriquemoretti0-ops/fm-rmm/internal/sign"
)

const schema = `
CREATE TABLE IF NOT EXISTS tokens (
  id TEXT PRIMARY KEY, hash TEXT UNIQUE NOT NULL, label TEXT NOT NULL,
  uses_left INTEGER NOT NULL, expires_at INTEGER NOT NULL, created_at INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS agents (
  id TEXT PRIMARY KEY, hostname TEXT NOT NULL, os TEXT NOT NULL,
  status TEXT NOT NULL, csr_pem TEXT NOT NULL, cert_pem TEXT NOT NULL DEFAULT '',
  cert_serial TEXT NOT NULL DEFAULT '', cert_expires INTEGER NOT NULL DEFAULT 0,
  poll_hash TEXT NOT NULL, token_id TEXT NOT NULL, remote_addr TEXT NOT NULL,
  enrolled_at INTEGER NOT NULL, approved_at INTEGER NOT NULL DEFAULT 0,
  last_seen INTEGER NOT NULL DEFAULT 0, heartbeat TEXT NOT NULL DEFAULT '{}'
);
CREATE TABLE IF NOT EXISTS jobs (
  id TEXT PRIMARY KEY, agent_id TEXT NOT NULL REFERENCES agents(id),
  action TEXT NOT NULL, params TEXT NOT NULL, signed TEXT NOT NULL,
  issuer TEXT NOT NULL, status TEXT NOT NULL,
  created_at INTEGER NOT NULL, expires_at INTEGER NOT NULL,
  delivered_at INTEGER NOT NULL DEFAULT 0, finished_at INTEGER NOT NULL DEFAULT 0,
  result TEXT NOT NULL DEFAULT ''
);
CREATE INDEX IF NOT EXISTS jobs_fila ON jobs(agent_id, status);
CREATE TABLE IF NOT EXISTS audit (
  seq INTEGER PRIMARY KEY, ts TEXT NOT NULL, event TEXT NOT NULL, actor TEXT NOT NULL,
  data TEXT NOT NULL, prev TEXT NOT NULL, hash TEXT NOT NULL
);
CREATE TRIGGER IF NOT EXISTS audit_sem_update BEFORE UPDATE ON audit
  BEGIN SELECT RAISE(ABORT, 'auditoria é append-only'); END;
CREATE TRIGGER IF NOT EXISTS audit_sem_delete BEFORE DELETE ON audit
  BEGIN SELECT RAISE(ABORT, 'auditoria é append-only'); END;
-- tech_name: o operador é um técnico (techs.name); o RBAC é o do técnico (CanAccess)
CREATE TABLE IF NOT EXISTS operators (
  id TEXT PRIMARY KEY, nome TEXT NOT NULL, display_name TEXT NOT NULL DEFAULT '',
  cert_thumbprint TEXT NOT NULL DEFAULT '', status TEXT NOT NULL, criado_em INTEGER NOT NULL,
  tech_name TEXT NOT NULL REFERENCES techs(name)
);
-- um cert de operador identifica uma pessoa só (thumbprint vazio = sem cert ainda)
CREATE UNIQUE INDEX IF NOT EXISTS operators_thumb ON operators(cert_thumbprint) WHERE cert_thumbprint <> '';
CREATE TABLE IF NOT EXISTS operator_credentials (
  credential_id TEXT PRIMARY KEY, operator_id TEXT NOT NULL REFERENCES operators(id),
  public_key BLOB NOT NULL, sign_count INTEGER NOT NULL DEFAULT 0,
  aaguid TEXT NOT NULL DEFAULT '', criado_em INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS operator_credentials_op ON operator_credentials(operator_id);
`

// Store guarda tudo do servidor num SQLite (seguro para o servidor e a CLI
// do administrador usarem ao mesmo tempo).
type Store struct{ db *sql.DB }

func OpenStore(path string) (*Store, error) {
	db, err := sql.Open("sqlite", "file:"+path+"?_pragma=busy_timeout(10000)&_pragma=journal_mode(WAL)&_pragma=foreign_keys(1)&_txlock=immediate")
	if err != nil {
		return nil, err
	}
	if _, err := db.Exec(schema); err != nil {
		db.Close()
		return nil, fmt.Errorf("banco: %w", err)
	}
	st := &Store{db: db}
	if err := st.initRBAC(); err != nil {
		db.Close()
		return nil, fmt.Errorf("banco (rbac): %w", err)
	}
	if err := st.initSessions(); err != nil {
		db.Close()
		return nil, fmt.Errorf("banco (sessões): %w", err)
	}
	if err := st.initListas(); err != nil {
		db.Close()
		return nil, fmt.Errorf("banco (listas de signers): %w", err)
	}
	if err := st.initCatalogoSoftware(); err != nil {
		db.Close()
		return nil, fmt.Errorf("banco (catálogo de software): %w", err)
	}
	if err := st.initBibliotecaScripts(); err != nil {
		db.Close()
		return nil, fmt.Errorf("banco (biblioteca de scripts): %w", err)
	}
	if err := st.initAcoes(); err != nil {
		db.Close()
		return nil, fmt.Errorf("banco (ações de operador): %w", err)
	}
	if err := st.initEscrow(); err != nil {
		db.Close()
		return nil, fmt.Errorf("banco (escrow): %w", err)
	}
	if err := st.initCVE(); err != nil {
		db.Close()
		return nil, fmt.Errorf("banco (vulnerabilidades): %w", err)
	}
	return st, nil
}

func (s *Store) Close() error { return s.db.Close() }

func randHex(n int) string {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		panic(err) // sem entropia não há como operar com segurança
	}
	return hex.EncodeToString(b)
}

func randSecret() string {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		panic(err)
	}
	return base64.RawURLEncoding.EncodeToString(b)
}

func hashSecret(s string) string {
	h := sha256.Sum256([]byte(s))
	return hex.EncodeToString(h[:])
}

func eqHash(a, b string) bool { return subtle.ConstantTimeCompare([]byte(a), []byte(b)) == 1 }

// ---------------------------------------------------------------- auditoria

// Audit grava uma entrada encadeada. A transação IMMEDIATE serializa
// escritores de processos diferentes (servidor e CLI).
func (s *Store) Audit(event, actor string, data map[string]any) error {
	raw, err := json.Marshal(data)
	if err != nil {
		return err
	}
	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	var seq int64
	prev := audit.Genesis
	err = tx.QueryRow(`SELECT seq, hash FROM audit ORDER BY seq DESC LIMIT 1`).Scan(&seq, &prev)
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		return err
	}
	e := audit.Entry{Seq: seq + 1, TS: time.Now().UTC(), Event: event, Actor: actor, Data: raw, Prev: prev}
	e.Hash = audit.Hash(e)
	if _, err := tx.Exec(`INSERT INTO audit(seq, ts, event, actor, data, prev, hash) VALUES (?,?,?,?,?,?,?)`,
		e.Seq, e.TS.Format(time.RFC3339Nano), e.Event, e.Actor, string(e.Data), e.Prev, e.Hash); err != nil {
		return err
	}
	return tx.Commit()
}

func (s *Store) AuditEntries() ([]audit.Entry, error) {
	rows, err := s.db.Query(`SELECT seq, ts, event, actor, data, prev, hash FROM audit ORDER BY seq`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []audit.Entry
	for rows.Next() {
		var e audit.Entry
		var ts, data string
		if err := rows.Scan(&e.Seq, &ts, &e.Event, &e.Actor, &data, &e.Prev, &e.Hash); err != nil {
			return nil, err
		}
		if e.TS, err = time.Parse(time.RFC3339Nano, ts); err != nil {
			return nil, err
		}
		e.Data = json.RawMessage(data)
		out = append(out, e)
	}
	return out, rows.Err()
}

// ------------------------------------------------------------------ tokens

// NewToken cria token de inscrição. O valor só é mostrado agora; o banco guarda o hash.
func (s *Store) NewToken(label string, uses int, ttl time.Duration) (id, token string, err error) {
	if uses < 1 {
		return "", "", errors.New("usos deve ser >= 1")
	}
	id = "tk-" + randHex(4)
	token = "fmr_" + randSecret()
	now := time.Now()
	_, err = s.db.Exec(`INSERT INTO tokens(id, hash, label, uses_left, expires_at, created_at) VALUES (?,?,?,?,?,?)`,
		id, hashSecret(token), label, uses, now.Add(ttl).Unix(), now.Unix())
	return id, token, err
}

// ErrToken: token inexistente, esgotado ou vencido (mesma mensagem para os três).
var ErrToken = errors.New("token de inscrição inválido")

type Agent struct {
	ID, Hostname, OS, Status, CSRPEM, CertPEM, CertSerial, RemoteAddr, TokenID string
	CertExpires, EnrolledAt, ApprovedAt, LastSeen                              int64
	Heartbeat                                                                  string
	// Grupo é o grupo do agente (RBAC): agents.grp, default 'default'.
	Grupo    string
	pollHash string
}

// Online diz se o agente deu check-in dentro de 2× o intervalo (janela de
// tolerância para uma batida perdida). Derivado, não armazenado.
func (a Agent) Online(interval time.Duration, now time.Time) bool {
	if a.LastSeen == 0 {
		return false
	}
	return now.Sub(time.Unix(a.LastSeen, 0)) <= 2*interval
}

// Enroll consome um uso do token e cria o agente PENDENTE (sem auto-join).
func (s *Store) Enroll(token, hostname, goos, csrPEM, remote string) (agentID, poll string, err error) {
	tx, err := s.db.Begin()
	if err != nil {
		return "", "", err
	}
	defer tx.Rollback()
	var tokID string
	err = tx.QueryRow(`SELECT id FROM tokens WHERE hash = ? AND uses_left > 0 AND expires_at > ?`,
		hashSecret(token), time.Now().Unix()).Scan(&tokID)
	if errors.Is(err, sql.ErrNoRows) {
		return "", "", ErrToken
	}
	if err != nil {
		return "", "", err
	}
	if _, err := tx.Exec(`UPDATE tokens SET uses_left = uses_left - 1 WHERE id = ?`, tokID); err != nil {
		return "", "", err
	}
	agentID = "ag-" + randHex(8)
	poll = randSecret()
	if _, err := tx.Exec(`INSERT INTO agents(id, hostname, os, status, csr_pem, poll_hash, token_id, remote_addr, enrolled_at)
		VALUES (?,?,?,?,?,?,?,?,?)`, agentID, hostname, goos, "pending", csrPEM, hashSecret(poll), tokID, remote, time.Now().Unix()); err != nil {
		return "", "", err
	}
	return agentID, poll, tx.Commit()
}

const agentCols = `id, hostname, os, status, csr_pem, cert_pem, cert_serial, cert_expires, poll_hash, token_id, remote_addr, enrolled_at, approved_at, last_seen, heartbeat, grp`

func scanAgent(sc interface{ Scan(...any) error }) (Agent, error) {
	var a Agent
	err := sc.Scan(&a.ID, &a.Hostname, &a.OS, &a.Status, &a.CSRPEM, &a.CertPEM, &a.CertSerial, &a.CertExpires,
		&a.pollHash, &a.TokenID, &a.RemoteAddr, &a.EnrolledAt, &a.ApprovedAt, &a.LastSeen, &a.Heartbeat, &a.Grupo)
	return a, err
}

var ErrNotFound = errors.New("não encontrado")

func (s *Store) Agent(id string) (Agent, error) {
	a, err := scanAgent(s.db.QueryRow(`SELECT `+agentCols+` FROM agents WHERE id = ?`, id))
	if errors.Is(err, sql.ErrNoRows) {
		return a, ErrNotFound
	}
	return a, err
}

func (s *Store) Agents(status string) ([]Agent, error) {
	q, args := `SELECT `+agentCols+` FROM agents ORDER BY enrolled_at`, []any{}
	if status != "" {
		q, args = `SELECT `+agentCols+` FROM agents WHERE status = ? ORDER BY enrolled_at`, []any{status}
	}
	rows, err := s.db.Query(q, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Agent
	for rows.Next() {
		a, err := scanAgent(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, a)
	}
	return out, rows.Err()
}

// CheckPoll confere o segredo de acompanhamento da inscrição.
func (s *Store) CheckPoll(id, poll string) (Agent, error) {
	a, err := s.Agent(id)
	if err != nil {
		return a, err
	}
	if !eqHash(a.pollHash, hashSecret(poll)) {
		return a, ErrNotFound
	}
	return a, nil
}

func (s *Store) Approve(id, certPEM, serial string, expires int64) error {
	r, err := s.db.Exec(`UPDATE agents SET status='approved', cert_pem=?, cert_serial=?, cert_expires=?, approved_at=? WHERE id=? AND status='pending'`,
		certPEM, serial, expires, time.Now().Unix(), id)
	return oneRow(r, err)
}

// SetStatus muda para rejected/revoked. Revogar vale no próximo check-in.
func (s *Store) SetStatus(id, from, to string) error {
	r, err := s.db.Exec(`UPDATE agents SET status=? WHERE id=? AND status=?`, to, id, from)
	return oneRow(r, err)
}

func oneRow(r sql.Result, err error) error {
	if err != nil {
		return err
	}
	if n, _ := r.RowsAffected(); n != 1 {
		return ErrNotFound
	}
	return nil
}

func (s *Store) Seen(id, heartbeat, goos string) error {
	_, err := s.db.Exec(`UPDATE agents SET last_seen=?, heartbeat=?, os=? WHERE id=?`, time.Now().Unix(), heartbeat, goos, id)
	return err
}

// --------------------------------------------------------------- operadores

// Operator é quem usa o console web. O login é por credencial WebAuthn
// (operator_credentials); o cert mTLS do operador fica ligado por thumbprint.
//
// SigningPub é a chave Ed25519 de assinatura do operador (base64, pública). A
// chave privada fica no navegador (WebCrypto, não exportável); o servidor só
// guarda a pública, que entra na lista de signers assinada offline pela raiz.
type Operator struct {
	ID, Nome, DisplayName, CertThumbprint, Status, TechName string
	CriadoEm                                                int64
	SigningPub                                              string
}

// OperatorCredential é uma chave WebAuthn do operador (o cadastro exige duas:
// a principal e a de backup).
type OperatorCredential struct {
	CredentialID, OperatorID string
	PublicKey                []byte
	SignCount                uint32
	AAGUID                   string
	CriadoEm                 int64
}

const operatorCols = `id, nome, display_name, cert_thumbprint, status, criado_em, tech_name, signing_pub`

func scanOperator(sc interface{ Scan(...any) error }) (Operator, error) {
	var o Operator
	err := sc.Scan(&o.ID, &o.Nome, &o.DisplayName, &o.CertThumbprint, &o.Status, &o.CriadoEm, &o.TechName, &o.SigningPub)
	return o, err
}

// CreateOperator cadastra o operador ligado a um técnico existente (tech_name).
// O acesso do operador é o do técnico (CanAccess). Sem status, entra como
// 'pendente' (não loga até registrar as credenciais e o cert).
func (s *Store) CreateOperator(op Operator) error {
	if op.ID == "" || op.Nome == "" {
		return errors.New("operador precisa de id e nome")
	}
	if op.TechName == "" {
		return errors.New("operador precisa de um técnico (tech_name)")
	}
	var n int
	if err := s.db.QueryRow(`SELECT COUNT(*) FROM techs WHERE name=?`, op.TechName).Scan(&n); err != nil {
		return err
	}
	if n == 0 {
		return fmt.Errorf("técnico %q não existe", op.TechName)
	}
	if op.Status == "" {
		op.Status = "pendente"
	}
	_, err := s.db.Exec(`INSERT INTO operators(id, nome, display_name, cert_thumbprint, status, criado_em, tech_name) VALUES (?,?,?,?,?,?,?)`,
		op.ID, op.Nome, op.DisplayName, op.CertThumbprint, op.Status, time.Now().Unix(), op.TechName)
	return err
}

func (s *Store) GetOperator(id string) (Operator, error) {
	o, err := scanOperator(s.db.QueryRow(`SELECT `+operatorCols+` FROM operators WHERE id=?`, id))
	if errors.Is(err, sql.ErrNoRows) {
		return o, ErrNotFound
	}
	return o, err
}

// OperatorByThumbprint acha o operador dono do cert mTLS (T3 usa no handshake).
func (s *Store) OperatorByThumbprint(thumb string) (Operator, error) {
	if thumb == "" {
		return Operator{}, ErrNotFound
	}
	o, err := scanOperator(s.db.QueryRow(`SELECT `+operatorCols+` FROM operators WHERE cert_thumbprint=?`, thumb))
	if errors.Is(err, sql.ErrNoRows) {
		return o, ErrNotFound
	}
	return o, err
}

// SetOperatorThumbprint liga o cert mTLS do operador. Thumbprint repetido em
// outro operador é recusado pelo índice único.
func (s *Store) SetOperatorThumbprint(id, thumb string) error {
	if thumb == "" {
		return errors.New("thumbprint do cert não pode ser vazio")
	}
	r, err := s.db.Exec(`UPDATE operators SET cert_thumbprint=? WHERE id=?`, thumb, id)
	return oneRow(r, err)
}

// SetOperatorSigningPub grava (ou troca, na rotação) a chave pública de
// assinatura do operador. A pública é normalizada (base64 padrão, 32 bytes).
// Pub repetida em outro operador é recusada pelo índice único.
func (s *Store) SetOperatorSigningPub(id, pubB64 string) error {
	pub, err := sign.DecodePub(pubB64)
	if err != nil {
		return fmt.Errorf("chave de assinatura do operador: %w", err)
	}
	r, err := s.db.Exec(`UPDATE operators SET signing_pub=? WHERE id=?`, sign.EncodePub(pub), id)
	return oneRow(r, err)
}

// SetOperatorStatus muda o status do operador (ex.: 'pendente' -> 'ativo').
// Quem chama é o administrador (CLI/handler com a checagem de permissão).
func (s *Store) SetOperatorStatus(id, status string) error {
	if status == "" {
		return errors.New("status do operador não pode ser vazio")
	}
	r, err := s.db.Exec(`UPDATE operators SET status=? WHERE id=?`, status, id)
	return oneRow(r, err)
}

// AddCredential registra uma chave WebAuthn. credential_id é chave primária:
// a mesma credencial não entra duas vezes.
func (s *Store) AddCredential(c OperatorCredential) error {
	_, err := s.db.Exec(`INSERT INTO operator_credentials(credential_id, operator_id, public_key, sign_count, aaguid, criado_em) VALUES (?,?,?,?,?,?)`,
		c.CredentialID, c.OperatorID, c.PublicKey, c.SignCount, c.AAGUID, time.Now().Unix())
	return err
}

// Credentials devolve as credenciais do operador (vazio se não houver).
func (s *Store) Credentials(operatorID string) ([]OperatorCredential, error) {
	rows, err := s.db.Query(`SELECT credential_id, operator_id, public_key, sign_count, aaguid, criado_em
		FROM operator_credentials WHERE operator_id=? ORDER BY criado_em, credential_id`, operatorID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []OperatorCredential
	for rows.Next() {
		var c OperatorCredential
		if err := rows.Scan(&c.CredentialID, &c.OperatorID, &c.PublicKey, &c.SignCount, &c.AAGUID, &c.CriadoEm); err != nil {
			return nil, err
		}
		out = append(out, c)
	}
	return out, rows.Err()
}

// UpdateSignCount grava o contador de assinaturas da credencial.
func (s *Store) UpdateSignCount(credentialID string, n uint32) error {
	r, err := s.db.Exec(`UPDATE operator_credentials SET sign_count=? WHERE credential_id=?`, n, credentialID)
	return oneRow(r, err)
}

// -------------------------------------------------------------------- jobs

type Job struct {
	ID, AgentID, Action, Params, Signed, Issuer, Status, Result string
	CreatedAt, ExpiresAt, DeliveredAt, FinishedAt               int64
}

func (s *Store) AddJob(j Job) error {
	_, err := s.db.Exec(`INSERT INTO jobs(id, agent_id, action, params, signed, issuer, status, created_at, expires_at) VALUES (?,?,?,?,?,?,?,?,?)`,
		j.ID, j.AgentID, j.Action, j.Params, j.Signed, j.Issuer, "queued", time.Now().Unix(), j.ExpiresAt)
	return err
}

const jobCols = `id, agent_id, action, params, signed, issuer, status, result, created_at, expires_at, delivered_at, finished_at`

func scanJob(sc interface{ Scan(...any) error }) (Job, error) {
	var j Job
	err := sc.Scan(&j.ID, &j.AgentID, &j.Action, &j.Params, &j.Signed, &j.Issuer, &j.Status, &j.Result,
		&j.CreatedAt, &j.ExpiresAt, &j.DeliveredAt, &j.FinishedAt)
	return j, err
}

// jobStaleApos: um job 'delivered' sem resultado vira 'stale' depois de
// expires_at + ClockSkew (o agente ainda pode executar dentro da tolerância de
// relógio; passada ela, o resultado não será mais aceito).
const jobStaleApos = proto.ClockSkew

// MarcarJobsStale converte jobs 'delivered' sem resultado e vencidos em 'stale'
// (o servidor não deixa 'delivered' eterno). Devolve quantos mudaram.
func (s *Store) MarcarJobsStale(agora time.Time) (int64, error) {
	r, err := s.db.Exec(`UPDATE jobs SET status='stale', finished_at=? WHERE status='delivered' AND finished_at=0 AND expires_at + ? <= ?`,
		agora.Unix(), int64(jobStaleApos/time.Second), agora.Unix())
	if err != nil {
		return 0, err
	}
	return r.RowsAffected()
}

// TakeQueued marca como entregues e devolve os jobs na fila do agente.
// Jobs vencidos viram 'expired' e não são entregues.
func (s *Store) TakeQueued(ctx context.Context, agentID string) ([]Job, error) {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()
	now := time.Now().Unix()
	if _, err := tx.Exec(`UPDATE jobs SET status='stale', finished_at=? WHERE status='delivered' AND finished_at=0 AND expires_at + ? <= ?`,
		now, int64(jobStaleApos/time.Second), now); err != nil {
		return nil, err
	}
	if _, err := tx.Exec(`UPDATE jobs SET status='expired' WHERE agent_id=? AND status='queued' AND expires_at <= ?`, agentID, now); err != nil {
		return nil, err
	}
	rows, err := tx.Query(`SELECT `+jobCols+` FROM jobs WHERE agent_id=? AND status='queued' ORDER BY created_at LIMIT 20`, agentID)
	if err != nil {
		return nil, err
	}
	var out []Job
	for rows.Next() {
		j, err := scanJob(rows)
		if err != nil {
			rows.Close()
			return nil, err
		}
		out = append(out, j)
	}
	rows.Close()
	for _, j := range out {
		if _, err := tx.Exec(`UPDATE jobs SET status='delivered', delivered_at=? WHERE id=?`, now, j.ID); err != nil {
			return nil, err
		}
	}
	return out, tx.Commit()
}

func (s *Store) Job(id string) (Job, error) {
	if _, err := s.MarcarJobsStale(time.Now()); err != nil {
		return Job{}, err
	}
	j, err := scanJob(s.db.QueryRow(`SELECT `+jobCols+` FROM jobs WHERE id=?`, id))
	if errors.Is(err, sql.ErrNoRows) {
		return j, ErrNotFound
	}
	return j, err
}

func (s *Store) Jobs(agentID string, limit int) ([]Job, error) {
	if _, err := s.MarcarJobsStale(time.Now()); err != nil {
		return nil, err
	}
	q, args := `SELECT `+jobCols+` FROM jobs ORDER BY created_at DESC LIMIT ?`, []any{limit}
	if agentID != "" {
		q, args = `SELECT `+jobCols+` FROM jobs WHERE agent_id=? ORDER BY created_at DESC LIMIT ?`, []any{agentID, limit}
	}
	rows, err := s.db.Query(q, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Job
	for rows.Next() {
		j, err := scanJob(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, j)
	}
	return out, rows.Err()
}

// ResultadosDeLeitura devolve os últimos jobs JÁ FINALIZADOS do agente cujas
// ações estão em acoes (ex.: só as read-only). Leitura pura: não altera nada.
// Mais novos primeiro; limit limita a quantidade.
func (s *Store) ResultadosDeLeitura(agentID string, acoes []string, limit int) ([]Job, error) {
	if len(acoes) == 0 || limit <= 0 {
		return nil, nil
	}
	marcas := make([]string, len(acoes))
	args := []any{agentID}
	for i, a := range acoes {
		marcas[i] = "?"
		args = append(args, a)
	}
	args = append(args, limit)
	q := `SELECT ` + jobCols + ` FROM jobs WHERE agent_id=? AND finished_at > 0 AND action IN (` +
		strings.Join(marcas, ",") + `) ORDER BY finished_at DESC, id DESC LIMIT ?`
	rows, err := s.db.Query(q, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Job
	for rows.Next() {
		j, err := scanJob(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, j)
	}
	return out, rows.Err()
}

// FinishJob grava o resultado. Só aceita job entregue AO MESMO agente.
func (s *Store) FinishJob(agentID, jobID, status, result string) error {
	r, err := s.db.Exec(`UPDATE jobs SET status=?, result=?, finished_at=? WHERE id=? AND agent_id=? AND status='delivered'`,
		status, result, time.Now().Unix(), jobID, agentID)
	return oneRow(r, err)
}
