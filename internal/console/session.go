package console

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"sync"
	"time"
)

// Sessão do operador no console. Decisões de segurança (ver docs/console-seguranca.md):
//   - o token NUNCA é guardado em texto: o manager guarda só o SHA-256 dele, e a
//     comparação é constant-time (dump de memória do manager não vaza token vivo);
//   - a sessão é LIGADA AO CLIENTE pelo thumbprint do cert mTLS do operador: um
//     token copiado para outra máquina (sem a chave do cert) não valida;
//   - TTL absoluto curto + TTL de inatividade (os dois expiram a sessão);
//   - cada sessão carrega um token CSRF próprio para as rotas de escrita.
//
// Este manager é a base; os handlers de login (WebAuthn) e os endpoints entram
// nos próximos incrementos e emitem/validam a sessão por aqui.

var (
	ErrSessaoInvalida   = errors.New("sessão inválida ou expirada")
	ErrClienteDiferente = errors.New("token de sessão não pertence a este cliente (mTLS)")
	ErrCSRF             = errors.New("token CSRF inválido")
)

type Session struct {
	OperatorID string
	thumbprint string // SHA-256 do cert mTLS do operador (hex)
	csrf       string
	created    time.Time
	lastSeen   time.Time
}

func (s *Session) OperatorThumbprint() string { return s.thumbprint }

type SessionManager struct {
	mu          sync.Mutex
	byHash      map[string]*Session // chave = SHA-256(token) em hex
	absoluteTTL time.Duration
	idleTTL     time.Duration
	now         func() time.Time
}

// NewSessionManager. absolute = vida máxima; idle = tempo sem uso até expirar.
func NewSessionManager(absolute, idle time.Duration) *SessionManager {
	return &SessionManager{
		byHash:      map[string]*Session{},
		absoluteTTL: absolute,
		idleTTL:     idle,
		now:         time.Now,
	}
}

func tokenHash(raw string) string {
	sum := sha256.Sum256([]byte(raw))
	return hex.EncodeToString(sum[:])
}

func randToken() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}

// CertThumbprint é o identificador estável do cert do operador (SHA-256 do DER).
func CertThumbprint(cert *x509.Certificate) string {
	sum := sha256.Sum256(cert.Raw)
	return hex.EncodeToString(sum[:])
}

// New cria a sessão ligada ao thumbprint do cert do operador. Devolve o token
// em claro (vai no cookie HttpOnly uma única vez) e o token CSRF.
func (m *SessionManager) New(operatorID, thumbprint string) (rawToken, csrf string, err error) {
	rawToken, err = randToken()
	if err != nil {
		return "", "", err
	}
	csrf, err = randToken()
	if err != nil {
		return "", "", err
	}
	now := m.now()
	m.mu.Lock()
	m.byHash[tokenHash(rawToken)] = &Session{
		OperatorID: operatorID,
		thumbprint: thumbprint,
		csrf:       csrf,
		created:    now,
		lastSeen:   now,
	}
	m.mu.Unlock()
	return rawToken, csrf, nil
}

// Validate confere o token e EXIGE que o thumbprint do cert atual bata com o da
// sessão (binding mTLS). Atualiza lastSeen. Expira por TTL absoluto ou inatividade.
func (m *SessionManager) Validate(rawToken, thumbprint string) (*Session, error) {
	h := tokenHash(rawToken)
	now := m.now()
	m.mu.Lock()
	defer m.mu.Unlock()
	s, ok := m.byHash[h]
	if !ok {
		return nil, ErrSessaoInvalida
	}
	if now.Sub(s.created) > m.absoluteTTL || now.Sub(s.lastSeen) > m.idleTTL {
		delete(m.byHash, h)
		return nil, ErrSessaoInvalida
	}
	if subtle.ConstantTimeCompare([]byte(s.thumbprint), []byte(thumbprint)) != 1 {
		// token válido apresentado por outro cliente: não vale, e não renova
		return nil, ErrClienteDiferente
	}
	s.lastSeen = now
	return s, nil
}

// CheckCSRF compara o token CSRF da sessão com o enviado (constant-time).
func (s *Session) CheckCSRF(sent string) error {
	if subtle.ConstantTimeCompare([]byte(s.csrf), []byte(sent)) != 1 {
		return ErrCSRF
	}
	return nil
}

func (s *Session) CSRF() string { return s.csrf }

// Revoke apaga a sessão (logout / step-down).
func (m *SessionManager) Revoke(rawToken string) {
	m.mu.Lock()
	delete(m.byHash, tokenHash(rawToken))
	m.mu.Unlock()
}

// GC remove sessões expiradas (chamar periodicamente).
func (m *SessionManager) GC() {
	now := m.now()
	m.mu.Lock()
	for h, s := range m.byHash {
		if now.Sub(s.created) > m.absoluteTTL || now.Sub(s.lastSeen) > m.idleTTL {
			delete(m.byHash, h)
		}
	}
	m.mu.Unlock()
}
