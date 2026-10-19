// Autenticação WebAuthn do operador do console (T2).
//
// Versão fixada: github.com/go-webauthn/webauthn v0.18.2 (publicada em 2026-09-19).
//
// Adaptações à API real da lib (divergências da spec, todas decididas aqui):
//   - A lib NÃO recusa contador de assinaturas regredido: ela só marca
//     CloneWarning e mantém o contador. A recusa anti-clone é nossa
//     (verificaAsercao), comparando o contador BRUTO da asserção com o guardado.
//   - A lib não traz autenticador virtual. Os testes usam um autenticador de
//     software (ES256, attestation "none") que gera registro e asserção reais,
//     validados pelo próprio FinishRegistration/ValidateLogin da lib.
//   - A validação de login compara o flag Backup Eligible com o persistido. O
//     store não guarda flags; por isso só se aceitam chaves NÃO sincronizáveis
//     (BE=0, chave física). Ver ErrChaveSincronizavel.
//   - O thumbprint do cert mTLS do operador entra por PARÂMETRO (T3 verifica o
//     cert e fornece). Nada de leitura de TLS aqui.
//
// Política do cadastro (documentada, não travada no store): cada operador
// registra DUAS chaves (principal + backup). O cadastro de chaves só acontece
// com o operador 'pendente'; a ativação ('ativo') é ação de administrador.
// Sem canal de recuperação por e-mail/SMS (ver docs/console-seguranca.md).
package console

import (
	"bytes"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/go-webauthn/webauthn/protocol"
	"github.com/go-webauthn/webauthn/webauthn"

	"github.com/eduardohenriquemoretti0-ops/fm-rmm/internal/server"
)

const (
	// TTLCerimonia é a janela de cada desafio (begin -> finish). Curta de propósito.
	TTLCerimonia = 2 * time.Minute
	// StepUpTTL é a janela de um step-up depois de um re-toque WebAuthn.
	StepUpTTL = 2 * time.Minute

	maxCerimonias  = 1000 // teto de desafios pendentes (contra enchimento de memória)
	maxUserHandle  = 64   // limite do user handle do WebAuthn
	statusPendente = "pendente"
	statusAtivo    = "ativo"
	nomeRPPadrao   = "FM-RMM Console"
)

var (
	// ErrAutenticacaoRecusada é a resposta genérica: não revela se o operador
	// existe, se está inativo ou se a chave não confere.
	ErrAutenticacaoRecusada = errors.New("autenticação recusada")
	ErrCerimonia            = errors.New("cerimônia inválida ou já usada")
	ErrCerimoniaExpirada    = errors.New("cerimônia expirada")
	ErrCerimoniasCheias     = errors.New("muitas cerimônias pendentes; tente em instantes")
	ErrCloneSuspeito        = errors.New("contador de assinaturas regrediu: possível clone da chave")
	ErrChaveSincronizavel   = errors.New("chave sincronizável (backup eligible) não é aceita: use chave física")
	ErrRegistroFechado      = errors.New("cadastro de chaves só com operador pendente")
	ErrThumbprint           = errors.New("thumbprint do certificado do operador inválido")
)

// ConfigWebAuthn é a relying party do console. Vem de configuração, nunca fixa
// no código. RPID = domínio do console (sem esquema nem porta); RPOrigins =
// origens https permitidas, que têm de estar sob o RPID.
type ConfigWebAuthn struct {
	RPID          string
	RPDisplayName string
	RPOrigins     []string
}

func (c ConfigWebAuthn) valida() error {
	if c.RPID == "" || strings.ContainsAny(c.RPID, ":/?#@") {
		return errors.New("RPID deve ser só o domínio do console (sem esquema, porta ou caminho)")
	}
	if len(c.RPOrigins) == 0 {
		return errors.New("RPOrigins vazio")
	}
	for _, o := range c.RPOrigins {
		u, err := url.Parse(o)
		if err != nil || u.Scheme != "https" || u.Host == "" {
			return fmt.Errorf("origem %q inválida: exige https://host", o)
		}
		h := u.Hostname()
		if h != c.RPID && !strings.HasSuffix(h, "."+c.RPID) {
			return fmt.Errorf("origem %q fora do RPID %q", o, c.RPID)
		}
	}
	return nil
}

// operadorWA adapta server.Operator + credenciais do store para webauthn.User.
type operadorWA struct {
	op    server.Operator
	creds []webauthn.Credential
}

var _ webauthn.User = operadorWA{}

// WebAuthnID é o user handle: o id do operador (controlado pelo servidor, <= 64 bytes).
func (u operadorWA) WebAuthnID() []byte { return []byte(u.op.ID) }

func (u operadorWA) WebAuthnName() string { return u.op.Nome }

func (u operadorWA) WebAuthnDisplayName() string {
	if u.op.DisplayName != "" {
		return u.op.DisplayName
	}
	return u.op.Nome
}

func (u operadorWA) WebAuthnCredentials() []webauthn.Credential { return u.creds }

// CerimoniaStore guarda os desafios pendentes. Cada um tem TTL curto, é de USO
// ÚNICO e fica preso ao tipo (registro/login/stepup) e ao operador.
type CerimoniaStore struct {
	mu  sync.Mutex
	m   map[string]cerimonia
	ttl time.Duration
	max int
	now func() time.Time
}

type cerimonia struct {
	tipo, opID string
	sessao     webauthn.SessionData
	expira     time.Time
}

// NovoCerimoniaStore cria o armazém de desafios (ttl, teto de entradas, relógio).
func NovoCerimoniaStore(ttl time.Duration, max int, now func() time.Time) *CerimoniaStore {
	return &CerimoniaStore{m: map[string]cerimonia{}, ttl: ttl, max: max, now: now}
}

// Nova guarda a sessão de uma cerimônia e devolve a chave (aleatória) que o
// cliente devolve no finish.
func (c *CerimoniaStore) Nova(tipo, opID string, sd webauthn.SessionData) (string, error) {
	key, err := randToken()
	if err != nil {
		return "", err
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	now := c.now()
	if len(c.m) >= c.max {
		c.gcLocked(now)
	}
	if len(c.m) >= c.max {
		return "", ErrCerimoniasCheias
	}
	c.m[key] = cerimonia{tipo: tipo, opID: opID, sessao: sd, expira: now.Add(c.ttl)}
	return key, nil
}

// Consome devolve a sessão da cerimônia e a APAGA, mesmo que a validação
// falhe depois (um desafio não se reaproveita). Tipo e operador têm de bater.
func (c *CerimoniaStore) Consome(key, tipo, opID string) (webauthn.SessionData, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	e, ok := c.m[key]
	if !ok {
		return webauthn.SessionData{}, ErrCerimonia
	}
	delete(c.m, key)
	if e.tipo != tipo || e.opID != opID {
		return webauthn.SessionData{}, ErrCerimonia
	}
	if c.now().After(e.expira) {
		return webauthn.SessionData{}, ErrCerimoniaExpirada
	}
	return e.sessao, nil
}

// GC remove os desafios vencidos (também roda sob demanda quando o armazém enche).
func (c *CerimoniaStore) GC() {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.gcLocked(c.now())
}

func (c *CerimoniaStore) gcLocked(now time.Time) {
	for k, e := range c.m {
		if now.After(e.expira) {
			delete(c.m, k)
		}
	}
}

// Autenticador conduz as cerimônias WebAuthn do console e emite/estende sessões.
type Autenticador struct {
	wa  *webauthn.WebAuthn
	st  *server.Store
	sm  *SessionManager
	cer *CerimoniaStore
	// mu serializa "verificar asserção + gravar contador": sem isso, duas
	// asserções concorrentes com o mesmo contador passariam ambas (corrida anti-clone).
	mu sync.Mutex
}

// NovoAutenticador valida a configuração e monta o autenticador.
func NovoAutenticador(cfg ConfigWebAuthn, st *server.Store, sm *SessionManager) (*Autenticador, error) {
	if st == nil || sm == nil {
		return nil, errors.New("webauthn: store e session manager são obrigatórios")
	}
	if err := cfg.valida(); err != nil {
		return nil, fmt.Errorf("webauthn: %w", err)
	}
	nome := cfg.RPDisplayName
	if nome == "" {
		nome = nomeRPPadrao
	}
	wa, err := webauthn.New(&webauthn.Config{
		RPID:          cfg.RPID,
		RPDisplayName: nome,
		RPOrigins:     cfg.RPOrigins,
	})
	if err != nil {
		return nil, fmt.Errorf("webauthn: %w", err)
	}
	return &Autenticador{
		wa:  wa,
		st:  st,
		sm:  sm,
		cer: NovoCerimoniaStore(TTLCerimonia, maxCerimonias, time.Now),
	}, nil
}

// carrega monta o adaptador do operador com as credenciais do store.
func (a *Autenticador) carrega(opID string) (operadorWA, error) {
	op, err := a.st.GetOperator(opID)
	if errors.Is(err, server.ErrNotFound) {
		return operadorWA{}, ErrAutenticacaoRecusada
	}
	if err != nil {
		return operadorWA{}, err
	}
	if len(op.ID) == 0 || len(op.ID) > maxUserHandle {
		return operadorWA{}, errors.New("id do operador fora do limite do user handle")
	}
	cs, err := a.st.Credentials(opID)
	if err != nil {
		return operadorWA{}, err
	}
	creds := make([]webauthn.Credential, 0, len(cs))
	for _, c := range cs {
		id, err := base64.RawURLEncoding.DecodeString(c.CredentialID)
		if err != nil {
			return operadorWA{}, fmt.Errorf("credencial %q corrompida: %w", c.CredentialID, err)
		}
		aaguid, err := hex.DecodeString(c.AAGUID)
		if err != nil {
			return operadorWA{}, fmt.Errorf("aaguid da credencial corrompido: %w", err)
		}
		creds = append(creds, webauthn.Credential{
			ID:            id,
			PublicKey:     c.PublicKey,
			Authenticator: webauthn.Authenticator{AAGUID: aaguid, SignCount: c.SignCount},
		})
	}
	return operadorWA{op: op, creds: creds}, nil
}

// IniciaRegistro começa o cadastro de uma chave. Só com operador 'pendente'.
// Devolve as opções para o navegador e a chave da cerimônia.
func (a *Autenticador) IniciaRegistro(opID string) (*protocol.CredentialCreation, string, error) {
	u, err := a.carrega(opID)
	if err != nil {
		return nil, "", err
	}
	if u.op.Status != statusPendente {
		return nil, "", ErrRegistroFechado
	}
	creation, sd, err := a.wa.BeginRegistration(u,
		webauthn.WithAuthenticatorSelection(protocol.AuthenticatorSelection{
			UserVerification: protocol.VerificationRequired,
		}),
		webauthn.WithConveyancePreference(protocol.PreferNoAttestation),
	)
	if err != nil {
		return nil, "", fmt.Errorf("registro WebAuthn: %w", err)
	}
	key, err := a.cer.Nova("registro", opID, *sd)
	if err != nil {
		return nil, "", err
	}
	return creation, key, nil
}

// FinalizaRegistro valida a resposta do navegador e persiste a credencial
// (AddCredential). Devolve o id da credencial (base64url).
func (a *Autenticador) FinalizaRegistro(opID, key string, req *http.Request) (string, error) {
	sd, err := a.cer.Consome(key, "registro", opID)
	if err != nil {
		return "", err
	}
	u, err := a.carrega(opID)
	if err != nil {
		return "", err
	}
	if u.op.Status != statusPendente {
		return "", ErrRegistroFechado
	}
	cred, err := a.wa.FinishRegistration(u, sd, req)
	if err != nil {
		return "", fmt.Errorf("registro WebAuthn: %w", err)
	}
	if cred.Flags.BackupEligible {
		return "", ErrChaveSincronizavel
	}
	credID := base64.RawURLEncoding.EncodeToString(cred.ID)
	if err := a.st.AddCredential(server.OperatorCredential{
		CredentialID: credID,
		OperatorID:   opID,
		PublicKey:    cred.PublicKey,
		SignCount:    cred.Authenticator.SignCount,
		AAGUID:       hex.EncodeToString(cred.Authenticator.AAGUID),
	}); err != nil {
		return "", err
	}
	if err := a.st.Audit("operador.webauthn.registro", opID, map[string]any{"credencial": credID}); err != nil {
		return "", err
	}
	return credID, nil
}

// iniciaAsercao começa uma asserção (login ou step-up). Exige operador 'ativo'
// com ao menos uma credencial.
func (a *Autenticador) iniciaAsercao(tipo, opID string) (*protocol.CredentialAssertion, string, error) {
	u, err := a.carrega(opID)
	if err != nil {
		return nil, "", err
	}
	if u.op.Status != statusAtivo || len(u.creds) == 0 {
		return nil, "", ErrAutenticacaoRecusada
	}
	assertion, sd, err := a.wa.BeginLogin(u, webauthn.WithUserVerification(protocol.VerificationRequired))
	if err != nil {
		return nil, "", fmt.Errorf("login WebAuthn: %w", err)
	}
	key, err := a.cer.Nova(tipo, opID, *sd)
	if err != nil {
		return nil, "", err
	}
	return assertion, key, nil
}

// IniciaLogin começa o login WebAuthn do operador.
func (a *Autenticador) IniciaLogin(opID string) (*protocol.CredentialAssertion, string, error) {
	return a.iniciaAsercao("login", opID)
}

// verificaAsercao valida a asserção do navegador contra as credenciais do
// operador e aplica o anti-clone. Chamar só com a.mu livre (ela trava).
// Regra: se o contador guardado > 0 e o recebido <= guardado, recusa (possível
// clone) e NÃO grava. Senão grava o contador novo.
func (a *Autenticador) verificaAsercao(opID string, sd webauthn.SessionData, req *http.Request) error {
	a.mu.Lock()
	defer a.mu.Unlock()

	u, err := a.carrega(opID)
	if err != nil {
		return err
	}
	if u.op.Status != statusAtivo {
		return ErrAutenticacaoRecusada
	}
	parsed, err := protocol.ParseCredentialRequestResponse(req)
	if err != nil {
		return ErrAutenticacaoRecusada
	}
	var guardada *webauthn.Credential
	for i := range u.creds {
		if bytes.Equal(u.creds[i].ID, parsed.RawID) {
			guardada = &u.creds[i]
			break
		}
	}
	if guardada == nil {
		return ErrAutenticacaoRecusada
	}
	cred, err := a.wa.ValidateLogin(u, sd, parsed)
	if err != nil {
		return fmt.Errorf("asserção WebAuthn: %w", err)
	}

	credID := base64.RawURLEncoding.EncodeToString(parsed.RawID)
	antes := guardada.Authenticator.SignCount
	novo := parsed.Response.AuthenticatorData.Counter // contador BRUTO da asserção
	// A lib só sinaliza CloneWarning; a recusa é desta camada.
	if (antes > 0 && novo <= antes) || cred.Authenticator.CloneWarning {
		if errA := a.st.Audit("operador.clone_suspeito", opID, map[string]any{
			"credencial": credID, "contador_guardado": antes, "contador_recebido": novo,
		}); errA != nil {
			return errors.Join(ErrCloneSuspeito, errA)
		}
		return ErrCloneSuspeito
	}
	if novo != antes {
		if err := a.st.UpdateSignCount(credID, novo); err != nil {
			return err
		}
	}
	return nil
}

// thumbprintValido confere o formato (SHA-256 em hex) do thumbprint do cert.
func thumbprintValido(t string) bool {
	b, err := hex.DecodeString(t)
	return err == nil && len(b) == sha256.Size
}

// FinalizaLogin valida a asserção, confere que o cert mTLS (thumbprint, dado por
// T3) é o do operador, audita e emite a sessão ligada a esse cert. Devolve o
// token em claro (vai no cookie uma vez) e o token CSRF.
func (a *Autenticador) FinalizaLogin(opID, key, thumbprint string, req *http.Request) (rawToken, csrf string, err error) {
	if !thumbprintValido(thumbprint) {
		return "", "", ErrThumbprint
	}
	sd, err := a.cer.Consome(key, "login", opID)
	if err != nil {
		return "", "", err
	}
	op, err := a.st.GetOperator(opID)
	if errors.Is(err, server.ErrNotFound) {
		return "", "", ErrAutenticacaoRecusada
	}
	if err != nil {
		return "", "", err
	}
	if op.Status != statusAtivo || op.CertThumbprint == "" ||
		subtle.ConstantTimeCompare([]byte(op.CertThumbprint), []byte(thumbprint)) != 1 {
		return "", "", ErrAutenticacaoRecusada
	}
	if err := a.verificaAsercao(opID, sd, req); err != nil {
		return "", "", err
	}
	if err := a.st.Audit("operador.login", opID, map[string]any{"thumbprint": thumbprint}); err != nil {
		return "", "", err
	}
	return a.sm.New(opID, thumbprint)
}

// IniciaStepUp começa o re-toque WebAuthn de uma sessão viva (ações sensíveis).
func (a *Autenticador) IniciaStepUp(rawToken, thumbprint string) (*protocol.CredentialAssertion, string, error) {
	s, err := a.sm.Validate(rawToken, thumbprint)
	if err != nil {
		return nil, "", err
	}
	return a.iniciaAsercao("stepup", s.OperatorID)
}

// FinalizaStepUp valida o re-toque do MESMO operador da sessão e marca o step-up
// válido por StepUpTTL. Anti-clone vale aqui também.
func (a *Autenticador) FinalizaStepUp(rawToken, thumbprint, key string, req *http.Request) error {
	s, err := a.sm.Validate(rawToken, thumbprint)
	if err != nil {
		return err
	}
	opID := s.OperatorID
	sd, err := a.cer.Consome(key, "stepup", opID)
	if err != nil {
		return err
	}
	if err := a.verificaAsercao(opID, sd, req); err != nil {
		return err
	}
	if err := a.st.Audit("operador.step_up", opID, map[string]any{}); err != nil {
		return err
	}
	return a.sm.MarcarStepUp(rawToken, thumbprint, StepUpTTL)
}
