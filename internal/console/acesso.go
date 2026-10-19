// Acesso do operador ao console (T3): mTLS + sessão + CSRF.
//
// Encadeamento das rotas protegidas (ordem fixa, fail-closed em cada elo):
//
//	SecurityHeaders -> comCert (cadeia do cert contra a NOSSA CA + PERFIL de
//	operador + operador pelo thumbprint) -> comSessao (token ligado ao thumbprint, via
//	SessionManager.Validate) -> comCSRF (só em POST/PUT/PATCH/DELETE, via
//	Session.CheckCSRF) -> handler.
//
// Decisões (ver docs/console-seguranca.md e docs/console-handoff-agentes.md §T3):
//   - o handshake já exige cert de cliente (TLSConfigConsole); o middleware
//     REVERIFICA a cadeia com x509.Verify, para não depender só do handshake e
//     para ser testável com tls.ConnectionState forjado;
//   - nenhuma resposta de acesso negado revela o motivo (outra CA, operador
//     inexistente, token de outro cliente): sempre 401 genérico;
//   - cookie de sessão com prefixo __Host- (exige Secure, Path=/ e sem Domain);
//   - sessão de operador que não está 'ativo' é revogada na hora.
package console

import (
	"context"
	"crypto/x509"
	"errors"
	"net/http"
	"time"

	"github.com/eduardohenriquemoretti0-ops/fm-rmm/internal/pki"
	"github.com/eduardohenriquemoretti0-ops/fm-rmm/internal/server"
)

const (
	// NomeCookieSessao é o cookie do token de sessão. O prefixo __Host- faz o
	// próprio navegador recusar o cookie sem Secure, sem Path=/ ou com Domain.
	NomeCookieSessao = "__Host-fmrmm_sessao"
	// CabecalhoCSRF carrega o token anti-CSRF nas rotas de escrita.
	CabecalhoCSRF = "X-FMRMM-CSRF"
)

// Console reúne as dependências do acesso do operador. Só o construtor
// NovoConsole o monta, com validação das dependências.
type Console struct {
	sessoes   *SessionManager
	aut       *Autenticador
	st        *server.Store
	ca        *x509.CertPool // pool da NOSSA CA: única raiz aceita para o cert do operador
	intervalo time.Duration  // intervalo de check-in dos agentes (base do "online")
	agora     func() time.Time
	estaticos string // diretório do SPA (web/dist); vazio = não serve estáticos
	relayBase string // wss:// do relay aceito em concessões (vazio = concessões desligadas)
}

// NovoConsole monta o console. Exige que o Autenticador e o store sejam os
// mesmos passados aqui, senão uma sessão criada por um manager poderia ser
// validada por outro. intervalo é o check-in dos agentes (ex.: 60s).
func NovoConsole(sessoes *SessionManager, aut *Autenticador, st *server.Store, ca *x509.CertPool, intervalo time.Duration) (*Console, error) {
	if sessoes == nil || aut == nil || st == nil || ca == nil {
		return nil, errors.New("console: sessões, autenticador, store e CA são obrigatórios")
	}
	if aut.sm != sessoes || aut.st != st {
		return nil, errors.New("console: autenticador deve usar o mesmo SessionManager e store")
	}
	if intervalo <= 0 {
		return nil, errors.New("console: intervalo de check-in deve ser positivo")
	}
	return &Console{sessoes: sessoes, aut: aut, st: st, ca: ca, intervalo: intervalo, agora: time.Now}, nil
}

// chaves de contexto: o middleware põe o operador e a sessão; os handlers leem.
type ctxKey int

const (
	ctxOperador ctxKey = iota
	ctxThumbprint
	ctxToken
	ctxSessao
)

// OperadorDoContexto devolve o operador autenticado pelo cert mTLS e o thumbprint.
func OperadorDoContexto(ctx context.Context) (server.Operator, string, bool) {
	op, ok1 := ctx.Value(ctxOperador).(server.Operator)
	thumb, ok2 := ctx.Value(ctxThumbprint).(string)
	return op, thumb, ok1 && ok2
}

// SessaoDoContexto devolve a sessão validada e o token em claro desta requisição.
func SessaoDoContexto(ctx context.Context) (*Session, string, bool) {
	s, ok1 := ctx.Value(ctxSessao).(*Session)
	tok, ok2 := ctx.Value(ctxToken).(string)
	return s, tok, ok1 && ok2
}

// negado responde 401 genérico. Nunca diz o motivo.
func negado(w http.ResponseWriter) {
	writeJSON(w, http.StatusUnauthorized, map[string]string{"erro": "autenticação recusada"})
}

// comCert exige cert de cliente da nossa CA e um operador cadastrado com esse
// thumbprint. Não exige sessão: serve ao login e ao registro.
func (c *Console) comCert(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.TLS == nil || len(r.TLS.PeerCertificates) == 0 {
			negado(w)
			return
		}
		leaf := r.TLS.PeerCertificates[0]
		inter := x509.NewCertPool()
		for _, ic := range r.TLS.PeerCertificates[1:] {
			inter.AddCert(ic)
		}
		if _, err := leaf.Verify(x509.VerifyOptions{
			Roots:         c.ca,
			Intermediates: inter,
			KeyUsages:     []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
		}); err != nil {
			negado(w)
			return
		}
		// T3b: cadeia válida NÃO basta. Cert de agente é da mesma CA; só o
		// perfil de operador (Organization) o diferencia.
		if !pki.EhOperador(leaf) {
			negado(w)
			return
		}
		thumb := CertThumbprint(leaf)
		op, err := c.st.OperatorByThumbprint(thumb)
		if errors.Is(err, server.ErrNotFound) {
			negado(w)
			return
		}
		if err != nil {
			// falha de infraestrutura: fecha a porta sem detalhar
			negado(w)
			return
		}
		ctx := context.WithValue(r.Context(), ctxOperador, op)
		ctx = context.WithValue(ctx, ctxThumbprint, thumb)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

// comSessao exige o cookie de sessão ligado ao thumbprint do cert atual. Em
// falha, limpa o cookie no navegador.
func (c *Console) comSessao(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		op, thumb, ok := OperadorDoContexto(r.Context())
		if !ok {
			negado(w)
			return
		}
		ck, err := r.Cookie(NomeCookieSessao)
		if err != nil || ck.Value == "" {
			negado(w)
			return
		}
		s, err := c.sessoes.Validate(ck.Value, thumb)
		if err != nil {
			// inclui ErrClienteDiferente: token válido, mas de outro cliente.
			// Não revoga (quem paga é só quem apresentou), só limpa o cookie.
			limpaCookieSessao(w)
			negado(w)
			return
		}
		if s.OperatorID != op.ID || op.Status != statusAtivo {
			c.sessoes.Revoke(ck.Value)
			limpaCookieSessao(w)
			negado(w)
			return
		}
		ctx := context.WithValue(r.Context(), ctxSessao, s)
		ctx = context.WithValue(ctx, ctxToken, ck.Value)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

// escritaCSRF diz se o método muda estado e por isso exige o token CSRF.
func escritaCSRF(metodo string) bool {
	switch metodo {
	case http.MethodPost, http.MethodPut, http.MethodPatch, http.MethodDelete:
		return true
	}
	return false
}

// comCSRF exige o header X-FMRMM-CSRF conferido com a sessão nas rotas de
// escrita. Fail-closed: sem sessão no contexto, recusa com 401.
func (c *Console) comCSRF(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !escritaCSRF(r.Method) {
			next.ServeHTTP(w, r)
			return
		}
		s, _, ok := SessaoDoContexto(r.Context())
		if !ok {
			negado(w)
			return
		}
		if err := s.CheckCSRF(r.Header.Get(CabecalhoCSRF)); err != nil {
			writeJSON(w, http.StatusForbidden, map[string]string{"erro": "CSRF ausente ou inválido"})
			return
		}
		next.ServeHTTP(w, r)
	})
}

// protegido = cert + sessão + CSRF (rotas de operador logado).
func (c *Console) protegido(h http.HandlerFunc) http.Handler {
	return c.comCert(c.comSessao(c.comCSRF(h)))
}

// soCert = só cert + operador (login e registro, antes de existir sessão).
func (c *Console) soCert(h http.HandlerFunc) http.Handler {
	return c.comCert(h)
}

// limpaCookieSessao manda o navegador apagar o cookie, com os mesmos atributos.
func limpaCookieSessao(w http.ResponseWriter) {
	c := SessionCookie(NomeCookieSessao, "", 0)
	c.MaxAge = -1
	http.SetCookie(w, c)
}
