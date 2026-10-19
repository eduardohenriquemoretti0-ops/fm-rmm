package console

import (
	"encoding/json"
	"errors"
	"net/http"
)

// CabecalhoCerimonia carrega a chave da cerimônia WebAuthn (devolvida pelo
// /inicio). Vai em header porque o corpo do /fim é a própria asserção JSON.
const CabecalhoCerimonia = "X-FMRMM-Cerimonia"

// limiteCorpo limita o corpo das requisições de cerimônia (contra abuso de memória).
const limiteCorpo = 64 << 10

// Roteador devolve o mux do console com todas as rotas e o endurecimento HTTP.
//
// Rotas:
//
//	GET  /healthz                 público
//	POST /api/login/inicio        cert do operador -> opções de asserção
//	POST /api/login/fim           cert + asserção -> cookie de sessão + CSRF
//	GET  /api/sessao              sessão -> operador e token CSRF
//	POST /api/logout              sessão + CSRF -> revoga a sessão
//	POST /api/registro/inicio     cert do operador PENDENTE -> opções de registro
//	POST /api/registro/fim        cert do operador PENDENTE + atestado -> credencial
//
// O registro não tem sessão (o operador ainda não loga): fica atrás só do cert,
// e o Autenticador recusa tudo que não seja operador 'pendente'. A ativação
// ('ativo') é ação do administrador, fora deste pacote.
func (c *Console) Roteador() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"status":"ok"}`))
	})
	mux.Handle("POST /api/login/inicio", c.soCert(c.loginInicio))
	mux.Handle("POST /api/login/fim", c.soCert(c.loginFim))
	mux.Handle("GET /api/sessao", c.protegido(c.sessaoAtual))
	mux.Handle("POST /api/logout", c.protegido(c.logout))
	mux.Handle("POST /api/registro/inicio", c.soCert(c.registroInicio))
	mux.Handle("POST /api/registro/fim", c.soCert(c.registroFim))
	return SecurityHeaders(mux)
}

func (c *Console) loginInicio(w http.ResponseWriter, r *http.Request) {
	op, _, ok := OperadorDoContexto(r.Context())
	if !ok {
		negado(w)
		return
	}
	opcoes, chave, err := c.aut.IniciaLogin(op.ID)
	if err != nil {
		falhaCerimonia(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"cerimonia": chave, "opcoes": opcoes})
}

func (c *Console) loginFim(w http.ResponseWriter, r *http.Request) {
	op, thumb, ok := OperadorDoContexto(r.Context())
	if !ok {
		negado(w)
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, limiteCorpo)
	raw, csrf, err := c.aut.FinalizaLogin(op.ID, r.Header.Get(CabecalhoCerimonia), thumb, r)
	if err != nil {
		falhaCerimonia(w, err)
		return
	}
	// o token vai só no cookie HttpOnly; o CSRF vai no corpo, para o SPA guardar em memória
	http.SetCookie(w, SessionCookie(NomeCookieSessao, raw, c.sessoes.absoluteTTL))
	writeJSON(w, http.StatusOK, map[string]string{"operador": op.ID, "csrf": csrf})
}

func (c *Console) sessaoAtual(w http.ResponseWriter, r *http.Request) {
	op, _, ok := OperadorDoContexto(r.Context())
	s, _, okS := SessaoDoContexto(r.Context())
	if !ok || !okS {
		negado(w)
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{
		"operador": op.ID,
		"nome":     op.Nome,
		"csrf":     s.CSRF(),
	})
}

func (c *Console) logout(w http.ResponseWriter, r *http.Request) {
	_, tok, ok := SessaoDoContexto(r.Context())
	if !ok {
		negado(w)
		return
	}
	c.sessoes.Revoke(tok)
	limpaCookieSessao(w)
	writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
}

func (c *Console) registroInicio(w http.ResponseWriter, r *http.Request) {
	op, _, ok := OperadorDoContexto(r.Context())
	if !ok {
		negado(w)
		return
	}
	opcoes, chave, err := c.aut.IniciaRegistro(op.ID)
	if err != nil {
		falhaCerimonia(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"cerimonia": chave, "opcoes": opcoes})
}

func (c *Console) registroFim(w http.ResponseWriter, r *http.Request) {
	op, _, ok := OperadorDoContexto(r.Context())
	if !ok {
		negado(w)
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, limiteCorpo)
	credID, err := c.aut.FinalizaRegistro(op.ID, r.Header.Get(CabecalhoCerimonia), r)
	if err != nil {
		falhaCerimonia(w, err)
		return
	}
	writeJSON(w, http.StatusCreated, map[string]string{"credencial": credID})
}

// falhaCerimonia traduz erro de cerimônia em resposta. Só os erros que o
// próprio operador precisa conhecer têm mensagem específica; todo o resto
// (inclusive falha de lib WebAuthn e de banco) vira 401 genérico: fail-closed,
// sem detalhe para o cliente.
func falhaCerimonia(w http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, ErrCerimoniasCheias):
		writeJSON(w, http.StatusServiceUnavailable, map[string]string{"erro": "tente novamente em instantes"})
	case errors.Is(err, ErrRegistroFechado):
		writeJSON(w, http.StatusForbidden, map[string]string{"erro": "cadastro de chaves indisponível"})
	case errors.Is(err, ErrChaveSincronizavel):
		writeJSON(w, http.StatusUnprocessableEntity, map[string]string{"erro": "use uma chave física (não sincronizável)"})
	default:
		negado(w)
	}
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}
