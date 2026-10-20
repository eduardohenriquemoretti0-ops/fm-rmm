package console

import (
	"encoding/json"
	"errors"
	"net/http"
	"os"
	"path"
	"strings"
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
//	POST /api/stepup/inicio       sessão + CSRF -> opções de asserção (re-toque)
//	POST /api/stepup/fim          sessão + CSRF + asserção -> marca step-up na sessão
//	GET  /api/agentes             sessão -> agentes visíveis ao operador (RBAC)
//	GET  /api/agentes/{id}        sessão -> detalhe + últimos resultados de leitura (404 sem RBAC)
//	GET  /api/agentes/{id}/vulnerabilidades  sessão -> resumo de CVEs (OSV; lê o banco, 404 sem RBAC)
//	GET  /api/catalogo-software   sessão -> itens publicados (id, nome, gerenciador; sem pkg_id/hash)
//	GET  /api/biblioteca-scripts  sessão -> scripts publicados (id, nome, versao, interprete; NUNCA o corpo)
//	GET  /api/acoes-disponiveis   sessão -> ações de escrita + metadados de formulário (sem comando/receita)
//	POST /api/bmc/status          sessão + CSRF + step-up + grupo bmc -> estado de energia do BMC (credencial por ação, não persistida)
//	POST /api/bmc/power           idem -> ação de energia (On/ForceOff/GracefulShutdown/ForceRestart/GracefulRestart)
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
	mux.Handle("POST /api/stepup/inicio", c.protegido(c.stepUpInicio))
	mux.Handle("POST /api/stepup/fim", c.protegido(c.stepUpFim))
	mux.Handle("GET /api/agentes", c.protegido(c.listarAgentes))
	mux.Handle("GET /api/agentes/{id}", c.protegido(c.detalheAgente))
	mux.Handle("GET /api/agentes/{id}/vulnerabilidades", c.protegido(c.vulnerabilidadesAgente))
	mux.Handle("GET /api/catalogo-software", c.protegido(c.listarCatalogoSoftware))
	mux.Handle("GET /api/biblioteca-scripts", c.protegido(c.listarBibliotecaScripts))
	mux.Handle("GET /api/acoes-disponiveis", c.protegido(c.listarAcoesDisponiveis))
	mux.Handle("POST /api/acoes", c.protegido(c.criarAcao))
	mux.Handle("POST /api/bmc/status", c.protegido(c.bmcStatus))
	mux.Handle("POST /api/bmc/power", c.protegido(c.bmcPower))
	mux.Handle("POST /api/operador/chave-assinatura", c.protegido(c.registrarChaveAssinatura))
	if c.estaticos != "" {
		// "GET /" é o fallback do mux: qualquer rota não registrada cai aqui.
		mux.Handle("GET /", estaticosHandler(c.estaticos))
	}
	return SecurityHeaders(mux)
}

// ServirEstaticos monta o SPA (diretório web/dist) na mesma origem do console.
// Vazio desliga. Deve ser chamado antes de Roteador().
func (c *Console) ServirEstaticos(dir string) { c.estaticos = dir }

// estaticosHandler serve os arquivos do SPA. Nada sob /api/ chega aqui como
// arquivo (404 JSON-neutro); http.Dir recusa traversal. Só arquivos REGULARES
// são servidos: diretório sem index.html vira 404 (sem listagem). Toda 404
// daqui sai com Cache-Control: no-store (o FileServer apaga/reescreve headers
// de cache em erro). Os demais headers vêm do SecurityHeaders.
func estaticosHandler(dir string) http.Handler {
	fs := http.FileServer(noDirFS{http.Dir(dir)})
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/api" || strings.HasPrefix(r.URL.Path, "/api/") {
			w.Header().Set("Cache-Control", "no-store")
			http.NotFound(w, r)
			return
		}
		fs.ServeHTTP(&noStore404{ResponseWriter: w}, r)
	})
}

// noDirFS recusa abrir diretório que não tenha index.html: o FileServer só
// lista diretório quando consegue abri-lo, então um erro aqui vira 404.
type noDirFS struct{ fs http.FileSystem }

func (n noDirFS) Open(name string) (http.File, error) {
	f, err := n.fs.Open(name)
	if err != nil {
		return nil, err
	}
	st, err := f.Stat()
	if err != nil {
		f.Close()
		return nil, err
	}
	if st.IsDir() {
		idx, err := n.fs.Open(path.Join(name, "index.html"))
		if err != nil {
			f.Close()
			return nil, os.ErrNotExist
		}
		idx.Close()
	}
	return f, nil
}

// noStore404 reaplica Cache-Control: no-store quando o FileServer responde erro
// (ele troca os headers de cache nas respostas de erro).
type noStore404 struct {
	http.ResponseWriter
	feito bool
}

func (w *noStore404) WriteHeader(code int) {
	if !w.feito {
		w.feito = true
		if code >= 400 {
			w.Header().Set("Cache-Control", "no-store")
		}
	}
	w.ResponseWriter.WriteHeader(code)
}

func (w *noStore404) Write(b []byte) (int, error) {
	if !w.feito {
		w.WriteHeader(http.StatusOK)
	}
	return w.ResponseWriter.Write(b)
}

func (c *Console) stepUpInicio(w http.ResponseWriter, r *http.Request) {
	_, thumb, ok := OperadorDoContexto(r.Context())
	_, tok, okS := SessaoDoContexto(r.Context())
	if !ok || !okS {
		negado(w)
		return
	}
	opcoes, chave, err := c.aut.IniciaStepUp(tok, thumb)
	if err != nil {
		falhaCerimonia(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"cerimonia": chave, "opcoes": opcoes})
}

func (c *Console) stepUpFim(w http.ResponseWriter, r *http.Request) {
	_, thumb, ok := OperadorDoContexto(r.Context())
	_, tok, okS := SessaoDoContexto(r.Context())
	if !ok || !okS {
		negado(w)
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, limiteCorpo)
	if err := c.aut.FinalizaStepUp(tok, thumb, r.Header.Get(CabecalhoCerimonia), r); err != nil {
		falhaCerimonia(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
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
		"operador":  op.ID,
		"nome":      op.Nome,
		"csrf":      s.CSRF(),
		"tecnico":   op.TechName,
		"relay_url": c.relayBase,
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
