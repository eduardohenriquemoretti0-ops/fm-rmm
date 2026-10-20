package console

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/eduardohenriquemoretti0-ops/fm-rmm/internal/proto"
	"github.com/eduardohenriquemoretti0-ops/fm-rmm/internal/server"
	"github.com/eduardohenriquemoretti0-ops/fm-rmm/internal/sign"
)

const relayTeste = "wss://relay.exemplo:8443/r"

// cenarioAcao: o cenário padrão + relógio do console travado + operador op-a
// com chave de assinatura (a privada vive só no teste, como no navegador).
type cenarioAcao struct {
	*cenario
	priv ed25519.PrivateKey
	pub  ed25519.PublicKey
	tok  string
	csrf string
	ck   *http.Cookie
}

func novoCenarioAcao(t *testing.T) *cenarioAcao {
	t.Helper()
	c := novoCenario(t)
	c.a.c.agora = func() time.Time { return c.a.f.agora }
	c.a.c.ConfigurarRelay(relayTeste)
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	if err := c.a.f.st.SetOperatorSigningPub("op-a", sign.EncodePub(pub)); err != nil {
		t.Fatal(err)
	}
	publicaListaTeste(t, c.a.f.st, sign.EncodePub(pub))
	tok, csrf, err := c.a.f.sm.New("op-a", CertThumbprint(c.certA))
	if err != nil {
		t.Fatal(err)
	}
	return &cenarioAcao{cenario: c, priv: priv, pub: pub, tok: tok, csrf: csrf,
		ck: SessionCookie(NomeCookieSessao, tok, time.Minute)}
}

// publicaListaTeste publica (com uma raiz descartável) a lista de signers com
// as operadoras dadas; versão = atual+1.
func publicaListaTeste(t *testing.T, st *server.Store, pubs ...string) {
	t.Helper()
	raizPub, raiz, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	var ops []sign.SignerEntry
	for _, p := range pubs {
		pk, err := sign.DecodePub(p)
		if err != nil {
			t.Fatal(err)
		}
		ops = append(ops, sign.SignerEntry{KeyID: sign.KeyID(pk), Pub: p, Role: sign.RoleOperator})
	}
	exp, err := st.ExportarLista()
	if err != nil {
		t.Fatal(err)
	}
	raw, sig, _, err := server.ConstruirLista(raiz, exp.VersaoAtual, ops, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := server.PublicarLista(st, raizPub, raw, sig, "teste"); err != nil {
		t.Fatal(err)
	}
}

func (c *cenarioAcao) stepUp(t *testing.T) {
	t.Helper()
	if err := c.a.f.sm.MarcarStepUp(c.tok, CertThumbprint(c.certA), time.Minute); err != nil {
		t.Fatal(err)
	}
}

func (c *cenarioAcao) job(id, agente string) proto.JobPayload {
	now := c.a.f.agora
	return proto.JobPayload{V: proto.Version, JobID: id, AgentID: agente, Action: "info",
		IssuedAt: now, ExpiresAt: now.Add(time.Hour), Issuer: "op-a"}
}

func (c *cenarioAcao) grant(id, agente string) proto.RemoteGrant {
	now := c.a.f.agora
	return proto.RemoteGrant{V: proto.Version, SessionID: id, AgentID: agente, Technician: "tA",
		Mode: proto.ModeView, Engine: proto.EngineScreenshot, RelayURL: relayTeste,
		RelayToken: strings.Repeat("r", 40), IssuedAt: now, ExpiresAt: now.Add(10 * time.Minute), Issuer: "op-a"}
}

// corpoJob assina (como o navegador) e monta o corpo de /api/acoes.
func (c *cenarioAcao) corpoJob(t *testing.T, p proto.JobPayload) acaoReq {
	t.Helper()
	sj, err := sign.SignJob(c.priv, p)
	if err != nil {
		t.Fatal(err)
	}
	return acaoReq{Tipo: TipoAcaoJob, Payload: sj.Payload, Sig: sj.Sig, KeyID: sj.KeyID}
}

func (c *cenarioAcao) corpoGrant(t *testing.T, g proto.RemoteGrant) acaoReq {
	t.Helper()
	sg, err := sign.SignGrant(c.priv, g)
	if err != nil {
		t.Fatal(err)
	}
	return acaoReq{Tipo: TipoAcaoGrant, Payload: sg.Payload, Sig: sg.Sig, KeyID: sg.KeyID}
}

func (c *cenarioAcao) envia(t *testing.T, rota string, corpo any) *httptest.ResponseRecorder {
	t.Helper()
	b, _ := json.Marshal(corpo)
	r := reqTLS(http.MethodPost, rota, bytes.NewReader(b), c.certA)
	r.AddCookie(c.ck)
	r.Header.Set(CabecalhoCSRF, c.csrf)
	rec := httptest.NewRecorder()
	c.a.c.Roteador().ServeHTTP(rec, r)
	return rec
}

func (c *cenarioAcao) fila(t *testing.T, agente string) (jobs int, sess int) {
	t.Helper()
	js, err := c.a.f.st.Jobs(agente, 50)
	if err != nil {
		t.Fatal(err)
	}
	ss, err := c.a.f.st.Sessions(50)
	if err != nil {
		t.Fatal(err)
	}
	for _, s := range ss {
		if s.AgentID == agente {
			sess++
		}
	}
	return len(js), sess
}

func (c *cenarioAcao) exigeCodigo(t *testing.T, rec *httptest.ResponseRecorder, status int, codigo string) {
	t.Helper()
	if rec.Code != status || !strings.Contains(rec.Body.String(), `"`+codigo+`"`) {
		t.Fatalf("quer %d/%s, veio %d: %s", status, codigo, rec.Code, rec.Body.String())
	}
}

func TestAcaoJobValidaEnfileiraSemReassinar(t *testing.T) {
	c := novoCenarioAcao(t)
	c.stepUp(t)
	req := c.corpoJob(t, c.job("job-0001aaaa", c.ag1))
	rec := c.envia(t, "/api/acoes", req)
	if rec.Code != http.StatusAccepted {
		t.Fatalf("ação válida: %d %s", rec.Code, rec.Body.String())
	}
	j, err := c.a.f.st.Job("job-0001aaaa")
	if err != nil {
		t.Fatal(err)
	}
	var sj proto.SignedJob
	if err := json.Unmarshal([]byte(j.Signed), &sj); err != nil {
		t.Fatal(err)
	}
	// o que está na fila é EXATAMENTE o que o operador assinou (não houve re-assinatura)
	if !bytes.Equal(sj.Payload, req.Payload) || !bytes.Equal(sj.Sig, req.Sig) || sj.KeyID != sign.KeyID(c.pub) {
		t.Fatal("objeto enfileirado difere do assinado pelo operador")
	}
	if !ed25519.Verify(c.pub, sj.Payload, sj.Sig) {
		t.Fatal("assinatura enfileirada não confere com a chave do operador")
	}
	// auditoria da ação
	ents, _ := c.a.f.st.AuditEntries()
	achou := false
	for _, e := range ents {
		if e.Event == "console.acao.enfileirada" && e.Actor == "op-a" {
			achou = true
		}
	}
	if !achou {
		t.Fatal("ação não auditada")
	}
}

func TestAcaoGrantValidaEnfileira(t *testing.T) {
	c := novoCenarioAcao(t)
	c.stepUp(t)
	g := c.grant("ses-0001aaaa", c.ag1)
	req := c.corpoGrant(t, g)
	rec := c.envia(t, "/api/acoes", req)
	if rec.Code != http.StatusAccepted {
		t.Fatalf("grant válido: %d %s", rec.Code, rec.Body.String())
	}
	if _, s := c.fila(t, c.ag1); s != 1 {
		t.Fatalf("sessões na fila = %d", s)
	}
	ents, _ := c.a.f.st.AuditEntries()
	for _, e := range ents {
		if bytes.Contains(e.Data, []byte(g.RelayToken)) {
			t.Fatal("relay_token vazou na auditoria")
		}
	}
}

func TestAcaoAssinaturaInvalidaRecusada(t *testing.T) {
	c := novoCenarioAcao(t)
	c.stepUp(t)
	// (a) bit trocado na assinatura
	req := c.corpoJob(t, c.job("job-0002aaaa", c.ag1))
	req.Sig[0] ^= 1
	c.exigeCodigo(t, c.envia(t, "/api/acoes", req), 401, "assinatura_invalida")
	// (b) payload adulterado depois de assinar (outra ação/agente)
	req = c.corpoJob(t, c.job("job-0003aaaa", c.ag1))
	req.Payload = bytes.Replace(req.Payload, []byte(`"info"`), []byte(`"INFO"`), 1)
	c.exigeCodigo(t, c.envia(t, "/api/acoes", req), 401, "assinatura_invalida")
	// (c) assinado por OUTRA chave (não a registrada do operador), key_id honesto
	_, outra, _ := ed25519.GenerateKey(rand.Reader)
	sj, _ := sign.SignJob(outra, c.job("job-0004aaaa", c.ag1))
	c.exigeCodigo(t, c.envia(t, "/api/acoes", acaoReq{TipoAcaoJob, sj.Payload, sj.Sig, sj.KeyID}), 401, "assinatura_invalida")
	// (d) assinado por outra chave com key_id FORJADO para o do operador
	c.exigeCodigo(t, c.envia(t, "/api/acoes", acaoReq{TipoAcaoJob, sj.Payload, sj.Sig, sign.KeyID(c.pub)}), 401, "assinatura_invalida")
	if j, _ := c.fila(t, c.ag1); j != 0 {
		t.Fatalf("job enfileirado apesar de assinatura inválida: %d", j)
	}
}

func TestAcaoNonceRepetidoRecusado(t *testing.T) {
	c := novoCenarioAcao(t)
	c.stepUp(t)
	req := c.corpoJob(t, c.job("job-0005aaaa", c.ag1))
	if rec := c.envia(t, "/api/acoes", req); rec.Code != http.StatusAccepted {
		t.Fatalf("1ª: %d %s", rec.Code, rec.Body.String())
	}
	c.exigeCodigo(t, c.envia(t, "/api/acoes", req), 409, "nonce_repetido") // replay idêntico
	// mesmo nonce com payload diferente (nova assinatura válida): também recusado
	p := c.job("job-0005aaaa", c.ag1)
	p.Params = map[string]string{"x": "y"}
	c.exigeCodigo(t, c.envia(t, "/api/acoes", c.corpoJob(t, p)), 422, "acao_fora_do_catalogo")
	p.Params = nil
	p.ExpiresAt = p.ExpiresAt.Add(time.Minute)
	c.exigeCodigo(t, c.envia(t, "/api/acoes", c.corpoJob(t, p)), 409, "nonce_repetido")
	if j, _ := c.fila(t, c.ag1); j != 1 {
		t.Fatalf("jobs na fila = %d, quer 1", j)
	}
}

func TestAcaoExpiradaRecusada(t *testing.T) {
	c := novoCenarioAcao(t)
	c.stepUp(t)
	p := c.job("job-0006aaaa", c.ag1)
	p.IssuedAt = c.a.f.agora.Add(-3 * time.Hour)
	p.ExpiresAt = c.a.f.agora.Add(-2 * time.Hour)
	c.exigeCodigo(t, c.envia(t, "/api/acoes", c.corpoJob(t, p)), 410, "acao_expirada")
	g := c.grant("ses-0006aaaa", c.ag1)
	g.IssuedAt = c.a.f.agora.Add(-40 * time.Minute)
	g.ExpiresAt = c.a.f.agora.Add(-30 * time.Minute)
	c.exigeCodigo(t, c.envia(t, "/api/acoes", c.corpoGrant(t, g)), 410, "acao_expirada")
}

func TestAcaoForaDoRBACRecusada(t *testing.T) {
	c := novoCenarioAcao(t)
	c.stepUp(t)
	// ag2 está no grupo gB; op-a (técnico tA) só tem gA. Mesma resposta de "não existe".
	foraRBAC := c.envia(t, "/api/acoes", c.corpoJob(t, c.job("job-0007aaaa", c.ag2)))
	c.exigeCodigo(t, foraRBAC, 404, "agente_nao_encontrado")
	inexistente := c.envia(t, "/api/acoes", c.corpoJob(t, c.job("job-0008aaaa", "agente-que-nao-existe")))
	c.exigeCodigo(t, inexistente, 404, "agente_nao_encontrado")
	if foraRBAC.Body.String() != inexistente.Body.String() {
		t.Fatal("RBAC vaza existência do agente")
	}
	c.exigeCodigo(t, c.envia(t, "/api/acoes", c.corpoGrant(t, c.grant("ses-0007aaaa", c.ag2))), 404, "agente_nao_encontrado")
	if j, s := c.fila(t, c.ag2); j != 0 || s != 0 {
		t.Fatalf("enfileirou fora do RBAC: jobs=%d sessões=%d", j, s)
	}
	// recusa não queima o nonce: depois de ganhar o grupo, o mesmo id passa
	if err := c.a.f.st.GrantGroup("tA", "gB"); err != nil {
		t.Fatal(err)
	}
	if rec := c.envia(t, "/api/acoes", c.corpoJob(t, c.job("job-0007aaaa", c.ag2))); rec.Code != 202 {
		t.Fatalf("após conceder grupo: %d %s", rec.Code, rec.Body.String())
	}
}

func TestAcaoSemStepUpRecusada(t *testing.T) {
	c := novoCenarioAcao(t) // sem MarcarStepUp
	rec := c.envia(t, "/api/acoes", c.corpoJob(t, c.job("job-0009aaaa", c.ag1)))
	c.exigeCodigo(t, rec, 403, "step_up_necessario")
	c.exigeCodigo(t, c.envia(t, "/api/acoes", c.corpoGrant(t, c.grant("ses-0009aaaa", c.ag1))), 403, "step_up_necessario")
	if j, s := c.fila(t, c.ag1); j != 0 || s != 0 {
		t.Fatal("enfileirou sem step-up")
	}
	// step-up vencido também recusa
	c.stepUp(t)
	c.a.f.avanca(2 * time.Minute) // janela era 1 min (relógio da sessão = fixture)
	p := c.job("job-0010aaaa", c.ag1)
	p.IssuedAt, p.ExpiresAt = c.a.f.agora, c.a.f.agora.Add(time.Hour)
	c.exigeCodigo(t, c.envia(t, "/api/acoes", c.corpoJob(t, p)), 403, "step_up_necessario")
}

func TestAcaoRegrasDeVinculo(t *testing.T) {
	c := novoCenarioAcao(t)
	c.stepUp(t)
	// issuer de outro operador
	p := c.job("job-0011aaaa", c.ag1)
	p.Issuer = "op-b"
	c.exigeCodigo(t, c.envia(t, "/api/acoes", c.corpoJob(t, p)), 403, "emissor_ou_nonce_invalido")
	// technician de outro técnico no grant
	g := c.grant("ses-0011aaaa", c.ag1)
	g.Technician = "tB"
	c.exigeCodigo(t, c.envia(t, "/api/acoes", c.corpoGrant(t, g)), 403, "emissor_ou_nonce_invalido")
	// relay que não é o configurado
	g = c.grant("ses-0012aaaa", c.ag1)
	g.RelayURL = "wss://atacante.exemplo/r"
	c.exigeCodigo(t, c.envia(t, "/api/acoes", c.corpoGrant(t, g)), 422, "relay_invalido")
	// ação fora do catálogo
	p = c.job("job-0013aaaa", c.ag1)
	p.Action = "rm_rf"
	c.exigeCodigo(t, c.envia(t, "/api/acoes", c.corpoJob(t, p)), 422, "acao_fora_do_catalogo")
	// payload fora da forma canônica (espaço extra), mesmo com assinatura válida sobre ele
	raw, _ := json.Marshal(c.job("job-0014aaaa", c.ag1))
	raw = bytes.Replace(raw, []byte(`{"v"`), []byte(`{ "v"`), 1)
	sig := ed25519.Sign(c.priv, raw)
	c.exigeCodigo(t, c.envia(t, "/api/acoes", acaoReq{TipoAcaoJob, raw, sig, sign.KeyID(c.pub)}), 400, "payload_nao_canonico")
	// campo desconhecido no corpo
	rec := c.envia(t, "/api/acoes", map[string]any{"tipo": "job", "payload": "", "sig": "", "key_id": "", "extra": 1})
	c.exigeCodigo(t, rec, 400, "requisicao_invalida")
}

func TestAcaoOperadorSemChaveRecusado(t *testing.T) {
	c := novoCenarioAcao(t)
	c.stepUp(t)
	// op-b não tem signing_pub
	tok, csrf, _ := c.a.f.sm.New("op-b", CertThumbprint(c.certB))
	_ = c.a.f.sm.MarcarStepUp(tok, CertThumbprint(c.certB), time.Minute)
	b, _ := json.Marshal(c.corpoJob(t, c.job("job-0015aaaa", c.ag2)))
	r := reqTLS(http.MethodPost, "/api/acoes", bytes.NewReader(b), c.certB)
	r.AddCookie(SessionCookie(NomeCookieSessao, tok, time.Minute))
	r.Header.Set(CabecalhoCSRF, csrf)
	rec := httptest.NewRecorder()
	c.a.c.Roteador().ServeHTTP(rec, r)
	c.exigeCodigo(t, rec, 403, "operador_sem_chave_de_assinatura")
}

func TestAcaoExigeCertSessaoCSRF(t *testing.T) {
	c := novoCenarioAcao(t)
	c.stepUp(t)
	b, _ := json.Marshal(c.corpoJob(t, c.job("job-0016aaaa", c.ag1)))
	casos := map[string]func(*http.Request){
		"sem cookie": func(r *http.Request) {},
		"sem csrf":   func(r *http.Request) { r.AddCookie(c.ck) },
	}
	for nome, prep := range casos {
		r := reqTLS(http.MethodPost, "/api/acoes", bytes.NewReader(b), c.certA)
		prep(r)
		rec := httptest.NewRecorder()
		c.a.c.Roteador().ServeHTTP(rec, r)
		if rec.Code != 401 && rec.Code != 403 {
			t.Fatalf("%s: %d", nome, rec.Code)
		}
	}
	r := reqTLS(http.MethodPost, "/api/acoes", bytes.NewReader(b), nil) // sem cert
	rec := httptest.NewRecorder()
	c.a.c.Roteador().ServeHTTP(rec, r)
	if rec.Code != 401 {
		t.Fatalf("sem cert: %d", rec.Code)
	}
	if j, _ := c.fila(t, c.ag1); j != 0 {
		t.Fatal("enfileirou sem autenticação completa")
	}
}

// ---- registro da chave de assinatura

func provaDe(priv ed25519.PrivateKey, opID string) (string, []byte) {
	pub := sign.EncodePub(priv.Public().(ed25519.PublicKey))
	return pub, ed25519.Sign(priv, MensagemProvaChave(opID, pub))
}

func TestRegistrarChaveAssinatura(t *testing.T) {
	c := novoCenario(t)
	tok, csrf, _ := c.a.f.sm.New("op-b", CertThumbprint(c.certB))
	ck := SessionCookie(NomeCookieSessao, tok, time.Minute)
	envia := func(corpo any) *httptest.ResponseRecorder {
		b, _ := json.Marshal(corpo)
		r := reqTLS(http.MethodPost, "/api/operador/chave-assinatura", bytes.NewReader(b), c.certB)
		r.AddCookie(ck)
		r.Header.Set(CabecalhoCSRF, csrf)
		rec := httptest.NewRecorder()
		c.a.c.Roteador().ServeHTTP(rec, r)
		return rec
	}
	_, priv, _ := ed25519.GenerateKey(rand.Reader)
	pub, prova := provaDe(priv, "op-b")
	corpo := chaveReq{SigningPub: pub, Prova: prova}

	if rec := envia(corpo); rec.Code != 403 { // sem step-up
		t.Fatalf("sem step-up: %d %s", rec.Code, rec.Body.String())
	}
	_ = c.a.f.sm.MarcarStepUp(tok, CertThumbprint(c.certB), time.Minute)
	// prova de posse feita para OUTRO operador (ou por outra chave): recusada
	_, provaErrada := provaDe(priv, "op-a")
	if rec := envia(chaveReq{SigningPub: pub, Prova: provaErrada}); rec.Code != 401 {
		t.Fatalf("prova errada: %d", rec.Code)
	}
	_, outra, _ := ed25519.GenerateKey(rand.Reader)
	_, provaOutra := provaDe(outra, "op-b")
	if rec := envia(chaveReq{SigningPub: pub, Prova: provaOutra}); rec.Code != 401 {
		t.Fatalf("prova de outra chave: %d", rec.Code)
	}
	if rec := envia(corpo); rec.Code != 201 {
		t.Fatalf("registro válido: %d %s", rec.Code, rec.Body.String())
	}
	op, _ := c.a.f.st.GetOperator("op-b")
	if op.SigningPub != pub {
		t.Fatalf("pub gravada = %q", op.SigningPub)
	}
	// segunda vez (troca por sessão roubada): recusada, a chave original fica
	_, priv2, _ := ed25519.GenerateKey(rand.Reader)
	pub2, prova2 := provaDe(priv2, "op-b")
	if rec := envia(chaveReq{SigningPub: pub2, Prova: prova2}); rec.Code != 409 {
		t.Fatalf("troca: %d", rec.Code)
	}
	op, _ = c.a.f.st.GetOperator("op-b")
	if op.SigningPub != pub {
		t.Fatal("chave foi trocada por registro de sessão")
	}
	// chave de outro operador (mesma pública) não pode ser registrada em op-a
	tokA, csrfA, _ := c.a.f.sm.New("op-a", CertThumbprint(c.certA))
	_ = c.a.f.sm.MarcarStepUp(tokA, CertThumbprint(c.certA), time.Minute)
	_, provaA := provaDe(priv, "op-a")
	b, _ := json.Marshal(chaveReq{SigningPub: pub, Prova: provaA})
	r := reqTLS(http.MethodPost, "/api/operador/chave-assinatura", bytes.NewReader(b), c.certA)
	r.AddCookie(SessionCookie(NomeCookieSessao, tokA, time.Minute))
	r.Header.Set(CabecalhoCSRF, csrfA)
	rec := httptest.NewRecorder()
	c.a.c.Roteador().ServeHTTP(rec, r)
	if rec.Code != 409 {
		t.Fatalf("pública duplicada em outro operador: %d", rec.Code)
	}
}

// Vetor de teste para o T7 (WebCrypto): os bytes canônicos, a assinatura e a
// prova de posse abaixo estão em docs/console-assinatura-acao.md. Se este teste
// quebrar, a struct mudou e o formato documentado (e o SPA) precisa mudar junto.
func TestVetorCanonicoDocumentado(t *testing.T) {
	seed := make([]byte, 32)
	for i := range seed {
		seed[i] = byte(i)
	}
	priv := ed25519.NewKeyFromSeed(seed)
	pub := priv.Public().(ed25519.PublicKey)
	if got := sign.EncodePub(pub); got != "A6EHv/POEL4dcN0Y50vAmWfk1jCbpQ1fHdyGZBJVMbg=" || sign.KeyID(pub) != "56475aa75463474c" {
		t.Fatalf("pub/key_id do vetor: %s %s", got, sign.KeyID(pub))
	}
	t0 := time.Date(2026, 10, 19, 12, 0, 0, 0, time.UTC)
	sj, err := sign.SignJob(priv, proto.JobPayload{V: 1, JobID: "job-0123456789abcdef", AgentID: "agt-0001", Action: "info",
		Params: map[string]string{"b": "2", "a": "1"}, IssuedAt: t0, ExpiresAt: t0.Add(time.Hour), Issuer: "op-joao"})
	if err != nil {
		t.Fatal(err)
	}
	const job = `{"v":1,"job_id":"job-0123456789abcdef","agent_id":"agt-0001","action":"info","params":{"a":"1","b":"2"},"issued_at":"2026-10-19T12:00:00Z","expires_at":"2026-10-19T13:00:00Z","issuer":"op-joao"}`
	if string(sj.Payload) != job {
		t.Fatalf("bytes do job:\n%s", sj.Payload)
	}
	if b64 := base64.StdEncoding.EncodeToString(sj.Sig); b64 != "7uImsymUQOmFO5OTjcMLRnISRRBfhQxabqAIbPb+XY6nk4p8Ktju1m6gaPfSBjnJpTZL3k4ekpE5EfFIUNxNBA==" {
		t.Fatalf("assinatura do job: %s", b64)
	}
	sg, err := sign.SignGrant(priv, proto.RemoteGrant{V: 1, SessionID: "ses-0123456789abcdef", AgentID: "agt-0001", Technician: "joao",
		Mode: "view", Engine: "screenshot", RelayURL: "wss://relay.exemplo:8443/r", RelayToken: strings.Repeat("A", 40),
		IssuedAt: t0, ExpiresAt: t0.Add(10 * time.Minute), Issuer: "op-joao"})
	if err != nil {
		t.Fatal(err)
	}
	const grant = `{"v":1,"session_id":"ses-0123456789abcdef","agent_id":"agt-0001","technician":"joao","mode":"view","engine":"screenshot","relay_url":"wss://relay.exemplo:8443/r","relay_token":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA","issued_at":"2026-10-19T12:00:00Z","expires_at":"2026-10-19T12:10:00Z","issuer":"op-joao"}`
	if string(sg.Payload) != grant {
		t.Fatalf("bytes do grant:\n%s", sg.Payload)
	}
	if b64 := base64.StdEncoding.EncodeToString(sg.Sig); b64 != "PHu0ceiydCnUJyVTZ85iQqjsec7ZDoX66hne75JTpjBB5Gv1sPfV43NQocIE55L6jvcWD46248VMdWgyYQfhBA==" {
		t.Fatalf("assinatura do grant: %s", b64)
	}
	prova := ed25519.Sign(priv, MensagemProvaChave("op-joao", sign.EncodePub(pub)))
	if b64 := base64.StdEncoding.EncodeToString(prova); b64 != "ZQ1045ka3+2cDB2qhfuSua9cLAxBh+nUXJr81W1lcy+/ZFdNcUQB6e28qiQxClFIpAbsIBsgTsZUr2Oqe97vBA==" {
		t.Fatalf("prova de posse: %s", b64)
	}
	// o servidor aceita exatamente essa forma como canônica
	var p proto.JobPayload
	if !decodificaCanonico([]byte(job), &p) {
		t.Fatal("o job documentado não passa na checagem de forma canônica")
	}
}

// N2: operador ativo no banco, mas fora da lista PUBLICADA, é recusado.
func TestAcaoOperadorForaDaListaPublicadaRecusado(t *testing.T) {
	c := novoCenarioAcao(t)
	c.stepUp(t)
	// nova versão da lista SEM a chave do op-a (admin retirou)
	publicaListaTeste(t, c.a.f.st)
	rec := c.envia(t, "/api/acoes", c.corpoJob(t, c.job("job-n2aaaa01", c.ag1)))
	c.exigeCodigo(t, rec, http.StatusForbidden, "operador_nao_publicado")
	rec = c.envia(t, "/api/acoes", c.corpoGrant(t, c.grant("ses-n2aaaa01", c.ag1)))
	c.exigeCodigo(t, rec, http.StatusForbidden, "operador_nao_publicado")
	if j, s := c.fila(t, c.ag1); j != 0 || s != 0 {
		t.Fatalf("nada deveria ser enfileirado: jobs=%d sessões=%d", j, s)
	}
	// a recusa é auditada
	ents, err := c.a.f.st.AuditEntries()
	if err != nil {
		t.Fatal(err)
	}
	achou := false
	for _, e := range ents {
		if e.Event == "console.acao.recusada" && strings.Contains(string(e.Data), "operador_nao_publicado") {
			achou = true
		}
	}
	if !achou {
		t.Error("recusa operador_nao_publicado não auditada")
	}
}

// Sem nenhuma lista publicada também recusa (fail-closed).
func TestAcaoSemListaPublicadaRecusado(t *testing.T) {
	c := novoCenario(t)
	c.a.c.agora = func() time.Time { return c.a.f.agora }
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	if err := c.a.f.st.SetOperatorSigningPub("op-a", sign.EncodePub(pub)); err != nil {
		t.Fatal(err)
	}
	tok, csrf, _ := c.a.f.sm.New("op-a", CertThumbprint(c.certA))
	_ = c.a.f.sm.MarcarStepUp(tok, CertThumbprint(c.certA), time.Minute)
	ca := &cenarioAcao{cenario: c, priv: priv, pub: pub, tok: tok, csrf: csrf,
		ck: SessionCookie(NomeCookieSessao, tok, time.Minute)}
	rec := ca.envia(t, "/api/acoes", ca.corpoJob(t, ca.job("job-n2bbbb01", c.ag1)))
	ca.exigeCodigo(t, rec, http.StatusForbidden, "operador_nao_publicado")
}

// wipe pelo console: step-up + confirmação WIPE-<agente>; nada é enfileirado
// fora do caminho completo e a intenção é auditada (sem segredo).
func (c *cenarioAcao) wipe(id, agente string, params map[string]string) proto.JobPayload {
	p := c.job(id, agente)
	p.Action, p.Params = "wipe_remoto", params
	return p
}

func TestWipeNoConsoleGate(t *testing.T) {
	c := novoCenarioAcao(t)
	ok := map[string]string{"motivo": "roubo", "confirmacao": "WIPE-" + c.ag1}

	// sem step-up
	c.exigeCodigo(t, c.envia(t, "/api/acoes", c.corpoJob(t, c.wipe("job-w0001aaa", c.ag1, ok))), 403, "step_up_necessario")
	c.stepUp(t)
	// sem confirmação / errada (de outro agente) / sem motivo: recusados
	c.exigeCodigo(t, c.envia(t, "/api/acoes", c.corpoJob(t, c.wipe("job-w0002aaa", c.ag1, map[string]string{"motivo": "roubo"}))), 422, "acao_fora_do_catalogo")
	c.exigeCodigo(t, c.envia(t, "/api/acoes", c.corpoJob(t, c.wipe("job-w0003aaa", c.ag1, map[string]string{"motivo": "roubo", "confirmacao": "WIPE-ag-ffffffffffffffff"}))), 422, "confirmacao_destrutiva_invalida")
	c.exigeCodigo(t, c.envia(t, "/api/acoes", c.corpoJob(t, c.wipe("job-w0004aaa", c.ag1, map[string]string{"confirmacao": "WIPE-" + c.ag1}))), 422, "acao_fora_do_catalogo")
	if j, _ := c.fila(t, c.ag1); j != 0 {
		t.Fatalf("enfileirou wipe fora do caminho completo: %d", j)
	}
	ents, _ := c.a.f.st.AuditEntries()
	for _, e := range ents {
		if e.Event == "console.acao.destrutiva" {
			t.Fatal("auditou destrutiva de pedido recusado")
		}
	}

	// caminho completo
	rec := c.envia(t, "/api/acoes", c.corpoJob(t, c.wipe("job-w0005aaa", c.ag1, ok)))
	if rec.Code != http.StatusAccepted {
		t.Fatalf("wipe completo: %d %s", rec.Code, rec.Body.String())
	}
	if j, _ := c.fila(t, c.ag1); j != 1 {
		t.Fatalf("fila = %d", j)
	}
	ents, _ = c.a.f.st.AuditEntries()
	achou := false
	for _, e := range ents {
		if e.Event == "console.acao.destrutiva" && e.Actor == "op-a" {
			achou = true
			s := string(e.Data)
			if !strings.Contains(s, c.ag1) || !strings.Contains(s, "roubo") || strings.Contains(s, "confirmacao") {
				t.Fatalf("auditoria destrutiva incompleta ou com campo indevido: %s", s)
			}
		}
	}
	if !achou {
		t.Fatal("console.acao.destrutiva não auditada")
	}
}

func TestLockNoConsoleExigeStepUpEEnfileira(t *testing.T) {
	c := novoCenarioAcao(t)
	p := c.job("job-l0001aaa", c.ag1)
	p.Action = "lock_remoto"
	c.exigeCodigo(t, c.envia(t, "/api/acoes", c.corpoJob(t, p)), 403, "step_up_necessario")
	c.stepUp(t)
	if rec := c.envia(t, "/api/acoes", c.corpoJob(t, p)); rec.Code != http.StatusAccepted {
		t.Fatalf("lock: %d %s", rec.Code, rec.Body.String())
	}
}
