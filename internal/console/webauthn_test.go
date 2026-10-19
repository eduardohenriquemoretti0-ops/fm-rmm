package console

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/go-webauthn/webauthn/webauthn"

	"github.com/eduardohenriquemoretti0-ops/fm-rmm/internal/server"
)

const (
	rpIDTeste   = "console.fmrmm.test"
	originTeste = "https://console.fmrmm.test"
)

// thumbTeste e thumbOutro são SHA-256 em hex (64 chars), no formato do CertThumbprint.
var (
	thumbTeste = strings.Repeat("ab", 32)
	thumbOutro = strings.Repeat("cd", 32)
)

// autSoft é um autenticador de software para teste: ES256, attestation "none",
// contador controlado pelo teste. Gera registro e asserção que a lib valida de
// verdade (não é um mock da validação).
type autSoft struct {
	chave  *ecdsa.PrivateKey
	credID []byte
}

func novoAutSoft(t *testing.T) *autSoft {
	t.Helper()
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	id := make([]byte, 16)
	if _, err := rand.Read(id); err != nil {
		t.Fatal(err)
	}
	return &autSoft{chave: k, credID: id}
}

func cborCabecalho(major byte, n int) []byte {
	switch {
	case n < 24:
		return []byte{major | byte(n)}
	case n < 256:
		return []byte{major | 24, byte(n)}
	default:
		return []byte{major | 25, byte(n >> 8), byte(n)}
	}
}

func cborTexto(s string) []byte  { return append(cborCabecalho(0x60, len(s)), s...) }
func cborBytes(b []byte) []byte  { return append(cborCabecalho(0x40, len(b)), b...) }
func b64(b []byte) string        { return base64.RawURLEncoding.EncodeToString(b) }
func (a *autSoft) idB64() string { return b64(a.credID) }

// coseChave: mapa COSE EC2/P-256/ES256 (kty=2, alg=-7, crv=1, x, y).
func (a *autSoft) coseChave() []byte {
	x, y := make([]byte, 32), make([]byte, 32)
	a.chave.PublicKey.X.FillBytes(x)
	a.chave.PublicKey.Y.FillBytes(y)
	out := []byte{0xA5, 0x01, 0x02, 0x03, 0x26, 0x20, 0x01, 0x21}
	out = append(out, cborBytes(x)...)
	out = append(out, 0x22)
	return append(out, cborBytes(y)...)
}

func (a *autSoft) authData(rpID string, flags byte, contador uint32, comCredencial bool) []byte {
	h := sha256.Sum256([]byte(rpID))
	ad := append([]byte{}, h[:]...)
	ad = append(ad, flags)
	ad = binary.BigEndian.AppendUint32(ad, contador)
	if comCredencial {
		ad = append(ad, make([]byte, 16)...) // AAGUID zero
		ad = binary.BigEndian.AppendUint16(ad, uint16(len(a.credID)))
		ad = append(ad, a.credID...)
		ad = append(ad, a.coseChave()...)
	}
	return ad
}

func clientData(tipo, desafio, origem string) []byte {
	cd, _ := json.Marshal(map[string]any{
		"type": tipo, "challenge": desafio, "origin": origem, "crossOrigin": false,
	})
	return cd
}

// corpoRegistro monta a resposta de criação (attestation "none").
func (a *autSoft) corpoRegistro(desafio, origem, rpID string, flags byte) []byte {
	ad := a.authData(rpID, flags, 0, true)
	att := []byte{0xA3}
	att = append(att, cborTexto("fmt")...)
	att = append(att, cborTexto("none")...)
	att = append(att, cborTexto("attStmt")...)
	att = append(att, 0xA0)
	att = append(att, cborTexto("authData")...)
	att = append(att, cborBytes(ad)...)
	corpo, _ := json.Marshal(map[string]any{
		"id": a.idB64(), "rawId": a.idB64(), "type": "public-key",
		"response": map[string]string{
			"clientDataJSON":    b64(clientData("webauthn.create", desafio, origem)),
			"attestationObject": b64(att),
		},
	})
	return corpo
}

// corpoAsercao monta a asserção assinada (UP|UV) com o contador dado.
func (a *autSoft) corpoAsercao(desafio, origem, rpID string, contador uint32, userHandle []byte) []byte {
	cd := clientData("webauthn.get", desafio, origem)
	ad := a.authData(rpID, 0x05, contador, false)
	h := sha256.Sum256(cd)
	digest := sha256.Sum256(append(append([]byte{}, ad...), h[:]...))
	sig, err := ecdsa.SignASN1(rand.Reader, a.chave, digest[:])
	if err != nil {
		panic(err)
	}
	resp := map[string]any{
		"clientDataJSON":    b64(cd),
		"authenticatorData": b64(ad),
		"signature":         b64(sig),
	}
	if userHandle != nil {
		resp["userHandle"] = b64(userHandle)
	}
	corpo, _ := json.Marshal(map[string]any{
		"id": a.idB64(), "rawId": a.idB64(), "type": "public-key", "response": resp,
	})
	return corpo
}

func req(corpo []byte) *http.Request {
	return httptest.NewRequest(http.MethodPost, "/", bytes.NewReader(corpo))
}

// fixture: store real (sqlite temporário), sessão e autenticador, com relógio controlado.
type fixture struct {
	a     *Autenticador
	st    *server.Store
	sm    *SessionManager
	agora time.Time
}

func novoFixture(t *testing.T) *fixture {
	t.Helper()
	st, err := server.OpenStore(filepath.Join(t.TempDir(), "t.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })
	if err := st.AddTech("t1"); err != nil {
		t.Fatal(err)
	}
	f := &fixture{st: st, sm: NewSessionManager(15*time.Minute, 10*time.Minute), agora: time.Unix(1_800_000_000, 0)}
	a, err := NovoAutenticador(ConfigWebAuthn{RPID: rpIDTeste, RPOrigins: []string{originTeste}}, st, f.sm)
	if err != nil {
		t.Fatal(err)
	}
	relogio := func() time.Time { return f.agora }
	f.sm.now = relogio
	a.cer.now = relogio
	f.a = a
	return f
}

func (f *fixture) avanca(d time.Duration) { f.agora = f.agora.Add(d) }

func (f *fixture) criaOperador(t *testing.T, id, status, thumb string) {
	t.Helper()
	if err := f.st.CreateOperator(server.Operator{ID: id, Nome: id, TechName: "t1", Status: status, CertThumbprint: thumb}); err != nil {
		t.Fatal(err)
	}
}

// registra faz o cadastro completo de uma chave (begin + finish) e devolve o id.
func (f *fixture) registra(t *testing.T, opID string, k *autSoft, flags byte) (string, error) {
	t.Helper()
	creation, key, err := f.a.IniciaRegistro(opID)
	if err != nil {
		t.Fatalf("IniciaRegistro: %v", err)
	}
	corpo := k.corpoRegistro(creation.Response.Challenge.String(), originTeste, rpIDTeste, flags)
	return f.a.FinalizaRegistro(opID, key, req(corpo))
}

// loga faz o login completo (begin + finish) com o thumbprint informado.
func (f *fixture) loga(t *testing.T, opID string, k *autSoft, contador uint32, thumb string) (string, string, error) {
	t.Helper()
	assercao, key, err := f.a.IniciaLogin(opID)
	if err != nil {
		t.Fatalf("IniciaLogin: %v", err)
	}
	corpo := k.corpoAsercao(assercao.Response.Challenge.String(), originTeste, rpIDTeste, contador, []byte(opID))
	return f.a.FinalizaLogin(opID, key, thumb, req(corpo))
}

// operadorAtivo cria o operador, registra a chave e o ativa com o thumbprint do cert.
func (f *fixture) operadorAtivo(t *testing.T, opID string, k *autSoft) {
	t.Helper()
	f.criaOperador(t, opID, "pendente", "")
	if _, err := f.registra(t, opID, k, 0x45); err != nil {
		t.Fatalf("registro: %v", err)
	}
	if err := f.st.SetOperatorThumbprint(opID, thumbTeste); err != nil {
		t.Fatal(err)
	}
	if err := f.st.SetOperatorStatus(opID, "ativo"); err != nil {
		t.Fatal(err)
	}
}

func (f *fixture) contadorGuardado(t *testing.T, opID string) uint32 {
	t.Helper()
	cs, err := f.st.Credentials(opID)
	if err != nil || len(cs) == 0 {
		t.Fatalf("credenciais: %v, %v", cs, err)
	}
	return cs[0].SignCount
}

func TestConfigWebAuthnRecusaOrigemForaDoRPID(t *testing.T) {
	st, err := server.OpenStore(filepath.Join(t.TempDir(), "t.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	sm := NewSessionManager(time.Minute, time.Minute)
	casos := map[string]ConfigWebAuthn{
		"rpid vazio":          {RPID: "", RPOrigins: []string{originTeste}},
		"rpid com esquema":    {RPID: "https://console.fmrmm.test", RPOrigins: []string{originTeste}},
		"sem origens":         {RPID: rpIDTeste},
		"origem http":         {RPID: rpIDTeste, RPOrigins: []string{"http://console.fmrmm.test"}},
		"origem de outro dom": {RPID: rpIDTeste, RPOrigins: []string{"https://evil.test"}},
	}
	for nome, cfg := range casos {
		if _, err := NovoAutenticador(cfg, st, sm); err == nil {
			t.Errorf("%s: aceitou configuração inválida", nome)
		}
	}
	if _, err := NovoAutenticador(ConfigWebAuthn{RPID: rpIDTeste, RPOrigins: []string{originTeste}}, st, sm); err != nil {
		t.Errorf("configuração válida recusada: %v", err)
	}
}

func TestAdaptadorOperadorComoWebAuthnUser(t *testing.T) {
	op := server.Operator{ID: "op-1", Nome: "ana"}
	u := operadorWA{op: op}
	if string(u.WebAuthnID()) != "op-1" {
		t.Errorf("user handle = %q", u.WebAuthnID())
	}
	if u.WebAuthnDisplayName() != "ana" {
		t.Errorf("display name sem DisplayName deve cair no Nome, veio %q", u.WebAuthnDisplayName())
	}
	f := novoFixture(t)
	f.criaOperador(t, strings.Repeat("x", 65), "pendente", "")
	if _, _, err := f.a.IniciaRegistro(strings.Repeat("x", 65)); err == nil {
		t.Error("user handle > 64 bytes foi aceito")
	}
}

func TestRegistroPersisteCredencial(t *testing.T) {
	f := novoFixture(t)
	f.criaOperador(t, "op-1", "pendente", "")
	k := novoAutSoft(t)
	credID, err := f.registra(t, "op-1", k, 0x45) // UP|UV|AT, BE=0 (chave física)
	if err != nil {
		t.Fatalf("FinalizaRegistro: %v", err)
	}
	if credID != k.idB64() {
		t.Errorf("credID = %q, quer %q", credID, k.idB64())
	}
	cs, err := f.st.Credentials("op-1")
	if err != nil || len(cs) != 1 {
		t.Fatalf("credenciais persistidas: %v, %v", cs, err)
	}
	if cs[0].CredentialID != credID || len(cs[0].PublicKey) == 0 || cs[0].SignCount != 0 {
		t.Errorf("credencial persistida errada: %+v", cs[0])
	}
}

func TestRegistroRecusaChaveSincronizavel(t *testing.T) {
	f := novoFixture(t)
	f.criaOperador(t, "op-1", "pendente", "")
	_, err := f.registra(t, "op-1", novoAutSoft(t), 0x4D) // BE=1 (passkey sincronizada)
	if !errors.Is(err, ErrChaveSincronizavel) {
		t.Fatalf("err = %v, quer ErrChaveSincronizavel", err)
	}
	if cs, _ := f.st.Credentials("op-1"); len(cs) != 0 {
		t.Errorf("chave sincronizável foi persistida: %d", len(cs))
	}
}

func TestRegistroSoComOperadorPendente(t *testing.T) {
	f := novoFixture(t)
	f.operadorAtivo(t, "op-1", novoAutSoft(t))
	if _, _, err := f.a.IniciaRegistro("op-1"); !errors.Is(err, ErrRegistroFechado) {
		t.Errorf("registro com operador ativo: err = %v, quer ErrRegistroFechado", err)
	}
}

func TestLoginAceitaAssinaturaEEmiteSessaoLigadaAoCert(t *testing.T) {
	f := novoFixture(t)
	k := novoAutSoft(t)
	f.operadorAtivo(t, "op-1", k)

	tok, csrf, err := f.loga(t, "op-1", k, 1, thumbTeste)
	if err != nil {
		t.Fatalf("FinalizaLogin: %v", err)
	}
	if tok == "" || csrf == "" {
		t.Fatal("sessão sem token ou CSRF")
	}
	s, err := f.sm.Validate(tok, thumbTeste)
	if err != nil || s.OperatorID != "op-1" {
		t.Fatalf("sessão não validou com o cert: %v", err)
	}
	if _, err := f.sm.Validate(tok, thumbOutro); !errors.Is(err, ErrClienteDiferente) {
		t.Errorf("token com outro cert: err = %v, quer ErrClienteDiferente", err)
	}
	if got := f.contadorGuardado(t, "op-1"); got != 1 {
		t.Errorf("contador após login = %d, quer 1", got)
	}
}

func TestLoginRecusaThumbprintDeOutroOperador(t *testing.T) {
	f := novoFixture(t)
	k := novoAutSoft(t)
	f.operadorAtivo(t, "op-1", k)
	_, _, err := f.loga(t, "op-1", k, 1, thumbOutro) // assinatura certa, cert de outro
	if !errors.Is(err, ErrAutenticacaoRecusada) {
		t.Fatalf("err = %v, quer ErrAutenticacaoRecusada", err)
	}
	if got := f.contadorGuardado(t, "op-1"); got != 0 {
		t.Errorf("contador mexeu numa recusa: %d", got)
	}
}

func TestLoginRecusaOperadorPendente(t *testing.T) {
	f := novoFixture(t)
	k := novoAutSoft(t)
	f.criaOperador(t, "op-1", "pendente", "")
	if _, err := f.registra(t, "op-1", k, 0x45); err != nil {
		t.Fatal(err)
	}
	if _, _, err := f.a.IniciaLogin("op-1"); !errors.Is(err, ErrAutenticacaoRecusada) {
		t.Errorf("login de operador pendente: err = %v, quer ErrAutenticacaoRecusada", err)
	}
}

func TestAntiCloneRecusaContadorQueRegride(t *testing.T) {
	f := novoFixture(t)
	k := novoAutSoft(t)
	f.operadorAtivo(t, "op-1", k)
	if _, _, err := f.loga(t, "op-1", k, 5, thumbTeste); err != nil {
		t.Fatalf("login inicial: %v", err)
	}
	for _, c := range []uint32{5, 3} { // igual e regredido, ambos com assinatura VÁLIDA
		if _, _, err := f.loga(t, "op-1", k, c, thumbTeste); !errors.Is(err, ErrCloneSuspeito) {
			t.Fatalf("contador %d: err = %v, quer ErrCloneSuspeito", c, err)
		}
	}
	if got := f.contadorGuardado(t, "op-1"); got != 5 {
		t.Errorf("contador após recusas = %d, quer 5 (não pode regredir)", got)
	}
	entradas, err := f.st.AuditEntries()
	if err != nil {
		t.Fatal(err)
	}
	clones := 0
	for _, e := range entradas {
		if e.Event == "operador.clone_suspeito" {
			clones++
		}
	}
	if clones != 2 {
		t.Errorf("eventos clone_suspeito na auditoria = %d, quer 2", clones)
	}
	if _, _, err := f.loga(t, "op-1", k, 6, thumbTeste); err != nil {
		t.Errorf("contador seguinte legítimo recusado: %v", err)
	}
}

func TestAntiCloneContadorZeroNaoBloqueia(t *testing.T) {
	// Autenticador sem contador (sempre 0): a regra só vale com contador guardado > 0.
	f := novoFixture(t)
	k := novoAutSoft(t)
	f.operadorAtivo(t, "op-1", k)
	for i := 0; i < 2; i++ {
		if _, _, err := f.loga(t, "op-1", k, 0, thumbTeste); err != nil {
			t.Fatalf("login %d com contador zero: %v", i, err)
		}
	}
}

func TestUserHandleDeOutroOperadorRecusado(t *testing.T) {
	f := novoFixture(t)
	k := novoAutSoft(t)
	f.operadorAtivo(t, "op-1", k)
	assercao, key, err := f.a.IniciaLogin("op-1")
	if err != nil {
		t.Fatal(err)
	}
	corpo := k.corpoAsercao(assercao.Response.Challenge.String(), originTeste, rpIDTeste, 1, []byte("op-2"))
	if _, _, err := f.a.FinalizaLogin("op-1", key, thumbTeste, req(corpo)); err == nil {
		t.Error("userHandle de outro operador foi aceito")
	}
}

func TestChallengeExpira(t *testing.T) {
	f := novoFixture(t)
	k := novoAutSoft(t)
	f.operadorAtivo(t, "op-1", k)
	assercao, key, err := f.a.IniciaLogin("op-1")
	if err != nil {
		t.Fatal(err)
	}
	f.avanca(TTLCerimonia + time.Second)
	corpo := k.corpoAsercao(assercao.Response.Challenge.String(), originTeste, rpIDTeste, 1, []byte("op-1"))
	_, _, err = f.a.FinalizaLogin("op-1", key, thumbTeste, req(corpo))
	if !errors.Is(err, ErrCerimoniaExpirada) {
		t.Fatalf("challenge vencido: err = %v, quer ErrCerimoniaExpirada", err)
	}
}

func TestCerimoniaUsoUnicoELigadaAoOperador(t *testing.T) {
	now := time.Unix(1_800_000_000, 0)
	c := NovoCerimoniaStore(TTLCerimonia, 10, func() time.Time { return now })
	key, err := c.Nova("login", "op-1", webauthnSessao("desafio"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := c.Consome(key, "login", "op-2"); !errors.Is(err, ErrCerimonia) {
		t.Errorf("chave de op-1 usada por op-2: err = %v", err)
	}
	if _, err := c.Consome(key, "login", "op-1"); !errors.Is(err, ErrCerimonia) {
		t.Errorf("chave depois de consumida: err = %v, quer ErrCerimonia", err)
	}
	key2, _ := c.Nova("login", "op-1", webauthnSessao("desafio"))
	if _, err := c.Consome(key2, "stepup", "op-1"); !errors.Is(err, ErrCerimonia) {
		t.Errorf("tipo trocado: err = %v, quer ErrCerimonia", err)
	}
}

func TestCerimoniaLimiteEGC(t *testing.T) {
	now := time.Unix(1_800_000_000, 0)
	c := NovoCerimoniaStore(time.Minute, 2, func() time.Time { return now })
	for i := 0; i < 2; i++ {
		if _, err := c.Nova("login", "op-1", webauthnSessao("d")); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := c.Nova("login", "op-1", webauthnSessao("d")); !errors.Is(err, ErrCerimoniasCheias) {
		t.Fatalf("acima do teto: err = %v, quer ErrCerimoniasCheias", err)
	}
	now = now.Add(2 * time.Minute) // vencidas: GC libera espaço
	if _, err := c.Nova("login", "op-1", webauthnSessao("d")); err != nil {
		t.Errorf("após expirar, deveria caber: %v", err)
	}
}

func TestStepUpExigeMesmoOperadorEExpira(t *testing.T) {
	f := novoFixture(t)
	k := novoAutSoft(t)
	f.operadorAtivo(t, "op-1", k)
	tok, _, err := f.loga(t, "op-1", k, 1, thumbTeste)
	if err != nil {
		t.Fatal(err)
	}
	if f.sm.StepUpValido(tok, thumbTeste) {
		t.Fatal("step-up válido antes de qualquer re-toque")
	}
	assercao, key, err := f.a.IniciaStepUp(tok, thumbTeste)
	if err != nil {
		t.Fatalf("IniciaStepUp: %v", err)
	}
	corpo := k.corpoAsercao(assercao.Response.Challenge.String(), originTeste, rpIDTeste, 2, []byte("op-1"))
	if err := f.a.FinalizaStepUp(tok, thumbTeste, key, req(corpo)); err != nil {
		t.Fatalf("FinalizaStepUp: %v", err)
	}
	if !f.sm.StepUpValido(tok, thumbTeste) {
		t.Fatal("step-up não marcou a sessão")
	}
	if f.sm.StepUpValido(tok, thumbOutro) {
		t.Error("step-up valeu para outro cliente")
	}
	f.avanca(StepUpTTL + time.Second)
	if f.sm.StepUpValido(tok, thumbTeste) {
		t.Error("step-up não expirou na janela curta")
	}
}

func TestStepUpAntiCloneTambemVale(t *testing.T) {
	f := novoFixture(t)
	k := novoAutSoft(t)
	f.operadorAtivo(t, "op-1", k)
	tok, _, err := f.loga(t, "op-1", k, 4, thumbTeste)
	if err != nil {
		t.Fatal(err)
	}
	assercao, key, err := f.a.IniciaStepUp(tok, thumbTeste)
	if err != nil {
		t.Fatal(err)
	}
	corpo := k.corpoAsercao(assercao.Response.Challenge.String(), originTeste, rpIDTeste, 2, []byte("op-1"))
	if err := f.a.FinalizaStepUp(tok, thumbTeste, key, req(corpo)); !errors.Is(err, ErrCloneSuspeito) {
		t.Fatalf("step-up com contador regredido: err = %v, quer ErrCloneSuspeito", err)
	}
	if f.sm.StepUpValido(tok, thumbTeste) {
		t.Error("step-up marcado apesar de clone")
	}
}

func TestMarcarStepUpRespeitaLimite(t *testing.T) {
	f := novoFixture(t)
	k := novoAutSoft(t)
	f.operadorAtivo(t, "op-1", k)
	tok, _, err := f.loga(t, "op-1", k, 1, thumbTeste)
	if err != nil {
		t.Fatal(err)
	}
	if err := f.sm.MarcarStepUp(tok, thumbTeste, StepUpMaxTTL+time.Second); err == nil {
		t.Error("janela de step-up acima do máximo foi aceita")
	}
	if err := f.sm.MarcarStepUp(tok, thumbOutro, time.Minute); err == nil {
		t.Error("step-up marcado com cert de outro cliente")
	}
}

// webauthnSessao cria uma SessionData mínima para os testes do armazém.
func webauthnSessao(desafio string) webauthn.SessionData {
	return webauthn.SessionData{Challenge: desafio}
}
