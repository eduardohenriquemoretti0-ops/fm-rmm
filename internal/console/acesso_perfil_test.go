package console

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/eduardohenriquemoretti0-ops/fm-rmm/internal/pki"
)

// (T3b) cert de AGENTE, da nossa CA e com operador cadastrado com esse thumbprint,
// é recusado no comCert: só a verificação de perfil pode barrar.
func TestCertDeAgenteRecusadoComoOperador(t *testing.T) {
	a := novoAmbiente(t)
	_, csrPEM, err := pki.NewAgentKeyAndCSR("pc-x")
	if err != nil {
		t.Fatal(err)
	}
	csr, err := pki.ParseCSR(csrPEM)
	if err != nil {
		t.Fatal(err)
	}
	certAgente, err := pki.SignAgent(a.ca, a.caK, csr, "ag-1234")
	if err != nil {
		t.Fatal(err)
	}
	// operador cadastrado com o thumbprint do cert de agente (cenário de erro de cadastro)
	a.f.criaOperador(t, "op-intruso", "ativo", CertThumbprint(certAgente))

	h := a.c.soCert(http.HandlerFunc(ecoOperador))
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, reqTLS(http.MethodPost, "/api/login/inicio", nil, certAgente))
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("cert de AGENTE como operador = %d, quer 401", rec.Code)
	}

	// e pela rota real de login também
	rec = httptest.NewRecorder()
	a.c.Roteador().ServeHTTP(rec, reqTLS(http.MethodPost, "/api/login/inicio", nil, certAgente))
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("login com cert de agente = %d, quer 401", rec.Code)
	}
}

// Cert da nossa CA sem o perfil de operador (sem Organization) também é recusado.
func TestCertSemPerfilDeOperadorRecusado(t *testing.T) {
	a := novoAmbiente(t)
	chave, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tpl := &x509.Certificate{
		SerialNumber: big.NewInt(4242),
		Subject:      pkix.Name{CommonName: "sem-perfil"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, tpl, a.ca, &chave.PublicKey, a.caK)
	if err != nil {
		t.Fatal(err)
	}
	semPerfil, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	a.f.criaOperador(t, "op-sem-perfil", "ativo", CertThumbprint(semPerfil))

	h := a.c.soCert(http.HandlerFunc(ecoOperador))
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, reqTLS(http.MethodPost, "/", nil, semPerfil))
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("cert sem perfil de operador = %d, quer 401", rec.Code)
	}
}

// Cert de operador (SignOperator) continua passando: o controle do T3b.
func TestCertDeOperadorPassaNoComCert(t *testing.T) {
	a := novoAmbiente(t)
	certA, _ := certDe(t, a.ca, a.caK, "op-a")
	a.f.criaOperador(t, "op-a", "ativo", CertThumbprint(certA))
	h := a.c.soCert(http.HandlerFunc(ecoOperador))
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, reqTLS(http.MethodPost, "/", nil, certA))
	if rec.Code != http.StatusOK {
		t.Fatalf("cert de operador = %d, quer 200", rec.Code)
	}
}

// NovoConsole exige intervalo de check-in positivo (base do "online").
func TestNovoConsoleExigeIntervalo(t *testing.T) {
	a := novoAmbiente(t)
	if _, err := NovoConsole(a.f.sm, a.f.a, a.f.st, a.pool, 0); err == nil {
		t.Error("aceitou intervalo zero")
	}
}
