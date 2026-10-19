package pki

import (
	"crypto/x509"
	"testing"
)

// csrDe gera um CSR de teste e o devolve já validado.
func csrDe(t *testing.T, nome string) *x509.CertificateRequest {
	t.Helper()
	_, csrPEM, err := NewAgentKeyAndCSR(nome)
	if err != nil {
		t.Fatal(err)
	}
	csr, err := ParseCSR(csrPEM)
	if err != nil {
		t.Fatal(err)
	}
	return csr
}

// SignOperator emite cert com o perfil de operador e cadeia válida na CA.
func TestSignOperatorPerfilEChain(t *testing.T) {
	ca, caKey, err := NewCA("FM-RMM CA")
	if err != nil {
		t.Fatal(err)
	}
	cert, err := SignOperator(ca, caKey, csrDe(t, "x"), "op-maria")
	if err != nil {
		t.Fatal(err)
	}
	if cert.Subject.CommonName != "op-maria" {
		t.Errorf("CN = %q, quer o id do operador", cert.Subject.CommonName)
	}
	if !EhOperador(cert) {
		t.Error("EhOperador recusou cert de SignOperator")
	}
	pool := x509.NewCertPool()
	pool.AddCert(ca)
	if _, err := cert.Verify(x509.VerifyOptions{Roots: pool, KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}}); err != nil {
		t.Fatalf("cert de operador não verifica contra a CA: %v", err)
	}
}

// Cert de AGENTE (SignAgent) nunca passa por operador, mesmo com cadeia válida.
func TestCertDeAgenteNaoEhOperador(t *testing.T) {
	ca, caKey, err := NewCA("FM-RMM CA")
	if err != nil {
		t.Fatal(err)
	}
	agente, err := SignAgent(ca, caKey, csrDe(t, "pc"), "ag-1234")
	if err != nil {
		t.Fatal(err)
	}
	if EhOperador(agente) {
		t.Error("EhOperador aceitou cert de agente")
	}
}

// Cert sem Organization (ex.: CA ou cert de servidor) não é operador.
func TestEhOperadorRecusaSemPerfil(t *testing.T) {
	ca, _, err := NewCA("FM-RMM CA")
	if err != nil {
		t.Fatal(err)
	}
	if EhOperador(ca) {
		t.Error("EhOperador aceitou a própria CA")
	}
}
