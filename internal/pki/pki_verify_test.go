package pki

import (
	"crypto/x509"
	"testing"
)

func TestChainVerifica(t *testing.T) {
	ca, caKey, err := NewCA("FM-RMM CA")
	if err != nil { t.Fatal(err) }
	srv, _, err := NewServerCert(ca, caKey, []string{"127.0.0.1"})
	if err != nil { t.Fatal(err) }
	pool := x509.NewCertPool()
	pool.AddCert(ca)
	if _, err := srv.Verify(x509.VerifyOptions{Roots: pool, KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}); err != nil {
		t.Fatalf("server não verifica contra a CA: %v", err)
	}
	// round-trip por PEM (como o agente faz com o bundle)
	caBack, err := ParseCertPEM(CertPEM(ca))
	if err != nil { t.Fatal(err) }
	pool2 := x509.NewCertPool(); pool2.AddCert(caBack)
	srvBack, _ := ParseCertPEM(CertPEM(srv))
	if _, err := srvBack.Verify(x509.VerifyOptions{Roots: pool2, KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}); err != nil {
		t.Fatalf("round-trip PEM falhou: %v", err)
	}
}
