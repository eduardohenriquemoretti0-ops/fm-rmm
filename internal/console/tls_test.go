package console

import (
	"crypto/tls"
	"crypto/x509"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/eduardohenriquemoretti0-ops/fm-rmm/internal/pki"
)

// Handshake TLS real com o helper TLSConfigConsole: cert da nossa CA passa;
// sem cert ou com cert de outra CA o handshake é recusado antes de qualquer HTTP.
func TestTLSConfigConsoleHandshakeReal(t *testing.T) {
	a := novoAmbiente(t)

	srvCert, srvKey, err := pki.NewServerCert(a.ca, a.caK, []string{"127.0.0.1"})
	if err != nil {
		t.Fatal(err)
	}
	cfg, err := TLSConfigConsole(a.ca, tls.Certificate{
		Certificate: [][]byte{srvCert.Raw},
		PrivateKey:  srvKey,
	})
	if err != nil {
		t.Fatal(err)
	}
	if cfg.ClientAuth != tls.RequireAndVerifyClientCert {
		t.Fatalf("ClientAuth = %v, quer RequireAndVerifyClientCert", cfg.ClientAuth)
	}
	if cfg.MinVersion != tls.VersionTLS12 {
		t.Fatalf("MinVersion = %x, quer TLS 1.2", cfg.MinVersion)
	}

	ts := httptest.NewUnstartedServer(a.c.Roteador())
	ts.TLS = cfg
	ts.StartTLS()
	defer ts.Close()

	certBom, chaveBom := certDe(t, a.ca, a.caK, "op-bom")
	outraCA, outraK, err := pki.NewCA("CA estranha")
	if err != nil {
		t.Fatal(err)
	}
	certEstranho, chaveEstranho := certDe(t, outraCA, outraK, "op-estranho")

	servidorRaiz := x509.NewCertPool()
	servidorRaiz.AddCert(a.ca)

	cliente := func(cert *x509.Certificate, chave any) *http.Client {
		tc := &tls.Config{RootCAs: servidorRaiz, MinVersion: tls.VersionTLS12}
		if cert != nil {
			tc.Certificates = []tls.Certificate{{Certificate: [][]byte{cert.Raw}, PrivateKey: chave}}
		}
		tr := &http.Transport{TLSClientConfig: tc}
		t.Cleanup(tr.CloseIdleConnections)
		return &http.Client{Transport: tr, Timeout: 5 * time.Second}
	}

	// cert da nossa CA: handshake ok e /healthz responde
	resp, err := cliente(certBom, chaveBom).Get(ts.URL + "/healthz")
	if err != nil {
		t.Fatalf("cert válido recusado no handshake: %v", err)
	}
	io.Copy(io.Discard, resp.Body)
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("/healthz = %d", resp.StatusCode)
	}

	// sem cert: o handshake precisa falhar
	if resp, err := cliente(nil, nil).Get(ts.URL + "/healthz"); err == nil {
		resp.Body.Close()
		t.Fatal("handshake sem cert de cliente foi aceito")
	}

	// cert de outra CA: o handshake precisa falhar
	if resp, err := cliente(certEstranho, chaveEstranho).Get(ts.URL + "/healthz"); err == nil {
		resp.Body.Close()
		t.Fatal("handshake com cert de outra CA foi aceito")
	}
}

func TestTLSConfigConsoleValidaEntradas(t *testing.T) {
	a := novoAmbiente(t)
	if _, err := TLSConfigConsole(nil, tls.Certificate{}); err == nil {
		t.Error("aceitou CA nula")
	}
	if _, err := TLSConfigConsole(a.ca, tls.Certificate{}); err == nil {
		t.Error("aceitou par de servidor vazio")
	}
}
