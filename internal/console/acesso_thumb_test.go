package console

import (
	"testing"

	"github.com/eduardohenriquemoretti0-ops/fm-rmm/internal/pki"
	"github.com/eduardohenriquemoretti0-ops/fm-rmm/internal/server"
)

// O thumbprint que o CLI grava (server.ThumbprintCert) tem de ser idêntico ao
// que o login compara (CertThumbprint), senão o operador nunca entra.
func TestThumbprintCLIIgualAoDoLogin(t *testing.T) {
	ca, caKey, err := pki.NewCA("t")
	if err != nil {
		t.Fatal(err)
	}
	_, csrPEM, _ := pki.NewAgentKeyAndCSR("x")
	csr, _ := pki.ParseCSR(csrPEM)
	c, err := pki.SignOperator(ca, caKey, csr, "op-1")
	if err != nil {
		t.Fatal(err)
	}
	if server.ThumbprintCert(c) != CertThumbprint(c) {
		t.Fatal("definições de thumbprint divergem")
	}
}
