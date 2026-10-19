package server

import (
	"path/filepath"
	"testing"

	"github.com/eduardohenriquemoretti0-ops/fm-rmm/internal/pki"
)

// montaServidor cria um dir com CA + banco e um técnico.
func montaServidor(t *testing.T) (string, *Store) {
	t.Helper()
	dir := t.TempDir()
	ca, caKey, err := pki.NewCA("FM-RMM CA")
	if err != nil {
		t.Fatal(err)
	}
	der, _ := pki.KeyDER(caKey)
	if err := pki.WritePEM(filepath.Join(dir, FileCA), "CERTIFICATE", ca.Raw); err != nil {
		t.Fatal(err)
	}
	if err := pki.WritePEM(filepath.Join(dir, FileCAKey), "PRIVATE KEY", der); err != nil {
		t.Fatal(err)
	}
	st, err := OpenStore(filepath.Join(dir, FileDB))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })
	if err := st.AddTech("joao"); err != nil {
		t.Fatal(err)
	}
	return dir, st
}

func TestOperadorCreateGet(t *testing.T) {
	_, st := montaServidor(t)
	id, err := NovoIDOperador()
	if err != nil {
		t.Fatal(err)
	}
	if err := st.CreateOperator(Operator{ID: id, Nome: "Maria", DisplayName: "Maria S.", TechName: "joao"}); err != nil {
		t.Fatal(err)
	}
	o, err := st.GetOperator(id)
	if err != nil || o.Status != "pendente" || o.TechName != "joao" || o.CertThumbprint != "" {
		t.Fatalf("get: %+v %v", o, err)
	}
	if err := st.CreateOperator(Operator{ID: "op-x", Nome: "X", TechName: "inexistente"}); err == nil {
		t.Fatal("técnico inexistente deveria ser recusado")
	}
}

func TestEmitirCertOperador(t *testing.T) {
	dir, st := montaServidor(t)
	if err := st.CreateOperator(Operator{ID: "op-1", Nome: "Maria", TechName: "joao"}); err != nil {
		t.Fatal(err)
	}
	out := filepath.Join(t.TempDir(), "saida")
	thumb, cert, err := EmitirCertOperador(st, dir, "op-1", out, false)
	if err != nil {
		t.Fatal(err)
	}
	lido, err := pki.LoadCert(filepath.Join(out, FileOperadorCrt))
	if err != nil {
		t.Fatal(err)
	}
	if !pki.EhOperador(lido) || lido.Subject.CommonName != "op-1" {
		t.Fatalf("cert sem perfil de operador: %v", lido.Subject)
	}
	ca, _ := pki.LoadCert(filepath.Join(dir, FileCA))
	if err := lido.CheckSignatureFrom(ca); err != nil {
		t.Fatalf("cadeia: %v", err)
	}
	if _, err := pki.LoadKey(filepath.Join(out, FileOperadorKey)); err != nil {
		t.Fatal(err)
	}
	o, _ := st.GetOperator("op-1")
	if o.CertThumbprint != thumb || thumb != ThumbprintCert(lido) || thumb != ThumbprintCert(cert) {
		t.Fatalf("thumbprint divergente: banco=%s ret=%s", o.CertThumbprint, thumb)
	}
	if got, err := st.OperatorByThumbprint(thumb); err != nil || got.ID != "op-1" {
		t.Fatalf("OperatorByThumbprint: %v %v", got, err)
	}
	// segunda emissão exige --reemitir e não sobrescreve arquivos
	if _, _, err := EmitirCertOperador(st, dir, "op-1", out, false); err == nil {
		t.Fatal("reemissão sem flag deveria falhar")
	}
	if _, _, err := EmitirCertOperador(st, dir, "op-1", out, true); err == nil {
		t.Fatal("deveria recusar sobrescrever arquivos existentes")
	}
	if o2, _ := st.GetOperator("op-1"); o2.CertThumbprint != thumb {
		t.Fatal("falha na reemissão não pode alterar o thumbprint")
	}
	if _, _, err := EmitirCertOperador(st, dir, "op-nao", t.TempDir(), false); err == nil {
		t.Fatal("operador inexistente deveria falhar")
	}
}

func TestAtivarOperador(t *testing.T) {
	dir, st := montaServidor(t)
	if err := st.CreateOperator(Operator{ID: "op-1", Nome: "Maria", TechName: "joao"}); err != nil {
		t.Fatal(err)
	}
	if err := AtivarOperador(st, "op-1"); err == nil {
		t.Fatal("sem cert deveria recusar")
	}
	if _, _, err := EmitirCertOperador(st, dir, "op-1", filepath.Join(t.TempDir(), "o"), false); err != nil {
		t.Fatal(err)
	}
	if err := AtivarOperador(st, "op-1"); err == nil {
		t.Fatal("sem credenciais deveria recusar")
	}
	for _, c := range []string{"cred-a", "cred-b"} {
		if err := st.AddCredential(OperatorCredential{CredentialID: c, OperatorID: "op-1", PublicKey: []byte{1}}); err != nil {
			t.Fatal(err)
		}
		if c == "cred-a" {
			if err := AtivarOperador(st, "op-1"); err == nil {
				t.Fatal("com 1 credencial deveria recusar")
			}
		}
	}
	if err := AtivarOperador(st, "op-1"); err != nil {
		t.Fatal(err)
	}
	if o, _ := st.GetOperator("op-1"); o.Status != "ativo" {
		t.Fatalf("status = %s", o.Status)
	}
}

func TestOperatorsListaFlags(t *testing.T) {
	dir, st := montaServidor(t)
	for _, id := range []string{"op-a", "op-b"} {
		if err := st.CreateOperator(Operator{ID: id, Nome: id, TechName: "joao"}); err != nil {
			t.Fatal(err)
		}
	}
	if _, _, err := EmitirCertOperador(st, dir, "op-b", filepath.Join(t.TempDir(), "o"), false); err != nil {
		t.Fatal(err)
	}
	ops, err := st.Operators()
	if err != nil || len(ops) != 2 {
		t.Fatalf("%v %v", ops, err)
	}
	if ops[0].CertThumbprint != "" || ops[1].CertThumbprint == "" || ops[0].SigningPub != "" {
		t.Fatalf("flags: %+v", ops)
	}
}
