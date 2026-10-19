package server

import (
	"bytes"
	"errors"
	"path/filepath"
	"testing"
	"time"
)

// abreStoreTeste abre um banco temporário e devolve o caminho para reabri-lo.
func abreStoreTeste(t *testing.T) (*Store, string) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "t.db")
	st, err := OpenStore(path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })
	return st, path
}

// criaOperador cria o técnico (se preciso) e o operador ligado a ele.
func criaOperador(t *testing.T, st *Store, id, tech string) {
	t.Helper()
	if err := st.AddTech(tech); err != nil {
		t.Fatal(err)
	}
	if err := st.CreateOperator(Operator{ID: id, Nome: id, TechName: tech}); err != nil {
		t.Fatal(err)
	}
}

func TestOperadorCriarLer(t *testing.T) {
	st, _ := abreStoreTeste(t)
	if err := st.AddTech("eduardo"); err != nil {
		t.Fatal(err)
	}
	op := Operator{ID: "op-1", Nome: "eduardo", DisplayName: "Eduardo Moretti", TechName: "eduardo"}
	if err := st.CreateOperator(op); err != nil {
		t.Fatal(err)
	}
	got, err := st.GetOperator("op-1")
	if err != nil {
		t.Fatal(err)
	}
	if got.Nome != "eduardo" || got.DisplayName != "Eduardo Moretti" || got.TechName != "eduardo" {
		t.Errorf("campos: %+v", got)
	}
	if got.Status != "pendente" {
		t.Errorf("status padrão = %q, quer pendente", got.Status)
	}
	if got.CriadoEm == 0 {
		t.Error("criado_em não preenchido")
	}
	if _, err := st.GetOperator("op-inexistente"); !errors.Is(err, ErrNotFound) {
		t.Errorf("operador inexistente: err=%v, quer ErrNotFound", err)
	}
	if err := st.CreateOperator(op); err == nil {
		t.Error("id de operador repetido aceito")
	}
	if err := st.CreateOperator(Operator{ID: "op-2", TechName: "eduardo"}); err == nil {
		t.Error("operador sem nome aceito")
	}
	if err := st.CreateOperator(Operator{ID: "op-3", Nome: "x"}); err == nil {
		t.Error("operador sem tech_name aceito")
	}
	if err := st.CreateOperator(Operator{ID: "op-4", Nome: "x", TechName: "fantasma"}); err == nil {
		t.Error("operador ligado a técnico inexistente aceito")
	}
}

func TestOperatorByThumbprint(t *testing.T) {
	st, _ := abreStoreTeste(t)
	criaOperador(t, st, "op-1", "ana")
	if err := st.SetOperatorThumbprint("op-1", "aa11"); err != nil {
		t.Fatal(err)
	}
	got, err := st.OperatorByThumbprint("aa11")
	if err != nil || got.ID != "op-1" || got.TechName != "ana" {
		t.Fatalf("OperatorByThumbprint: %+v, %v", got, err)
	}
	if _, err := st.OperatorByThumbprint("bb22"); !errors.Is(err, ErrNotFound) {
		t.Errorf("thumbprint desconhecido: err=%v", err)
	}
	if _, err := st.OperatorByThumbprint(""); !errors.Is(err, ErrNotFound) {
		t.Errorf("thumbprint vazio: err=%v", err)
	}
}

func TestOperadorThumbprint(t *testing.T) {
	st, _ := abreStoreTeste(t)
	criaOperador(t, st, "op-1", "t1")
	criaOperador(t, st, "op-2", "t2")
	if err := st.SetOperatorThumbprint("op-1", "aa11"); err != nil {
		t.Fatal(err)
	}
	got, _ := st.GetOperator("op-1")
	if got.CertThumbprint != "aa11" {
		t.Errorf("thumbprint = %q", got.CertThumbprint)
	}
	if err := st.SetOperatorThumbprint("op-2", "aa11"); err == nil {
		t.Error("mesmo cert ligado a dois operadores")
	}
	if err := st.SetOperatorThumbprint("op-2", ""); err == nil {
		t.Error("thumbprint vazio aceito")
	}
	if err := st.SetOperatorThumbprint("nao-existe", "bb22"); !errors.Is(err, ErrNotFound) {
		t.Errorf("operador inexistente: err=%v", err)
	}
}

// RBAC: o operador acessa o que o técnico acessa (CanAccess), nada além.
func TestOperadorRBACPeloTecnico(t *testing.T) {
	st, _ := abreStoreTeste(t)
	criaOperador(t, st, "op-1", "tecnico-t")
	if err := st.GrantGroup("tecnico-t", "A"); err != nil {
		t.Fatal(err)
	}
	_, tok, err := st.NewToken("lote", 2, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	agA, _, err := st.Enroll(tok, "pcA", "windows", "csr", "1.2.3.4")
	if err != nil {
		t.Fatal(err)
	}
	agB, _, err := st.Enroll(tok, "pcB", "windows", "csr", "1.2.3.4")
	if err != nil {
		t.Fatal(err)
	}
	if err := st.SetAgentGroup(agA, "A"); err != nil {
		t.Fatal(err)
	}
	if err := st.SetAgentGroup(agB, "B"); err != nil {
		t.Fatal(err)
	}
	op, err := st.GetOperator("op-1")
	if err != nil {
		t.Fatal(err)
	}
	if err := st.CanAccess(op.TechName, agA); err != nil {
		t.Errorf("operador do grupo A recusado no agente A: %v", err)
	}
	if err := st.CanAccess(op.TechName, agB); !errors.Is(err, ErrAccessDenied) {
		t.Errorf("operador do grupo A alcançou agente B (IDOR): err=%v", err)
	}
	// técnico desabilitado: o operador perde o acesso junto
	if err := st.DisableTech("tecnico-t", true); err != nil {
		t.Fatal(err)
	}
	if err := st.CanAccess(op.TechName, agA); !errors.Is(err, ErrAccessDenied) {
		t.Errorf("técnico desabilitado ainda acessa via operador: err=%v", err)
	}
}

func TestCredencialIdUnico(t *testing.T) {
	st, _ := abreStoreTeste(t)
	criaOperador(t, st, "op-1", "t1")
	c := OperatorCredential{CredentialID: "cred-1", OperatorID: "op-1", PublicKey: []byte{1, 2, 3}}
	if err := st.AddCredential(c); err != nil {
		t.Fatal(err)
	}
	if err := st.AddCredential(c); err == nil {
		t.Fatal("2º insert do mesmo credential_id deveria falhar")
	}
	c.CredentialID = "cred-2"
	c.OperatorID = "op-fantasma"
	if err := st.AddCredential(c); err == nil {
		t.Fatal("credencial de operador inexistente aceita (FK)")
	}
}

func TestCredentialsDoOperador(t *testing.T) {
	st, _ := abreStoreTeste(t)
	criaOperador(t, st, "op-1", "t1")
	criaOperador(t, st, "op-2", "t2")
	chave1 := []byte{0x01, 0x02, 0x03}
	chave2 := []byte{0x04, 0x05, 0x06}
	for _, c := range []OperatorCredential{
		{CredentialID: "c-principal", OperatorID: "op-1", PublicKey: chave1, SignCount: 7, AAGUID: "aaguid-x"},
		{CredentialID: "c-backup", OperatorID: "op-1", PublicKey: chave2},
		{CredentialID: "c-outro", OperatorID: "op-2", PublicKey: chave1},
	} {
		if err := st.AddCredential(c); err != nil {
			t.Fatal(err)
		}
	}
	creds, err := st.Credentials("op-1")
	if err != nil {
		t.Fatal(err)
	}
	if len(creds) != 2 {
		t.Fatalf("op-1 tem %d credenciais, quer 2", len(creds))
	}
	// a ordem entre credenciais criadas no mesmo segundo não é garantida: busca por id
	porID := map[string]OperatorCredential{}
	for _, c := range creds {
		if c.OperatorID != "op-1" {
			t.Errorf("vazou credencial de outro operador: %+v", c)
		}
		porID[c.CredentialID] = c
	}
	p, ok := porID["c-principal"]
	if !ok {
		t.Fatalf("c-principal ausente: %+v", creds)
	}
	if p.SignCount != 7 || p.AAGUID != "aaguid-x" {
		t.Errorf("campos da credencial: %+v", p)
	}
	if !bytes.Equal(p.PublicKey, chave1) {
		t.Errorf("public_key corrompida: %x", p.PublicKey)
	}
	vazio, err := st.Credentials("op-sem-nada")
	if err != nil || len(vazio) != 0 {
		t.Errorf("operador sem credenciais: %v, %v", vazio, err)
	}
}

func TestUpdateSignCountPersiste(t *testing.T) {
	st, path := abreStoreTeste(t)
	criaOperador(t, st, "op-1", "t1")
	if err := st.AddCredential(OperatorCredential{CredentialID: "c-1", OperatorID: "op-1", PublicKey: []byte{9}}); err != nil {
		t.Fatal(err)
	}
	if err := st.UpdateSignCount("c-1", 42); err != nil {
		t.Fatal(err)
	}
	if err := st.UpdateSignCount("nao-existe", 1); !errors.Is(err, ErrNotFound) {
		t.Errorf("credencial inexistente: err=%v, quer ErrNotFound", err)
	}
	// reabre o banco: o contador tem que sobreviver ao fechamento
	if err := st.Close(); err != nil {
		t.Fatal(err)
	}
	st2, err := OpenStore(path)
	if err != nil {
		t.Fatal(err)
	}
	defer st2.Close()
	creds, err := st2.Credentials("op-1")
	if err != nil || len(creds) != 1 {
		t.Fatalf("credenciais após reabrir: %v, %v", creds, err)
	}
	if creds[0].SignCount != 42 {
		t.Errorf("sign_count após reabrir = %d, quer 42", creds[0].SignCount)
	}
}
