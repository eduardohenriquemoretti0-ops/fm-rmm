package server

import (
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"testing"
	"time"

	"github.com/eduardohenriquemoretti0-ops/fm-rmm/internal/sign"
)

// parChave gera um par Ed25519 para os testes de lista.
func parChave(t *testing.T) (ed25519.PublicKey, ed25519.PrivateKey) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return pub, priv
}

// operadorApto cria técnico + operador ativo com chave de assinatura.
func operadorApto(t *testing.T, st *Store, id, tech string, pub ed25519.PublicKey) {
	t.Helper()
	criaOperador(t, st, id, tech)
	if err := st.SetOperatorStatus(id, "ativo"); err != nil {
		t.Fatal(err)
	}
	if err := st.SetOperatorSigningPub(id, sign.EncodePub(pub)); err != nil {
		t.Fatal(err)
	}
}

func TestOperadoresParaListaFiltraAptos(t *testing.T) {
	st, _ := abreStoreTeste(t)
	apto, _ := parChave(t)
	pendente, _ := parChave(t)
	desabilitado, _ := parChave(t)
	operadorApto(t, st, "op-apto", "joao", apto)
	operadorApto(t, st, "op-pend", "ana", pendente)
	if err := st.SetOperatorStatus("op-pend", "pendente"); err != nil {
		t.Fatal(err)
	}
	operadorApto(t, st, "op-desab", "carla", desabilitado)
	if err := st.DisableTech("carla", true); err != nil {
		t.Fatal(err)
	}
	criaOperador(t, st, "op-sem", "dani") // ativo, mas SEM chave de assinatura
	if err := st.SetOperatorStatus("op-sem", "ativo"); err != nil {
		t.Fatal(err)
	}

	ents, err := st.OperadoresParaLista()
	if err != nil {
		t.Fatal(err)
	}
	if len(ents) != 1 {
		t.Fatalf("esperado só o operador apto, veio %d: %+v", len(ents), ents)
	}
	e := ents[0]
	if e.KeyID != sign.KeyID(apto) || e.Pub != sign.EncodePub(apto) || e.Role != sign.RoleOperator {
		t.Fatalf("entrada errada: %+v", e)
	}
}

func TestSetOperatorSigningPubValida(t *testing.T) {
	st, _ := abreStoreTeste(t)
	pub, _ := parChave(t)
	outra, _ := parChave(t)
	criaOperador(t, st, "op-1", "joao")
	criaOperador(t, st, "op-2", "joao")

	if err := st.SetOperatorSigningPub("op-1", "não-é-base64!"); err == nil {
		t.Fatal("chave com base64 inválido aceita")
	}
	if err := st.SetOperatorSigningPub("op-1", sign.EncodePub(pub[:16])); err == nil {
		t.Fatal("chave de tamanho errado aceita")
	}
	if err := st.SetOperatorSigningPub("op-x", sign.EncodePub(pub)); !errors.Is(err, ErrNotFound) {
		t.Fatalf("operador inexistente: esperado ErrNotFound, veio %v", err)
	}
	if err := st.SetOperatorSigningPub("op-1", sign.EncodePub(pub)); err != nil {
		t.Fatal(err)
	}
	op, _ := st.GetOperator("op-1")
	if op.SigningPub != sign.EncodePub(pub) {
		t.Fatalf("chave não gravada: %q", op.SigningPub)
	}
	// a mesma pública não pode servir a dois operadores
	if err := st.SetOperatorSigningPub("op-2", sign.EncodePub(pub)); err == nil {
		t.Fatal("chave repetida em outro operador aceita")
	}
	// rotação: troca a chave do mesmo operador
	if err := st.SetOperatorSigningPub("op-1", sign.EncodePub(outra)); err != nil {
		t.Fatalf("rotação recusada: %v", err)
	}
}

func TestConstruirPublicarELerLista(t *testing.T) {
	st, _ := abreStoreTeste(t)
	raizPub, raizPriv := parChave(t)
	opPub, _ := parChave(t)
	operadorApto(t, st, "op-1", "joao", opPub)

	exp, err := st.ExportarLista()
	if err != nil {
		t.Fatal(err)
	}
	if exp.VersaoAtual != 0 || len(exp.Operadores) != 1 {
		t.Fatalf("export inicial: %+v", exp)
	}
	raw, sig, versao, err := ConstruirLista(raizPriv, exp.VersaoAtual, exp.Operadores, time.Now().UTC())
	if err != nil {
		t.Fatal(err)
	}
	if versao != 1 {
		t.Fatalf("primeira versão deveria ser 1, veio %d", versao)
	}
	// o que a ferramenta gera é exatamente o que o agente aceita
	if _, err := sign.ParseSignerList(raizPub, raw, sig); err != nil {
		t.Fatalf("ParseSignerList recusou a lista gerada: %v", err)
	}
	if v, err := PublicarLista(st, raizPub, raw, sig, "teste"); err != nil || v != 1 {
		t.Fatalf("publicar: v=%d err=%v", v, err)
	}
	v, gotRaw, gotSig, err := st.listaAtual()
	if err != nil || v != 1 || string(gotRaw) != string(raw) || string(gotSig) != string(sig) {
		t.Fatalf("lista servida difere da publicada: v=%d err=%v", v, err)
	}
	entries, _ := st.AuditEntries()
	if len(entries) == 0 || entries[len(entries)-1].Event != "lista.publicada" {
		t.Fatal("publicação sem auditoria")
	}
}

func TestPublicarListaRecusaDowngradeEReplay(t *testing.T) {
	st, _ := abreStoreTeste(t)
	raizPub, raizPriv := parChave(t)
	opPub, _ := parChave(t)
	now := time.Now().UTC()

	raw1, sig1, _, _ := ConstruirLista(raizPriv, 0, nil, now)
	raw2, sig2, _, _ := ConstruirLista(raizPriv, 1, []sign.SignerEntry{{KeyID: sign.KeyID(opPub), Pub: sign.EncodePub(opPub), Role: sign.RoleOperator}}, now)
	if _, err := PublicarLista(st, raizPub, raw2, sig2, "teste"); err != nil {
		t.Fatal(err)
	}
	if _, err := PublicarLista(st, raizPub, raw1, sig1, "teste"); !errors.Is(err, sign.ErrListaVersao) {
		t.Fatalf("downgrade no servidor: esperado ErrListaVersao, veio %v", err)
	}
	if _, err := PublicarLista(st, raizPub, raw2, sig2, "teste"); !errors.Is(err, sign.ErrListaVersao) {
		t.Fatalf("replay da mesma versão: esperado ErrListaVersao, veio %v", err)
	}
	if v, _, _, _ := st.listaAtual(); v != 2 {
		t.Fatalf("versão publicada mudou após recusas: %d", v)
	}
}

func TestPublicarListaSoAceitaAssinaturaDaRaiz(t *testing.T) {
	st, _ := abreStoreTeste(t)
	raizPub, _ := parChave(t)
	_, intrusoPriv := parChave(t)
	raw, sig, _, err := ConstruirLista(intrusoPriv, 0, nil, time.Now().UTC()) // assinada por outra chave
	if err != nil {
		t.Fatal(err)
	}
	if _, err := PublicarLista(st, raizPub, raw, sig, "teste"); !errors.Is(err, sign.ErrListaAssinatura) {
		t.Fatalf("lista de não-raiz publicada: %v", err)
	}
	if v, _, _, _ := st.listaAtual(); v != 0 {
		t.Fatal("lista recusada foi gravada")
	}
}

func TestConstruirListaRecusaPapelAdminEOperadorInvalido(t *testing.T) {
	_, raizPriv := parChave(t)
	opPub, _ := parChave(t)
	now := time.Now().UTC()
	admin := []sign.SignerEntry{{KeyID: sign.KeyID(opPub), Pub: sign.EncodePub(opPub), Role: sign.RoleAdmin}}
	if _, _, _, err := ConstruirLista(raizPriv, 0, admin, now); err == nil {
		t.Fatal("export com papel admin aceito pela ferramenta")
	}
	ruim := []sign.SignerEntry{{KeyID: "0000000000000000", Pub: sign.EncodePub(opPub), Role: sign.RoleOperator}}
	if _, _, _, err := ConstruirLista(raizPriv, 0, ruim, now); !errors.Is(err, sign.ErrListaMalformada) {
		t.Fatalf("key_id que não confere aceito: %v", err)
	}
	// a própria raiz listada como operador é duplicata
	raizPub := raizPriv.Public().(ed25519.PublicKey)
	dup := []sign.SignerEntry{{KeyID: sign.KeyID(raizPub), Pub: sign.EncodePub(raizPub), Role: sign.RoleOperator}}
	if _, _, _, err := ConstruirLista(raizPriv, 0, dup, now); err == nil {
		t.Fatal("raiz repetida como operador aceita")
	}
}

func TestMigracaoIdempotente(t *testing.T) {
	st, path := abreStoreTeste(t)
	pub, _ := parChave(t)
	operadorApto(t, st, "op-1", "joao", pub)
	if err := st.Close(); err != nil {
		t.Fatal(err)
	}
	// reabrir: as migrações (ALTER/índice/tabela) rodam de novo sem erro nem perda
	st2, err := OpenStore(path)
	if err != nil {
		t.Fatalf("reabrir o banco: %v", err)
	}
	defer st2.Close()
	op, err := st2.GetOperator("op-1")
	if err != nil || op.SigningPub != sign.EncodePub(pub) {
		t.Fatalf("chave perdida após reabrir: %q err=%v", op.SigningPub, err)
	}
}
