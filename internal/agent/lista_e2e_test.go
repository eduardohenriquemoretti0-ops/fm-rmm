package agent

// Aceite do T5b, ponta a ponta no mesmo processo: servidor TLS de verdade
// (httptest), agente real e a ferramenta de admin (ConstruirLista) com a chave
// raiz. Cobre: export -> montagem/assinatura offline -> publicação -> servir no
// check-in -> ingestão -> operador passa a valer -> revogação -> replay recusado
// -> persistência após reinício.

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/eduardohenriquemoretti0-ops/fm-rmm/internal/proto"
	"github.com/eduardohenriquemoretti0-ops/fm-rmm/internal/server"
	"github.com/eduardohenriquemoretti0-ops/fm-rmm/internal/sign"
)

// jobDoOperador monta um job assinado pela chave de OPERADOR para o agente dado.
func jobDoOperador(t *testing.T, priv ed25519.PrivateKey, agentID string, now time.Time) proto.SignedJob {
	t.Helper()
	p := proto.JobPayload{V: proto.Version, JobID: fmt.Sprintf("job-op-%d", contadorJob.Add(1)),
		AgentID: agentID, Action: "info", IssuedAt: now, ExpiresAt: now.Add(time.Hour), Issuer: "operador:joao"}
	sj, err := sign.SignJob(priv, p)
	if err != nil {
		t.Fatal(err)
	}
	return sj
}

func TestListaEndToEnd(t *testing.T) {
	l := newLab(t)
	ctx := context.Background()
	ag := l.newAgent(l.token(1))
	l.enrolled(ag)
	agentID := ag.state.AgentID
	raiz := l.admin // a raiz do bundle é a chave de admin do lab
	raizPub := raiz.Public().(ed25519.PublicKey)

	// operador com chave de assinatura (em produção a privada fica no navegador)
	opPub, opPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	if err := l.st.AddTech("joao"); err != nil {
		t.Fatal(err)
	}
	if err := l.st.CreateOperator(server.Operator{ID: "op-joao", Nome: "João", TechName: "joao"}); err != nil {
		t.Fatal(err)
	}
	if err := l.st.SetOperatorStatus("op-joao", "ativo"); err != nil {
		t.Fatal(err)
	}
	if err := l.st.SetOperatorSigningPub("op-joao", sign.EncodePub(opPub)); err != nil {
		t.Fatal(err)
	}

	// 1. sem lista publicada: o check-in não traz lista e o operador NÃO vale
	if err := ag.CheckinOnce(ctx); err != nil {
		t.Fatalf("check-in sem lista: %v", err)
	}
	if ag.trust.maxVersion != 0 {
		t.Fatalf("sem lista publicada, versão aceita deveria ser 0, veio %d", ag.trust.maxVersion)
	}
	sjAntes := jobDoOperador(t, opPriv, agentID, ag.now())
	if _, err := sign.VerifyJobAny(ag.confianca(), sjAntes, agentID, ag.now()); !errors.Is(err, sign.ErrSignature) {
		t.Fatalf("operador aceito antes de qualquer lista: %v", err)
	}

	// 2. ferramenta de admin (offline): export -> monta e assina com a raiz -> publica
	exp, err := l.st.ExportarLista()
	if err != nil {
		t.Fatal(err)
	}
	if exp.VersaoAtual != 0 || len(exp.Operadores) != 1 || exp.Operadores[0].KeyID != sign.KeyID(opPub) {
		t.Fatalf("export: %+v", exp)
	}
	raw1, sig1, v1, err := server.ConstruirLista(raiz, exp.VersaoAtual, exp.Operadores, ag.now())
	if err != nil || v1 != 1 {
		t.Fatalf("ConstruirLista: v=%d err=%v", v1, err)
	}
	if _, err := sign.ParseSignerList(raizPub, raw1, sig1); err != nil {
		t.Fatalf("ParseSignerList recusa a lista da ferramenta: %v", err)
	}
	if _, err := server.PublicarLista(l.st, raizPub, raw1, sig1, "teste"); err != nil {
		t.Fatalf("publicar v1: %v", err)
	}

	// 3. o agente recebe a lista no check-in e a ingere
	if err := ag.CheckinOnce(ctx); err != nil {
		t.Fatalf("check-in com lista: %v", err)
	}
	if ag.trust.maxVersion != 1 {
		t.Fatalf("check-in não ingeriu a lista: versão aceita %d", ag.trust.maxVersion)
	}

	// 4. o operador da lista passa a valer no trust-set e o job é executado
	sj := jobDoOperador(t, opPriv, agentID, ag.now())
	if _, err := sign.VerifyJobAny(ag.confianca(), sj, agentID, ag.now()); err != nil {
		t.Fatalf("job do operador da lista recusado pelo trust-set: %v", err)
	}
	if res := ag.handleJob(ctx, sj); res.Status != "ok" {
		t.Fatalf("job do operador da lista não executou: status=%s erro=%s", res.Status, res.Error)
	}

	// 5. revogação: v2 sem o operador (a raiz continua). Chega no próximo check-in.
	exp2, err := l.st.ExportarLista()
	if err != nil {
		t.Fatal(err)
	}
	if exp2.VersaoAtual != 1 {
		t.Fatalf("versão atual no servidor: %d", exp2.VersaoAtual)
	}
	raw2, sig2, v2, err := server.ConstruirLista(raiz, exp2.VersaoAtual, nil, ag.now())
	if err != nil || v2 != 2 {
		t.Fatalf("ConstruirLista v2: v=%d err=%v", v2, err)
	}
	if _, err := server.PublicarLista(l.st, raizPub, raw2, sig2, "teste"); err != nil {
		t.Fatalf("publicar v2: %v", err)
	}
	if err := ag.CheckinOnce(ctx); err != nil {
		t.Fatal(err)
	}
	if ag.trust.maxVersion != 2 {
		t.Fatalf("revogação não chegou ao agente: versão %d", ag.trust.maxVersion)
	}
	sjRev := jobDoOperador(t, opPriv, agentID, ag.now())
	if _, err := sign.VerifyJobAny(ag.confianca(), sjRev, agentID, ag.now()); !errors.Is(err, sign.ErrSignature) {
		t.Fatalf("operador revogado ainda aceito: %v", err)
	}

	// 6. replay da lista v1 (assinada corretamente, com o operador): recusado
	if err := ag.IngerirListaSigners(raw1, sig1); !errors.Is(err, sign.ErrListaVersao) {
		t.Fatalf("replay da v1 aceito: %v", err)
	}
	if _, err := sign.VerifyJobAny(ag.confianca(), sjRev, agentID, ag.now()); !errors.Is(err, sign.ErrSignature) {
		t.Fatalf("replay da v1 reabilitou o operador revogado: %v", err)
	}
	// e o servidor também não aceita publicar a v1 de volta
	if _, err := server.PublicarLista(l.st, raizPub, raw1, sig1, "teste"); !errors.Is(err, sign.ErrListaVersao) {
		t.Fatalf("servidor republicou lista antiga: %v", err)
	}

	// 7. reinício do agente: a versão 2 e a revogação persistem (trust.json)
	ag2, err := New(ag.Dir, ag.Log)
	if err != nil {
		t.Fatal(err)
	}
	if ag2.trust.maxVersion != 2 {
		t.Fatalf("após reinício, versão aceita %d (esperado 2)", ag2.trust.maxVersion)
	}
	if _, err := sign.VerifyJobAny(ag2.confianca(), sjRev, agentID, ag2.now()); !errors.Is(err, sign.ErrSignature) {
		t.Fatalf("após reinício, operador revogado voltou: %v", err)
	}
	if err := ag2.IngerirListaSigners(raw1, sig1); !errors.Is(err, sign.ErrListaVersao) {
		t.Fatalf("após reinício, downgrade aceito: %v", err)
	}
}
