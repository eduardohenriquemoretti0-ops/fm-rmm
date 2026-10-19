package sign

import (
	"crypto/ed25519"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/eduardohenriquemoretti0-ops/fm-rmm/internal/proto"
)

// entradaTeste monta um signer a partir de uma chave pública.
func entradaTeste(pub ed25519.PublicKey, role string, notAfter *time.Time) SignerEntry {
	return SignerEntry{KeyID: KeyID(pub), Pub: EncodePub(pub), Role: role, NotAfter: notAfter}
}

func TestListaRoundTrip(t *testing.T) {
	raizPub, raizPriv := keypair(t)
	opPub, _ := keypair(t)
	issued := time.Date(2026, 10, 19, 12, 0, 0, 0, time.UTC)
	l := SignerList{Version: 1, IssuedAt: issued, Signers: []SignerEntry{entradaTeste(opPub, RoleOperator, nil)}}

	raw, sig, err := SignSignerList(raizPriv, l)
	if err != nil {
		t.Fatal(err)
	}
	back, err := ParseSignerList(raizPub, raw, sig)
	if err != nil {
		t.Fatalf("lista válida recusada: %v", err)
	}
	if back.Version != 1 || len(back.Signers) != 1 || back.Signers[0].Pub != EncodePub(opPub) {
		t.Fatalf("conteúdo diferente após ida e volta: %+v", back)
	}
}

func TestListaCanonicaDeterministica(t *testing.T) {
	a, _ := keypair(t)
	b, _ := keypair(t)
	issued := time.Date(2026, 10, 19, 12, 0, 0, 123, time.FixedZone("BRT", -3*3600))
	ordem1 := SignerList{Version: 2, IssuedAt: issued, Signers: []SignerEntry{entradaTeste(a, RoleOperator, nil), entradaTeste(b, RoleAdmin, nil)}}
	ordem2 := SignerList{Version: 2, IssuedAt: issued.UTC(), Signers: []SignerEntry{entradaTeste(b, RoleAdmin, nil), entradaTeste(a, RoleOperator, nil)}}

	r1, err := CanonicalSignerList(ordem1)
	if err != nil {
		t.Fatal(err)
	}
	r2, err := CanonicalSignerList(ordem2)
	if err != nil {
		t.Fatal(err)
	}
	if string(r1) != string(r2) {
		t.Fatalf("forma canônica depende da ordem/fuso:\n%s\n%s", r1, r2)
	}
	if len(ordem1.Signers) != 2 || ordem1.Signers[0].KeyID != KeyID(a) {
		t.Fatal("CanonicalSignerList alterou a entrada")
	}
}

func TestListaForjadaRecusada(t *testing.T) {
	raizPub, _ := keypair(t)
	_, intrusoPriv := keypair(t)
	opPub, _ := keypair(t)
	l := SignerList{Version: 1, IssuedAt: time.Now().UTC(), Signers: []SignerEntry{entradaTeste(opPub, RoleOperator, nil)}}

	raw, sig, err := SignSignerList(intrusoPriv, l) // assinada por chave que NÃO é a raiz
	if err != nil {
		t.Fatal(err)
	}
	if _, err := ParseSignerList(raizPub, raw, sig); !errors.Is(err, ErrListaAssinatura) {
		t.Fatalf("lista forjada: esperado ErrListaAssinatura, veio %v", err)
	}
}

func TestListaAdulteradaRecusada(t *testing.T) {
	raizPub, raizPriv := keypair(t)
	opPub, _ := keypair(t)
	outro, _ := keypair(t)
	l := SignerList{Version: 1, IssuedAt: time.Now().UTC(), Signers: []SignerEntry{entradaTeste(opPub, RoleOperator, nil)}}
	raw, sig, err := SignSignerList(raizPriv, l)
	if err != nil {
		t.Fatal(err)
	}
	trocado := strings.Replace(string(raw), EncodePub(opPub), EncodePub(outro), 1)
	trocado = strings.Replace(trocado, KeyID(opPub), KeyID(outro), 1)
	if _, err := ParseSignerList(raizPub, []byte(trocado), sig); !errors.Is(err, ErrListaAssinatura) {
		t.Fatalf("bytes trocados: esperado ErrListaAssinatura, veio %v", err)
	}
	if _, err := ParseSignerList(raizPub, raw, nil); !errors.Is(err, ErrListaAssinatura) {
		t.Fatalf("sem assinatura: esperado ErrListaAssinatura, veio %v", err)
	}
}

func TestListaNaoCanonicaRecusada(t *testing.T) {
	raizPub, raizPriv := keypair(t)
	l := SignerList{Version: 1, IssuedAt: time.Now().UTC()}
	raw, err := CanonicalSignerList(l)
	if err != nil {
		t.Fatal(err)
	}
	// mesma lista, com espaço extra: assinada pela raiz, mas não é a forma canônica
	variante := []byte(strings.Replace(string(raw), `{"version"`, `{ "version"`, 1))
	sig := ed25519.Sign(raizPriv, variante)
	if _, err := ParseSignerList(raizPub, variante, sig); !errors.Is(err, ErrListaMalformada) {
		t.Fatalf("forma não canônica: esperado ErrListaMalformada, veio %v", err)
	}
}

func TestListaMalformadaRecusada(t *testing.T) {
	raizPub, raizPriv := keypair(t)
	opPub, _ := keypair(t)
	agora := time.Now().UTC()
	casos := map[string]SignerList{
		"versão zero":      {Version: 0, IssuedAt: agora},
		"sem issued_at":    {Version: 1},
		"papel inválido":   {Version: 1, IssuedAt: agora, Signers: []SignerEntry{{KeyID: KeyID(opPub), Pub: EncodePub(opPub), Role: "root"}}},
		"key_id trocado":   {Version: 1, IssuedAt: agora, Signers: []SignerEntry{{KeyID: "0123456789abcdef", Pub: EncodePub(opPub), Role: RoleOperator}}},
		"pub inválida":     {Version: 1, IssuedAt: agora, Signers: []SignerEntry{{KeyID: "x", Pub: "não-é-base64!", Role: RoleOperator}}},
		"signer duplicado": {Version: 1, IssuedAt: agora, Signers: []SignerEntry{entradaTeste(opPub, RoleOperator, nil), entradaTeste(opPub, RoleOperator, nil)}},
	}
	for nome, l := range casos {
		t.Run(nome, func(t *testing.T) {
			if _, err := CanonicalSignerList(l); !errors.Is(err, ErrListaMalformada) {
				t.Fatalf("CanonicalSignerList: esperado ErrListaMalformada, veio %v", err)
			}
			if _, _, err := SignSignerList(raizPriv, l); !errors.Is(err, ErrListaMalformada) {
				t.Fatalf("SignSignerList: esperado ErrListaMalformada, veio %v", err)
			}
		})
	}

	// campo desconhecido, assinado pela raiz: recusado pelo decodificador estrito
	raw := []byte(`{"version":1,"issued_at":"2026-10-19T12:00:00Z","signers":[],"extra":1}`)
	if _, err := ParseSignerList(raizPub, raw, ed25519.Sign(raizPriv, raw)); !errors.Is(err, ErrListaMalformada) {
		t.Fatalf("campo extra: esperado ErrListaMalformada, veio %v", err)
	}
}

func TestTrustSetValidadeDosSignatarios(t *testing.T) {
	raizPub, raizPriv := keypair(t)
	ativoPub, _ := keypair(t)
	vencidoPub, _ := keypair(t)
	now := time.Date(2026, 10, 19, 12, 0, 0, 0, time.UTC)
	futuro := now.Add(time.Hour)
	passado := now.Add(-time.Hour)
	l := SignerList{Version: 1, IssuedAt: now, Signers: []SignerEntry{
		entradaTeste(ativoPub, RoleOperator, &futuro),
		entradaTeste(vencidoPub, RoleOperator, &passado),
	}}
	raw, sig, err := SignSignerList(raizPriv, l)
	if err != nil {
		t.Fatal(err)
	}
	parsed, err := ParseSignerList(raizPub, raw, sig)
	if err != nil {
		t.Fatal(err)
	}
	ts, err := TrustFromList(raizPub, parsed, now)
	if err != nil {
		t.Fatal(err)
	}
	// raiz + ativo; o vencido foi descartado na ingestão
	if len(ts.Keys) != 2 {
		t.Fatalf("esperado raiz+1 operador, veio %d chaves", len(ts.Keys))
	}
	if n := len(ts.Usable(now)); n != 2 {
		t.Fatalf("Usable(now): esperado 2, veio %d", n)
	}
	// ao passar do not_after, o operador ativo deixa de valer mesmo sem nova lista
	if n := len(ts.Usable(futuro.Add(time.Second))); n != 1 {
		t.Fatalf("Usable após not_after: esperado 1 (só a raiz), veio %d", n)
	}
}

func TestVerifyJobAnyOperadorDaLista(t *testing.T) {
	raizPub, raizPriv := keypair(t)
	opPub, opPriv := keypair(t)
	now := time.Now().UTC()
	l := SignerList{Version: 1, IssuedAt: now, Signers: []SignerEntry{entradaTeste(opPub, RoleOperator, nil)}}
	raw, sig, err := SignSignerList(raizPriv, l)
	if err != nil {
		t.Fatal(err)
	}
	parsed, err := ParseSignerList(raizPub, raw, sig)
	if err != nil {
		t.Fatal(err)
	}
	ts, err := TrustFromList(raizPub, parsed, now)
	if err != nil {
		t.Fatal(err)
	}

	sjOp, err := SignJob(opPriv, payload(now))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := VerifyJobAny(ts, sjOp, "ag-1", now); err != nil {
		t.Fatalf("job do operador da lista recusado: %v", err)
	}
	if _, err := VerifyJob(raizPub, sjOp, "ag-1", now); !errors.Is(err, ErrSignature) {
		t.Fatalf("VerifyJob (só raiz) deveria recusar o operador: %v", err)
	}
	sjRaiz, _ := SignJob(raizPriv, payload(now))
	if _, err := VerifyJobAny(ts, sjRaiz, "ag-1", now); err != nil {
		t.Fatalf("job da raiz recusado: %v", err)
	}
	var zero TrustSet
	if _, err := VerifyJobAny(zero, sjRaiz, "ag-1", now); !errors.Is(err, ErrSignature) {
		t.Fatalf("trust-set vazio deveria recusar tudo: %v", err)
	}
}

func TestVerifyGrantAnyOperadorDaLista(t *testing.T) {
	raizPub, _ := keypair(t)
	opPub, opPriv := keypair(t)
	now := time.Now().UTC()
	g := proto.RemoteGrant{V: proto.Version, SessionID: "s1", AgentID: "ag-1", Technician: "joao",
		Mode: proto.ModeView, Engine: proto.EngineScreenshot, RelayURL: "wss://relay.test", RelayToken: "tok",
		IssuedAt: now, ExpiresAt: now.Add(10 * time.Minute), Issuer: "teste"}
	sg, err := SignGrant(opPriv, g)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := VerifyGrant(raizPub, sg, "ag-1", now); !errors.Is(err, ErrSignature) {
		t.Fatalf("grant do operador sem lista: esperado ErrSignature, veio %v", err)
	}
	ts := TrustSet{Keys: []TrustedKey{{KeyID: KeyID(opPub), Pub: opPub, Role: RoleOperator}}}
	if _, err := VerifyGrantAny(ts, sg, "ag-1", now); err != nil {
		t.Fatalf("grant do operador no trust-set recusado: %v", err)
	}
}

func TestVerifyJobSinglePreservaComportamento(t *testing.T) {
	pub, priv := keypair(t)
	now := time.Now().UTC()
	sj, _ := SignJob(priv, payload(now))
	if _, err := VerifyJob(pub, sj, "ag-1", now); err != nil {
		t.Fatalf("fluxo de uma chave quebrou: %v", err)
	}
	// chave nula ou de tamanho errado não pode causar pânico
	if _, err := VerifyJob(nil, sj, "ag-1", now); !errors.Is(err, ErrSignature) {
		t.Fatalf("chave nula: esperado ErrSignature, veio %v", err)
	}
}
