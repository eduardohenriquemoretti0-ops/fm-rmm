package sign

import (
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"path/filepath"
	"testing"
	"time"

	"github.com/eduardohenriquemoretti0-ops/fm-rmm/internal/proto"
)

func keypair(t *testing.T) (ed25519.PublicKey, ed25519.PrivateKey) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return pub, priv
}

func payload(now time.Time) proto.JobPayload {
	return proto.JobPayload{V: proto.Version, JobID: "job-1", AgentID: "ag-1", Action: "info",
		IssuedAt: now, ExpiresAt: now.Add(time.Hour), Issuer: "teste"}
}

func TestVerifyJob(t *testing.T) {
	pub, priv := keypair(t)
	otherPub, otherPriv := keypair(t)
	_ = otherPub
	now := time.Now().UTC()

	sj, err := SignJob(priv, payload(now))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := VerifyJob(pub, sj, "ag-1", now); err != nil {
		t.Fatalf("job válido recusado: %v", err)
	}

	tampered := sj
	tampered.Payload = append([]byte{}, sj.Payload...)
	tampered.Payload[len(tampered.Payload)-3] ^= 1
	forged, _ := SignJob(otherPriv, payload(now))

	cases := []struct {
		name string
		sj   proto.SignedJob
		pub  ed25519.PublicKey
		ag   string
		at   time.Time
		want error
	}{
		{"payload alterado", tampered, pub, "ag-1", now, ErrSignature},
		{"assinado por outra chave", forged, pub, "ag-1", now, ErrSignature},
		{"assinatura vazia", proto.SignedJob{Payload: sj.Payload}, pub, "ag-1", now, ErrSignature},
		{"outro agente", sj, pub, "ag-2", now, ErrAgent},
		{"expirado", sj, pub, "ag-1", now.Add(2 * time.Hour), ErrExpired},
		{"emitido no futuro", sj, pub, "ag-1", now.Add(-time.Hour), ErrNotYet},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if _, err := VerifyJob(c.pub, c.sj, c.ag, c.at); !errors.Is(err, c.want) {
				t.Fatalf("esperado %v, veio %v", c.want, err)
			}
		})
	}

	long := payload(now)
	long.ExpiresAt = now.Add(proto.MaxJobTTL + time.Minute)
	sjLong, _ := SignJob(priv, long)
	if _, err := VerifyJob(pub, sjLong, "ag-1", now); !errors.Is(err, ErrTTL) {
		t.Fatalf("validade longa: esperado ErrTTL, veio %v", err)
	}
	badV := payload(now)
	badV.V = 99
	sjV, _ := SignJob(priv, badV)
	if _, err := VerifyJob(pub, sjV, "ag-1", now); !errors.Is(err, ErrVersion) {
		t.Fatalf("versão: esperado ErrVersion, veio %v", err)
	}
	// tolerância de relógio: 4 min de atraso do agente ainda aceita
	if _, err := VerifyJob(pub, sj, "ag-1", now.Add(-4*time.Minute)); err != nil {
		t.Fatalf("tolerância de relógio: %v", err)
	}
}

func TestKeyFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "admin.key")
	pub, err := GenerateKey(path)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := GenerateKey(path); err == nil {
		t.Fatal("GenerateKey sobrescreveu chave existente")
	}
	priv, err := LoadPrivate(path)
	if err != nil {
		t.Fatal(err)
	}
	if !pub.Equal(priv.Public()) {
		t.Fatal("chave lida não confere")
	}
	back, err := DecodePub(EncodePub(pub))
	if err != nil || !back.Equal(pub) {
		t.Fatal("codificação da pública")
	}
}
