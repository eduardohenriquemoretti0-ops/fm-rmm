// Package sign assina e verifica jobs com Ed25519.
//
// A chave privada fica com o ADMINISTRADOR, fora do servidor: um servidor
// comprometido não consegue fabricar job que o agente aceite.
package sign

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"os"
	"time"

	"github.com/eduardohenriquemoretti0-ops/fm-rmm/internal/proto"
)

// KeyID é a impressão curta da chave pública (16 hex).
func KeyID(pub ed25519.PublicKey) string {
	h := sha256.Sum256(pub)
	return hex.EncodeToString(h[:8])
}

// GenerateKey cria o par e grava a privada em PEM (0600). Recusa sobrescrever.
func GenerateKey(path string) (ed25519.PublicKey, error) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}
	der, err := x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		return nil, err
	}
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	if err := pem.Encode(f, &pem.Block{Type: "PRIVATE KEY", Bytes: der}); err != nil {
		return nil, err
	}
	return pub, f.Close()
}

func LoadPrivate(path string) (ed25519.PrivateKey, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	blk, _ := pem.Decode(b)
	if blk == nil {
		return nil, errors.New("chave de assinatura: PEM inválido")
	}
	k, err := x509.ParsePKCS8PrivateKey(blk.Bytes)
	if err != nil {
		return nil, err
	}
	priv, ok := k.(ed25519.PrivateKey)
	if !ok {
		return nil, errors.New("chave de assinatura não é Ed25519")
	}
	return priv, nil
}

func EncodePub(pub ed25519.PublicKey) string { return base64.StdEncoding.EncodeToString(pub) }

func DecodePub(s string) (ed25519.PublicKey, error) {
	b, err := base64.StdEncoding.DecodeString(s)
	if err != nil || len(b) != ed25519.PublicKeySize {
		return nil, errors.New("chave pública Ed25519 inválida")
	}
	return ed25519.PublicKey(b), nil
}

// SignJob serializa e assina o payload.
func SignJob(priv ed25519.PrivateKey, p proto.JobPayload) (proto.SignedJob, error) {
	raw, err := json.Marshal(p)
	if err != nil {
		return proto.SignedJob{}, err
	}
	pub := priv.Public().(ed25519.PublicKey)
	return proto.SignedJob{Payload: raw, Sig: ed25519.Sign(priv, raw), KeyID: KeyID(pub)}, nil
}

// Erros de verificação (o agente registra o motivo e descarta o job).
var (
	ErrSignature = errors.New("assinatura inválida")
	ErrVersion   = errors.New("versão de protocolo desconhecida")
	ErrAgent     = errors.New("job destinado a outro agente")
	ErrExpired   = errors.New("job expirado")
	ErrNotYet    = errors.New("job emitido no futuro")
	ErrTTL       = errors.New("validade do job acima do máximo")
	ErrMalformed = errors.New("job malformado")
)

// VerifyJob confere assinatura contra UMA chave e o restante das regras.
// Equivale a VerifyJobAny(SingleKey(pub), ...).
func VerifyJob(pub ed25519.PublicKey, sj proto.SignedJob, agentID string, now time.Time) (proto.JobPayload, error) {
	return VerifyJobAny(SingleKey(pub), sj, agentID, now)
}

// VerifyJobAny confere assinatura contra QUALQUER chave usável do trust-set,
// versão, destino e janela de validade. NÃO confere replay nem catálogo: isso
// é do agente (estado local).
func VerifyJobAny(ts TrustSet, sj proto.SignedJob, agentID string, now time.Time) (proto.JobPayload, error) {
	var p proto.JobPayload
	if !ts.assina(sj.Payload, sj.Sig, now) {
		return p, ErrSignature
	}
	if err := json.Unmarshal(sj.Payload, &p); err != nil {
		return p, fmt.Errorf("%w: %v", ErrMalformed, err)
	}
	if p.V != proto.Version {
		return p, ErrVersion
	}
	if p.JobID == "" || p.Action == "" {
		return p, ErrMalformed
	}
	if p.AgentID != agentID {
		return p, ErrAgent
	}
	if p.ExpiresAt.Sub(p.IssuedAt) > proto.MaxJobTTL || !p.ExpiresAt.After(p.IssuedAt) {
		return p, ErrTTL
	}
	if p.IssuedAt.After(now.Add(proto.ClockSkew)) {
		return p, ErrNotYet
	}
	if now.After(p.ExpiresAt.Add(proto.ClockSkew)) {
		return p, ErrExpired
	}
	return p, nil
}
