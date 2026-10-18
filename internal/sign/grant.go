package sign

import (
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"time"

	"github.com/eduardohenriquemoretti0-ops/fm-rmm/internal/proto"
)

// Assina e verifica concessões de sessão remota, com a mesma chave de
// administrador (fora do servidor) usada nos jobs.

var (
	ErrGrantMode = errors.New("modo de sessão inválido")
	ErrEngine    = errors.New("motor de mídia inválido")
	ErrGrantTTL  = errors.New("validade da concessão acima do máximo")
	ErrRelay     = errors.New("concessão sem relay")
)

func SignGrant(priv ed25519.PrivateKey, g proto.RemoteGrant) (proto.SignedGrant, error) {
	raw, err := json.Marshal(g)
	if err != nil {
		return proto.SignedGrant{}, err
	}
	pub := priv.Public().(ed25519.PublicKey)
	return proto.SignedGrant{Payload: raw, Sig: ed25519.Sign(priv, raw), KeyID: KeyID(pub)}, nil
}

// VerifyGrant confere assinatura, modo, destino, relay e janela de validade.
// Rejeita qualquer modo que não seja view/control (não há modo oculto).
func VerifyGrant(pub ed25519.PublicKey, sg proto.SignedGrant, agentID string, now time.Time) (proto.RemoteGrant, error) {
	var g proto.RemoteGrant
	if len(sg.Sig) != ed25519.SignatureSize || !ed25519.Verify(pub, sg.Payload, sg.Sig) {
		return g, ErrSignature
	}
	if err := json.Unmarshal(sg.Payload, &g); err != nil {
		return g, ErrMalformed
	}
	if g.V != proto.Version {
		return g, ErrVersion
	}
	if g.SessionID == "" || g.Technician == "" {
		return g, ErrMalformed
	}
	if g.AgentID != agentID {
		return g, ErrAgent
	}
	if g.Mode != proto.ModeView && g.Mode != proto.ModeControl {
		return g, ErrGrantMode
	}
	if g.Engine != proto.EngineScreenshot && g.Engine != proto.EngineRustDesk {
		return g, ErrEngine
	}
	if g.Engine == proto.EngineRustDesk && g.MediaSecret == "" {
		return g, ErrMalformed // rustdesk exige senha de uso único
	}
	if g.RelayURL == "" || g.RelayToken == "" {
		return g, ErrRelay
	}
	if g.ExpiresAt.Sub(g.IssuedAt) > proto.MaxGrantTTL || !g.ExpiresAt.After(g.IssuedAt) {
		return g, ErrGrantTTL
	}
	if g.IssuedAt.After(now.Add(proto.ClockSkew)) {
		return g, ErrNotYet
	}
	if now.After(g.ExpiresAt.Add(proto.ClockSkew)) {
		return g, ErrExpired
	}
	return g, nil
}
