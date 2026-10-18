package server

import (
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/eduardohenriquemoretti0-ops/fm-rmm/internal/catalog"
	"github.com/eduardohenriquemoretti0-ops/fm-rmm/internal/proto"
	"github.com/eduardohenriquemoretti0-ops/fm-rmm/internal/sign"
)

// Arquivos do diretório do servidor.
const (
	FileCA      = "ca.crt"
	FileCAKey   = "ca.key"
	FileCert    = "server.crt"
	FileKey     = "server.key"
	FileDB      = "fmrmm.db"
	FileSigners = "signers.json"
)

// Signers: chaves públicas de administrador aceitas (key_id -> base64).
func LoadSigners(dir string) (map[string]ed25519.PublicKey, error) {
	var raw map[string]string
	b, err := os.ReadFile(filepath.Join(dir, FileSigners))
	if errors.Is(err, os.ErrNotExist) {
		return map[string]ed25519.PublicKey{}, nil
	}
	if err != nil {
		return nil, err
	}
	if err := json.Unmarshal(b, &raw); err != nil {
		return nil, err
	}
	out := map[string]ed25519.PublicKey{}
	for id, s := range raw {
		pub, err := sign.DecodePub(s)
		if err != nil {
			return nil, err
		}
		if sign.KeyID(pub) != id {
			return nil, fmt.Errorf("signers.json: key_id %s não confere com a chave", id)
		}
		out[id] = pub
	}
	return out, nil
}

func AddSigner(dir string, pub ed25519.PublicKey) error {
	cur, err := LoadSigners(dir)
	if err != nil {
		return err
	}
	cur[sign.KeyID(pub)] = pub
	raw := map[string]string{}
	for id, p := range cur {
		raw[id] = sign.EncodePub(p)
	}
	b, _ := json.MarshalIndent(raw, "", "  ")
	tmp := filepath.Join(dir, FileSigners+".tmp")
	if err := os.WriteFile(tmp, b, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, filepath.Join(dir, FileSigners))
}

// NewJob valida no catálogo (para o sistema do agente), assina com a chave
// do administrador e enfileira. A chave do servidor não participa.
func NewJob(st *Store, priv ed25519.PrivateKey, signers map[string]ed25519.PublicKey, agentID, action string, params map[string]string, ttl time.Duration, issuer string) (string, error) {
	if ttl <= 0 || ttl > proto.MaxJobTTL {
		return "", fmt.Errorf("validade deve estar entre 1s e %s", proto.MaxJobTTL)
	}
	if _, ok := signers[sign.KeyID(priv.Public().(ed25519.PublicKey))]; !ok {
		return "", errors.New("esta chave de administrador não está cadastrada no servidor (bundle --signer-pub)")
	}
	a, err := st.Agent(agentID)
	if err != nil {
		return "", fmt.Errorf("agente %s: %w", agentID, err)
	}
	if a.Status != "approved" {
		return "", fmt.Errorf("agente %s está %s", agentID, a.Status)
	}
	if _, err := catalog.Validate(action, a.OS, params); err != nil {
		return "", err
	}
	now := time.Now().UTC()
	p := proto.JobPayload{
		V: proto.Version, JobID: "job-" + randHex(8), AgentID: agentID, Action: action, Params: params,
		IssuedAt: now, ExpiresAt: now.Add(ttl), Issuer: issuer,
	}
	sj, err := sign.SignJob(priv, p)
	if err != nil {
		return "", err
	}
	signed, _ := json.Marshal(sj)
	pj, _ := json.Marshal(params)
	if err := st.AddJob(Job{ID: p.JobID, AgentID: agentID, Action: action, Params: string(pj), Signed: string(signed), Issuer: issuer, ExpiresAt: p.ExpiresAt.Unix()}); err != nil {
		return "", err
	}
	return p.JobID, st.Audit("job.criado", issuer, map[string]any{"job": p.JobID, "agente": agentID, "acao": action, "params": params, "chave": sj.KeyID})
}
