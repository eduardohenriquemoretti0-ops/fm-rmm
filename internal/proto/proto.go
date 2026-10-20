// Package proto define as mensagens trocadas entre agente e servidor.
//
// Regra central: um job só é executado se o PAYLOAD (bytes exatos) vier
// assinado pela chave Ed25519 do administrador. A assinatura cobre os bytes
// brutos do JSON, então não há ambiguidade de canonicalização.
package proto

import (
	"encoding/json"
	"time"
)

// Versão do protocolo. Agente recusa payload de versão desconhecida.
const Version = 1

// Limites aplicados pelos dois lados.
const (
	MaxJobTTL     = 24 * time.Hour  // validade máxima aceita para um job
	ClockSkew     = 5 * time.Minute // tolerância de relógio entre admin e agente
	MaxOutputSize = 256 * 1024      // saída máxima de uma ação (bytes)
)

// JobPayload é o que o administrador assina.
type JobPayload struct {
	V         int               `json:"v"`
	JobID     string            `json:"job_id"`
	AgentID   string            `json:"agent_id"`
	Action    string            `json:"action"`
	Params    map[string]string `json:"params,omitempty"`
	IssuedAt  time.Time         `json:"issued_at"`
	ExpiresAt time.Time         `json:"expires_at"`
	Issuer    string            `json:"issuer"`
}

// SignedJob viaja do servidor ao agente. Payload são os bytes exatos assinados.
type SignedJob struct {
	Payload json.RawMessage `json:"payload"`
	Sig     []byte          `json:"sig"`
	KeyID   string          `json:"key_id"`
}

// Heartbeat é a telemetria leve enviada em todo check-in.
type Heartbeat struct {
	Hostname     string `json:"hostname"`
	OS           string `json:"os"`
	Arch         string `json:"arch"`
	AgentVersion string `json:"agent_version"`
	UptimeSec    int64  `json:"uptime_sec"`
}

type CheckinRequest struct {
	Heartbeat Heartbeat `json:"heartbeat"`
}

// SignedSignerList é a lista de signers (trust-set do agente) já assinada pela
// chave RAIZ offline. Raw são os bytes canônicos exatos da lista; Sig é a
// assinatura Ed25519 destacada. Ambos viajam em base64 (sem ambiguidade).
type SignedSignerList struct {
	Raw []byte `json:"raw"`
	Sig []byte `json:"sig"`
}

// SignedSoftwareCatalog é o catálogo de software (allow-list) assinado pela
// chave RAIZ offline. Mesmo formato de SignedSignerList.
type SignedSoftwareCatalog struct {
	Raw []byte `json:"raw"`
	Sig []byte `json:"sig"`
}

// SignedScriptLibrary é a biblioteca de scripts assinada pela chave RAIZ
// offline. Mesmo formato de SignedSoftwareCatalog.
type SignedScriptLibrary struct {
	Raw []byte `json:"raw"`
	Sig []byte `json:"sig"`
}

type CheckinResponse struct {
	Jobs        []SignedJob   `json:"jobs"`
	Grants      []SignedGrant `json:"grants,omitempty"` // sessões remotas autorizadas
	IntervalSec int           `json:"interval_sec"`
	// Lista é a lista de signers corrente (omitida se o servidor ainda não tem uma).
	// O agente ingere e aplica anti-downgrade; lista repetida é o caso normal.
	Lista *SignedSignerList `json:"lista,omitempty"`
	// Software é o catálogo de software corrente (omitido se não há). O agente
	// verifica contra a raiz e aplica anti-downgrade; repetido é o caso normal.
	Software *SignedSoftwareCatalog `json:"software,omitempty"`
	// Scripts é a biblioteca de scripts corrente (omitida se não há): raiz + anti-downgrade.
	Scripts *SignedScriptLibrary `json:"scripts,omitempty"`
}

// Result é o retorno de um job. Autenticado pelo mTLS do agente.
type Result struct {
	JobID      string    `json:"job_id"`
	Status     string    `json:"status"` // ok | erro | recusado
	ExitCode   int       `json:"exit_code"`
	Output     string    `json:"output"`
	Truncated  bool      `json:"truncated"`
	Error      string    `json:"error,omitempty"`
	StartedAt  time.Time `json:"started_at"`
	FinishedAt time.Time `json:"finished_at"`
	// Escrow acompanha o resultado de forcar_criptografia: SÓ ciphertext + metadados.
	Escrow *EscrowRecord `json:"escrow,omitempty"`
}

// EscrowRecord é a chave de recuperação SELADA (nacl SealAnonymous, base64) para
// a EscrowPub do admin. O servidor só guarda isto; a chave em claro nunca sai
// do agente.
type EscrowRecord struct {
	Volume string `json:"volume"`
	Metodo string `json:"metodo"` // bitlocker | filevault
	Blob   string `json:"blob"`   // base64 do ciphertext
}

type EnrollRequest struct {
	Token    string `json:"token"`
	CSRPEM   string `json:"csr_pem"`
	Hostname string `json:"hostname"`
	OS       string `json:"os"`
}

type EnrollResponse struct {
	AgentID    string `json:"agent_id"`
	PollSecret string `json:"poll_secret"`
}

type EnrollStatusRequest struct {
	AgentID    string `json:"agent_id"`
	PollSecret string `json:"poll_secret"`
}

type EnrollStatusResponse struct {
	Status  string `json:"status"` // pending | approved | rejected | revoked
	CertPEM string `json:"cert_pem,omitempty"`
}

// Bundle é o pacote público entregue junto com o instalador do agente.
type Bundle struct {
	ServerURL string `json:"server_url"`
	CAPEM     string `json:"ca_pem"`
	SignerPub string `json:"signer_pub"` // Ed25519, base64
	SignerID  string `json:"signer_id"`
	// EscrowPub: chave pública X25519 (base64) do admin para selar chaves de
	// recuperação de disco (a privada, escrow.key, fica offline). Opcional.
	EscrowPub string `json:"escrow_pub,omitempty"`
	// RustDesk self-hosted endurecido (opcional; só se o acesso remoto usa rustdesk).
	// Pinning: o agente e o console só falam com ESTE rendezvous/relay e com esta chave.
	RustDeskHost string `json:"rustdesk_host,omitempty"` // host do hbbs (ex.: 10.0.2.2)
	RustDeskKey  string `json:"rustdesk_key,omitempty"`  // chave pública do hbbs (base64)
}
