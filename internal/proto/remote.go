package proto

import "time"

// Mensagens do acesso remoto autorizado (classe TeamViewer/AnyDesk,
// self-hosted). O agente só abre uma sessão quando recebe uma CONCESSÃO
// assinada pelo administrador; a sessão sempre mostra o indicador visível.
//
// NÃO existe modo de captura oculta: a concessão não tem campo para desligar
// o indicador. Isso é decisão de projeto (ver README, seção de escopo).

// Modos de sessão. Só estes; "oculto" não existe de propósito.
const (
	ModeView    = "view"    // só visualização da tela (read-only)
	ModeControl = "control" // visualização + teclado/mouse
)

// Motores de mídia. "screenshot" = captura em quadros pelo nosso relay (Linux/
// macOS). "rustdesk" = RustDesk self-hosted endurecido (resolve Session 0 no
// Windows); os pixels passam pelo hbbr do RustDesk, não pelo nosso relay.
const (
	EngineScreenshot = "screenshot"
	EngineRustDesk   = "rustdesk"
)

// RemoteGrant é o que o administrador assina para autorizar UMA sessão.
// Curta (minutos), para um agente e um técnico específicos.
type RemoteGrant struct {
	V           int       `json:"v"`
	SessionID   string    `json:"session_id"`
	AgentID     string    `json:"agent_id"`
	Technician  string    `json:"technician"`             // quem vai acessar (auditoria)
	Mode        string    `json:"mode"`                   // view | control
	Engine      string    `json:"engine"`                 // screenshot | rustdesk
	MediaSecret string    `json:"media_secret,omitempty"` // rustdesk: senha de uso único da sessão
	RelayURL    string    `json:"relay_url"`              // wss:// do relay desta sessão (canal de controle)
	RelayToken  string    `json:"relay_token"`            // pareia as duas pontas no relay
	IssuedAt    time.Time `json:"issued_at"`
	ExpiresAt   time.Time `json:"expires_at"`
	Issuer      string    `json:"issuer"`
}

// MaxGrantTTL: uma concessão de sessão vale no máximo isto.
const MaxGrantTTL = 30 * time.Minute

// SignedGrant viaja do servidor ao agente pelo canal de check-in.
type SignedGrant struct {
	Payload []byte `json:"payload"` // bytes exatos de RemoteGrant, assinados
	Sig     []byte `json:"sig"`
	KeyID   string `json:"key_id"`
}

// SessionEvent é o que o agente reporta sobre a sessão (vai para a auditoria).
type SessionEvent struct {
	SessionID string    `json:"session_id"`
	Event     string    `json:"event"` // iniciada | indicador_on | encerrada | recusada
	Detail    string    `json:"detail,omitempty"`
	At        time.Time `json:"at"`
}
