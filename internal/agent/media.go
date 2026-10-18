package agent

import (
	"context"
	"fmt"
	"log/slog"
	"net"
	"time"
)

// handshakeMedia é o plano de mídia PADRÃO do PoC. Ele NÃO captura tela nem
// injeta input: apenas abre o canal sobre o relay e mantém a sessão, provando
// o caminho autorizado ponta a ponta (concessão -> indicador -> relay).
//
// O plano de mídia real (tela/input/arquivo) é integração com um motor
// endurecido (ex.: RustDesk), encaixado aqui sem reescrever codec/NAT/cripto —
// como recomenda o brief. Troque por sua implementação de SessionMedia.
type handshakeMedia struct{ log *slog.Logger }

// NewPlaceholderMedia devolve o plano de mídia padrão do PoC.
func NewPlaceholderMedia(log *slog.Logger) SessionMedia { return &handshakeMedia{log: log} }

func (m *handshakeMedia) Serve(ctx context.Context, conn net.Conn, mode, _ string) error {
	banner := fmt.Sprintf("FM-RMM/1 session mode=%s (plano de mídia real: integrar motor endurecido)\n", mode)
	if err := conn.SetWriteDeadline(time.Now().Add(10 * time.Second)); err != nil {
		return err
	}
	if _, err := conn.Write([]byte(banner)); err != nil {
		return err
	}
	_ = conn.SetWriteDeadline(time.Time{})
	m.log.Info("plano de mídia placeholder ativo", "modo", mode)
	// mantém a sessão viva até expirar/cancelar ou a outra ponta fechar
	go func() {
		buf := make([]byte, 4096)
		for {
			if _, err := conn.Read(buf); err != nil {
				return
			}
		}
	}()
	<-ctx.Done()
	return ctx.Err()
}
