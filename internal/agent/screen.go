package agent

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"time"
)

// screenMedia é o plano de mídia de VISUALIZAÇÃO (modo view): captura a tela
// em quadros PNG e os envia pelo relay. Sempre read-only — não injeta teclado
// nem mouse. O indicador de sessão já está aceso quando isto roda.
//
// Captura real depende do SO ter como fotografar a tela da sessão interativa.
// Onde não dá (ex.: serviço em Session 0 no Windows, sem helper de desktop),
// a captura falha e a sessão encerra com motivo claro — nunca envia quadro
// falso. O caminho de controle (input) e a captura via Session 0 no Windows
// são o que se resolve integrando um motor endurecido (RustDesk).
type screenMedia struct {
	log      *slog.Logger
	interval time.Duration
	capture  func() ([]byte, error) // troca nos testes; padrão: captureScreen
}

// NewScreenMedia cria o plano de mídia de visualização (um quadro por `every`).
func NewScreenMedia(log *slog.Logger, every time.Duration) SessionMedia {
	if every <= 0 {
		every = time.Second
	}
	return &screenMedia{log: log, interval: every, capture: captureScreen}
}

// protocolo de quadro: 4 bytes big-endian com o tamanho, seguidos do PNG.
const maxFrame = 16 << 20

func (m *screenMedia) Serve(ctx context.Context, conn net.Conn, mode, _ string) error {
	if mode != "view" {
		// controle (input) ainda não implementado: recusa explícita, não finge
		return errors.New("modo controle ainda não suportado (integrar motor de mídia)")
	}
	// primeiro quadro já valida que a captura funciona; se não, encerra claro
	first, err := m.capture()
	if err != nil {
		return fmt.Errorf("captura de tela indisponível: %w", err)
	}
	if err := writeFrame(conn, first); err != nil {
		return err
	}
	t := time.NewTicker(m.interval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-t.C:
			img, err := m.capture()
			if err != nil {
				m.log.Warn("captura falhou no meio da sessão", "erro", err)
				return err
			}
			if err := writeFrame(conn, img); err != nil {
				return err // console desconectou
			}
		}
	}
}

func writeFrame(conn net.Conn, img []byte) error {
	if len(img) > maxFrame {
		return fmt.Errorf("quadro grande demais: %d bytes", len(img))
	}
	var hdr [4]byte
	binary.BigEndian.PutUint32(hdr[:], uint32(len(img)))
	if err := conn.SetWriteDeadline(time.Now().Add(15 * time.Second)); err != nil {
		return err
	}
	if _, err := conn.Write(hdr[:]); err != nil {
		return err
	}
	_, err := conn.Write(img)
	return err
}

// ReadFrame lê um quadro do fluxo (usado pelo visualizador do console).
func ReadFrame(r io.Reader) ([]byte, error) {
	var hdr [4]byte
	if _, err := io.ReadFull(r, hdr[:]); err != nil {
		return nil, err
	}
	n := binary.BigEndian.Uint32(hdr[:])
	if n > maxFrame {
		return nil, fmt.Errorf("quadro grande demais: %d", n)
	}
	buf := make([]byte, n)
	if _, err := io.ReadFull(r, buf); err != nil {
		return nil, err
	}
	return buf, nil
}
