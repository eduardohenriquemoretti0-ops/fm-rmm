package agent

import (
	"bytes"
	"context"
	"errors"
	"image"
	"image/color"
	"image/png"
	"io"
	"log/slog"
	"net"
	"testing"
	"time"
)

// pngFake gera um PNG pequeno de verdade (para o teste não depender de display).
func pngFake(t *testing.T) []byte {
	t.Helper()
	img := image.NewRGBA(image.Rect(0, 0, 8, 8))
	img.Set(1, 1, color.RGBA{255, 0, 0, 255})
	var buf bytes.Buffer
	if err := png.Encode(&buf, img); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

// A mídia de visualização envia quadros que o console lê de volta intactos.
func TestScreenMediaFrames(t *testing.T) {
	frame := pngFake(t)
	m := &screenMedia{log: slog.New(slog.NewTextHandler(io.Discard, nil)), interval: 20 * time.Millisecond, capture: func() ([]byte, error) { return frame, nil }}
	cons, ag := net.Pipe()
	ctx, cancel := context.WithCancel(context.Background())
	go func() { _ = m.Serve(ctx, ag, "view", "") }()

	for i := 0; i < 3; i++ {
		cons.SetReadDeadline(time.Now().Add(2 * time.Second))
		got, err := ReadFrame(cons)
		if err != nil {
			t.Fatalf("quadro %d: %v", i, err)
		}
		if !bytes.Equal(got, frame) {
			t.Fatalf("quadro %d difere do original", i)
		}
		if _, err := png.Decode(bytes.NewReader(got)); err != nil {
			t.Fatalf("quadro %d não é PNG válido: %v", i, err)
		}
	}
	cancel()
	cons.Close()
}

// Sem captura disponível, a sessão encerra com erro — nunca envia quadro falso.
func TestScreenMediaFailClosed(t *testing.T) {
	m := &screenMedia{log: slog.New(slog.NewTextHandler(io.Discard, nil)), interval: time.Second,
		capture: func() ([]byte, error) { return nil, errors.New("sem display") }}
	cons, ag := net.Pipe()
	defer cons.Close()
	errc := make(chan error, 1)
	go func() { errc <- m.Serve(context.Background(), ag, "view", "") }()
	select {
	case err := <-errc:
		if err == nil {
			t.Fatal("deveria falhar sem captura")
		}
	case <-time.After(2 * time.Second):
		t.Fatal("Serve não retornou")
	}
}

// Modo controle ainda não é suportado: recusa explícita (não finge).
func TestScreenMediaControleRecusa(t *testing.T) {
	m := &screenMedia{log: slog.New(slog.NewTextHandler(io.Discard, nil)), interval: time.Second,
		capture: func() ([]byte, error) { return pngFake(t), nil }}
	_, ag := net.Pipe()
	if err := m.Serve(context.Background(), ag, "control", ""); err == nil {
		t.Fatal("modo controle deveria ser recusado")
	}
}
