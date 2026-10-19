//go:build windows

package agent

import (
	"context"
	"io"
	"log/slog"
	"net"
	"testing"
)

// A config do RustDesk é escrita no perfil do LocalService e exige o ambiente
// real do Windows; aqui testamos só as travas fail-closed, que não dependem disso.

func TestRustDeskMediaSemSenha(t *testing.T) {
	m := &rustdeskMedia{log: slog.New(slog.NewTextHandler(io.Discard, nil)), host: "h", key: "k"}
	_, ag := net.Pipe()
	if err := m.Serve(context.Background(), ag, "view", ""); err == nil {
		t.Fatal("deveria recusar sessão sem senha de uso único")
	}
}

func TestRustDeskMediaSemServidor(t *testing.T) {
	m := &rustdeskMedia{log: slog.New(slog.NewTextHandler(io.Discard, nil))}
	_, ag := net.Pipe()
	if err := m.Serve(context.Background(), ag, "view", "otp"); err == nil {
		t.Fatal("deveria recusar sem host/chave do servidor no bundle")
	}
}

func TestDeterministicID(t *testing.T) {
	id := deterministicID()
	if id == "" || len(id) > 16 {
		t.Fatalf("id inválido: %q", id)
	}
	for _, r := range id {
		if !(r >= 'a' && r <= 'z' || r >= '0' && r <= '9') {
			t.Fatalf("id com caractere inválido: %q", id)
		}
	}
}
