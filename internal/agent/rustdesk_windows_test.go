//go:build windows

package agent

import (
	"context"
	"io"
	"log/slog"
	"net"
	"testing"
)

// As chamadas ao RustDesk rodam na conta LocalService via schtasks (precisa do
// ambiente real do Windows), então aqui testamos só as travas fail-closed, que
// não dependem disso.

func TestRustDeskMediaSemSenha(t *testing.T) {
	m := &rustdeskMedia{log: slog.New(slog.NewTextHandler(io.Discard, nil)), exe: `C:\Program Files\RustDesk\RustDesk.exe`, host: "h", key: "k"}
	_, ag := net.Pipe()
	if err := m.Serve(context.Background(), ag, "view", ""); err == nil {
		t.Fatal("deveria recusar sessão sem senha de uso único")
	}
}

func TestRustDeskMediaSemServidor(t *testing.T) {
	m := &rustdeskMedia{log: slog.New(slog.NewTextHandler(io.Discard, nil)), exe: `C:\Program Files\RustDesk\RustDesk.exe`}
	_, ag := net.Pipe()
	if err := m.Serve(context.Background(), ag, "view", "otp"); err == nil {
		t.Fatal("deveria recusar sem host/chave do servidor no bundle")
	}
}
