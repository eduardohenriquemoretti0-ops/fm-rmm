//go:build windows

package agent

import (
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// Testa o motor RustDesk com um rustdesk.exe FALSO (script .bat que imprime um
// ID e aceita as flags). Verifica que a sessão arma, reporta o ID pelo canal de
// controle e NÃO exige o nosso relay para os pixels.
func TestRustDeskMediaArma(t *testing.T) {
	dir := t.TempDir()
	fake := filepath.Join(dir, "rustdesk.bat")
	// --get-id imprime um id fixo; as demais flags saem 0
	script := "@echo off\r\nif \"%1\"==\"--get-id\" (echo 123456789) else (exit /b 0)\r\n"
	if err := os.WriteFile(fake, []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	m := &rustdeskMedia{log: slog.New(slog.NewTextHandler(io.Discard, nil)), exe: fake, host: "10.0.2.2", key: "CHAVE="}
	cons, ag := net.Pipe()
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	go func() { _ = m.Serve(ctx, ag, "view", "senha-otp") }()

	cons.SetReadDeadline(time.Now().Add(3 * time.Second))
	frame, err := ReadFrame(cons)
	if err != nil {
		t.Fatalf("não recebeu metadados do motor: %v", err)
	}
	var meta map[string]string
	if err := json.Unmarshal(frame, &meta); err != nil {
		t.Fatal(err)
	}
	if meta["engine"] != "rustdesk" || meta["id"] != "123456789" || meta["host"] != "10.0.2.2" {
		t.Fatalf("metadados errados: %v", meta)
	}
	cancel()
	cons.Close()
}

// Sem senha de uso único, o motor RustDesk recusa (fail-closed).
func TestRustDeskMediaSemSenha(t *testing.T) {
	m := &rustdeskMedia{log: slog.New(slog.NewTextHandler(io.Discard, nil)), exe: "rustdesk.exe", host: "h", key: "k"}
	_, ag := net.Pipe()
	if err := m.Serve(context.Background(), ag, "view", ""); err == nil {
		t.Fatal("deveria recusar sessão sem senha de uso único")
	}
}
