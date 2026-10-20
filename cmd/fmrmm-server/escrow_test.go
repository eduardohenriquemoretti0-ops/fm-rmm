package main

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/eduardohenriquemoretti0-ops/fm-rmm/internal/escrow"
	"github.com/eduardohenriquemoretti0-ops/fm-rmm/internal/proto"
	"github.com/eduardohenriquemoretti0-ops/fm-rmm/internal/server"
)

func TestInitGeraEscrowEBundleLevaEscrowPub(t *testing.T) {
	dir := t.TempDir()
	if err := cmdInit([]string{"--dir", dir, "--hosts", "localhost"}); err != nil {
		t.Fatal(err)
	}
	keyPath := filepath.Join(dir, server.FileEscrowKey)
	fi, err := os.Stat(keyPath)
	if err != nil {
		t.Fatalf("init não gerou escrow.key: %v", err)
	}
	if fi.Mode().Perm() != 0o600 {
		t.Fatalf("escrow.key com permissão %v, esperado 0600", fi.Mode().Perm())
	}
	pub, err := escrow.PublicFromPrivate(keyPath)
	if err != nil {
		t.Fatal(err)
	}
	if b, _ := os.ReadFile(filepath.Join(dir, server.FileEscrowPub)); strings.TrimSpace(string(b)) != pub {
		t.Fatal("escrow.pub não confere com a privada")
	}
	// segundo init é recusado e não sobrescreve a chave
	if err := cmdInit([]string{"--dir", dir, "--hosts", "localhost"}); err == nil {
		t.Fatal("init duplicado deveria falhar")
	}

	adm := filepath.Join(t.TempDir(), "admin.key")
	if err := cmdKeygen([]string{"--out", adm}); err != nil {
		t.Fatal(err)
	}
	out := filepath.Join(t.TempDir(), "bundle.json")
	if err := cmdBundle([]string{"--dir", dir, "--url", "https://rmm.exemplo.com", "--key", adm, "--out", out}); err != nil {
		t.Fatal(err)
	}
	var b proto.Bundle
	raw, _ := os.ReadFile(out)
	if err := json.Unmarshal(raw, &b); err != nil {
		t.Fatal(err)
	}
	if b.EscrowPub != pub {
		t.Fatalf("EscrowPub do bundle = %q, esperado %q", b.EscrowPub, pub)
	}
	if strings.Contains(string(raw), "PRIVATE") {
		t.Fatal("bundle contém material privado")
	}
}

func TestEscrowAbrirOffline(t *testing.T) {
	dir := t.TempDir()
	priv := filepath.Join(dir, "escrow.key")
	pub, err := escrow.GenerateKey(priv)
	if err != nil {
		t.Fatal(err)
	}
	blob, _ := escrow.Seal(pub, escrow.Segredo{AgentID: "ag-1", Volume: "C:", Metodo: "bitlocker", Chave: "123456-234567-345678-456789-567890-678901-789012-890123"})

	// via stdin
	var out, errb bytes.Buffer
	if err := cmdEscrowAbrir([]string{"--escrow-key", priv}, strings.NewReader(blob+"\n"), &out, &errb); err != nil {
		t.Fatal(err)
	}
	if strings.TrimSpace(out.String()) != "123456-234567-345678-456789-567890-678901-789012-890123" {
		t.Fatalf("stdout = %q", out.String())
	}
	// via arquivo
	f := filepath.Join(dir, "blob.txt")
	_ = os.WriteFile(f, []byte(blob), 0o600)
	out.Reset()
	if err := cmdEscrowAbrir([]string{"--escrow-key", priv, "--blob", f}, nil, &out, &errb); err != nil || out.Len() == 0 {
		t.Fatalf("arquivo: %v", err)
	}
	// privada errada e blob inválido: falha limpa, nada em stdout
	outra := filepath.Join(dir, "outra.key")
	_, _ = escrow.GenerateKey(outra)
	for nome, args := range map[string][]string{
		"privada errada": {"--escrow-key", outra, "--blob", f},
		"sem arquivo":    {"--escrow-key", filepath.Join(dir, "nao-existe.key"), "--blob", f},
	} {
		out.Reset()
		if err := cmdEscrowAbrir(args, nil, &out, &errb); err == nil || out.Len() != 0 {
			t.Errorf("%s: deveria falhar sem saída (err=%v out=%q)", nome, err, out.String())
		}
	}
	out.Reset()
	if err := cmdEscrowAbrir([]string{"--escrow-key", priv}, strings.NewReader("lixo!!"), &out, &errb); err == nil || out.Len() != 0 {
		t.Errorf("blob inválido: err=%v out=%q", err, out.String())
	}
}

func TestEscrowListarSoCiphertext(t *testing.T) {
	dir := t.TempDir()
	if err := cmdInit([]string{"--dir", dir, "--hosts", "localhost"}); err != nil {
		t.Fatal(err)
	}
	st, err := server.OpenStore(filepath.Join(dir, server.FileDB))
	if err != nil {
		t.Fatal(err)
	}
	pub, _ := escrow.PublicFromPrivate(filepath.Join(dir, server.FileEscrowKey))
	blob, _ := escrow.Seal(pub, escrow.Segredo{Chave: "SEGREDO-EM-CLARO"})
	if err := st.AddEscrow("ag-1", "job-1", proto.EscrowRecord{Volume: "C:", Metodo: "bitlocker", Blob: blob}); err != nil {
		t.Fatal(err)
	}
	if err := st.AddEscrow("ag-1", "job-2", proto.EscrowRecord{Volume: "C:", Metodo: "bitlocker", Blob: "AAAA"}); err == nil {
		t.Fatal("blob curto/falso deveria ser recusado")
	}
	rows, _ := st.Escrows("ag-1")
	st.Close()
	if len(rows) != 1 || strings.Contains(rows[0].Blob, "SEGREDO-EM-CLARO") {
		t.Fatalf("%+v", rows)
	}
	if err := cmdEscrow([]string{"listar", "--dir", dir}); err != nil {
		t.Fatal(err)
	}
}
