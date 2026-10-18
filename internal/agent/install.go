package agent

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"

	"github.com/eduardohenriquemoretti0-ops/fm-rmm/internal/pki"
	"github.com/eduardohenriquemoretti0-ops/fm-rmm/internal/proto"
	"github.com/eduardohenriquemoretti0-ops/fm-rmm/internal/sign"
)

// ServiceName é o nome do serviço em todos os sistemas.
const ServiceName = "FMRMMAgent"

type InstallOptions struct {
	BundlePath string // bundle.json gerado pelo servidor
	Token      string // token de inscrição (obrigatório na 1ª instalação)
}

// Install instala ou ATUALIZA o agente (mesmo comando: idempotente).
// Em atualização mantém identidade e certificado; só troca binário e bundle.
func Install(o InstallOptions) error {
	if !isAdmin() {
		return errors.New("rode como Administrador (Windows) ou root (Linux/macOS)")
	}
	raw, err := os.ReadFile(o.BundlePath)
	if err != nil {
		return fmt.Errorf("bundle: %w", err)
	}
	if err := validateBundle(raw); err != nil {
		return err
	}
	dir := DataDir()
	if err := secureDir(dir); err != nil {
		return fmt.Errorf("diretório de dados: %w", err)
	}
	var st State
	_ = readJSONFile(filepath.Join(dir, fileState), &st)
	_, certErr := os.Stat(filepath.Join(dir, fileCert))
	alreadyEnrolled := st.AgentID != "" && certErr == nil
	if !alreadyEnrolled && st.AgentID == "" && o.Token == "" {
		return errors.New("primeira instalação: informe --token")
	}

	_ = stopService() // atualização: o binário em uso não pode ser trocado
	exe, err := os.Executable()
	if err != nil {
		return err
	}
	if err := copyBinary(exe, BinaryPath()); err != nil {
		return fmt.Errorf("copiar binário: %w", err)
	}
	if err := writeFileAtomic(filepath.Join(dir, fileBundle), raw); err != nil {
		return err
	}
	if !alreadyEnrolled && st.AgentID == "" {
		st = State{Token: o.Token}
		b, _ := json.MarshalIndent(st, "", "  ")
		if err := writeFileAtomic(filepath.Join(dir, fileState), b); err != nil {
			return err
		}
	}
	if err := installService(BinaryPath()); err != nil {
		return fmt.Errorf("registrar serviço: %w", err)
	}
	return startService()
}

// Uninstall para e remove o serviço e o binário. purge apaga também a
// identidade (chave, certificado, estado): a máquina precisará de nova inscrição.
func Uninstall(purge bool) error {
	if !isAdmin() {
		return errors.New("rode como Administrador (Windows) ou root (Linux/macOS)")
	}
	_ = stopService()
	if err := removeService(); err != nil {
		return fmt.Errorf("remover serviço: %w", err)
	}
	removeBinary(BinaryPath())
	if purge {
		return os.RemoveAll(DataDir())
	}
	return nil
}

func validateBundle(raw []byte) error {
	var b proto.Bundle
	if err := json.Unmarshal(raw, &b); err != nil {
		return fmt.Errorf("bundle ilegível: %w", err)
	}
	if _, err := sign.DecodePub(b.SignerPub); err != nil {
		return fmt.Errorf("bundle: %w", err)
	}
	if _, err := pki.ParseCertPEM(b.CAPEM); err != nil {
		return fmt.Errorf("bundle: CA: %w", err)
	}
	if len(b.ServerURL) < 9 || b.ServerURL[:8] != "https://" {
		return errors.New("bundle: server_url precisa ser https://")
	}
	return nil
}

// copyBinary copia via arquivo temporário + rename (nunca deixa binário pela metade).
func copyBinary(src, dst string) error {
	if same(src, dst) {
		return nil
	}
	if err := os.MkdirAll(filepath.Dir(dst), 0o755); err != nil {
		return err
	}
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer in.Close()
	tmp := dst + ".novo"
	out, err := os.OpenFile(tmp, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o755)
	if err != nil {
		return err
	}
	if _, err := io.Copy(out, in); err != nil {
		out.Close()
		return err
	}
	if err := out.Close(); err != nil {
		return err
	}
	return os.Rename(tmp, dst)
}

func same(a, b string) bool {
	sa, err1 := os.Stat(a)
	sb, err2 := os.Stat(b)
	return err1 == nil && err2 == nil && os.SameFile(sa, sb)
}
