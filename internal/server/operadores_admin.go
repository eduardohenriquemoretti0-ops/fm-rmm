package server

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"os"
	"path/filepath"

	"github.com/eduardohenriquemoretti0-ops/fm-rmm/internal/pki"
)

// Nomes dos arquivos gravados por EmitirCertOperador.
const (
	FileOperadorKey = "operador.key"
	FileOperadorCrt = "operador.crt"
	FileOperadorCA  = "ca.crt"
)

// NovoIDOperador gera um id aleatório de operador ("op-" + 16 hex).
func NovoIDOperador() (string, error) {
	b := make([]byte, 8)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return "op-" + hex.EncodeToString(b), nil
}

// ThumbprintCert é o SHA-256 do DER em hex minúsculo. É a MESMA definição de
// console.CertThumbprint (que o login compara); um teste no pacote console
// garante a equivalência.
func ThumbprintCert(c *x509.Certificate) string {
	sum := sha256.Sum256(c.Raw)
	return hex.EncodeToString(sum[:])
}

// EmitirCertOperador gera o par de chaves de cliente do operador, emite o cert
// pela CA do servidor (pki.SignOperator) e liga o thumbprint ao operador.
//
// MODO DIRETO (lab): a chave privada nasce AQUI, no servidor, e vai para o
// disco de quem roda o comando. Em produção o ideal é o operador gerar a chave
// e um CSR na própria máquina (a privada nunca sai de lá) e o admin só assinar
// o CSR com pki.SignOperator.
//
// Grava operador.key (PKCS#8, 0600), operador.crt e ca.crt em outDir. Recusa
// sobrescrever arquivos e, se o operador já tem cert, exige reemitir=true
// (a reemissão invalida o cert anterior).
func EmitirCertOperador(st *Store, serverDir, id, outDir string, reemitir bool) (thumb string, cert *x509.Certificate, err error) {
	op, err := st.GetOperator(id)
	if err != nil {
		return "", nil, fmt.Errorf("operador %q: %w", id, err)
	}
	if op.CertThumbprint != "" && !reemitir {
		return "", nil, errors.New("operador já tem cert; use --reemitir (invalida o anterior)")
	}
	ca, err := pki.LoadCert(filepath.Join(serverDir, FileCA))
	if err != nil {
		return "", nil, err
	}
	caKey, err := pki.LoadKey(filepath.Join(serverDir, FileCAKey))
	if err != nil {
		return "", nil, err
	}
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return "", nil, err
	}
	csrDER, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{Subject: pkix.Name{CommonName: id}}, key)
	if err != nil {
		return "", nil, err
	}
	csr, err := pki.ParseCSR(string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: csrDER})))
	if err != nil {
		return "", nil, err
	}
	cert, err = pki.SignOperator(ca, caKey, csr, id)
	if err != nil {
		return "", nil, err
	}
	if err := os.MkdirAll(outDir, 0o700); err != nil {
		return "", nil, err
	}
	keyDER, err := pki.KeyDER(key)
	if err != nil {
		return "", nil, err
	}
	var criados []string
	falha := func(e error) (string, *x509.Certificate, error) {
		for _, p := range criados {
			os.Remove(p)
		}
		return "", nil, e
	}
	for _, f := range []struct {
		nome, tipo string
		der        []byte
	}{{FileOperadorKey, "PRIVATE KEY", keyDER}, {FileOperadorCrt, "CERTIFICATE", cert.Raw}, {FileOperadorCA, "CERTIFICATE", ca.Raw}} {
		p := filepath.Join(outDir, f.nome)
		if err := pki.WritePEM(p, f.tipo, f.der); err != nil {
			return falha(err)
		}
		criados = append(criados, p)
	}
	thumb = ThumbprintCert(cert)
	if err := st.SetOperatorThumbprint(id, thumb); err != nil {
		return falha(err)
	}
	return thumb, cert, nil
}

// AtivarOperador põe o operador em 'ativo'. Guardas (a política do projeto):
// exige cert ligado e AO MENOS duas credenciais WebAuthn (principal + backup).
// A chave de assinatura NÃO é pré-requisito: só dá para cadastrá-la logado, e o
// login exige 'ativo'.
func AtivarOperador(st *Store, id string) error {
	op, err := st.GetOperator(id)
	if err != nil {
		return fmt.Errorf("operador %q: %w", id, err)
	}
	if op.CertThumbprint == "" {
		return errors.New("operador sem cert (rode operadores cert)")
	}
	creds, err := st.Credentials(id)
	if err != nil {
		return err
	}
	if len(creds) < 2 {
		return fmt.Errorf("operador tem %d credencial(is) WebAuthn; precisa de 2 (principal + backup)", len(creds))
	}
	return st.SetOperatorStatus(id, "ativo")
}

// Operators lista todos os operadores (ordem por id).
func (s *Store) Operators() ([]Operator, error) {
	rows, err := s.db.Query(`SELECT ` + operatorCols + ` FROM operators ORDER BY id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Operator
	for rows.Next() {
		o, err := scanOperator(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, o)
	}
	return out, rows.Err()
}
