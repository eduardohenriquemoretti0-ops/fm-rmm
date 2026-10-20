// Package escrow sela chaves de recuperação de disco para o administrador.
//
// Modelo: o par X25519 do admin é gerado no init; a PRIVADA (escrow.key) fica
// OFFLINE com o admin e a PÚBLICA vai no bundle do agente. O agente sela a
// chave de recuperação com nacl/box.SealAnonymous para essa pública; o
// servidor guarda só o ciphertext. Só quem tem a privada decifra.
package escrow

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"os"
	"regexp"

	"golang.org/x/crypto/curve25519"
	"golang.org/x/crypto/nacl/box"
)

const (
	// PEMType é o tipo do bloco PEM de escrow.key.
	PEMType = "FMRMM ESCROW PRIVATE KEY"
	// MaxBlob limita o tamanho aceito de um blob selado (base64).
	MaxBlob = 4096
	// Version é a versão do envelope em claro (dentro do blob selado).
	Version = 1
)

// Segredo é o conteúdo que vai DENTRO do blob selado.
type Segredo struct {
	V       int    `json:"v"`
	AgentID string `json:"agent_id"`
	Volume  string `json:"volume"`
	Metodo  string `json:"metodo"`
	Chave   string `json:"chave"` // chave de recuperação em claro (só existe dentro do blob)
}

// GenerateKey cria o par X25519, grava a privada em PEM (0600, sem sobrescrever)
// e devolve a pública em base64.
func GenerateKey(path string) (string, error) {
	pub, priv, err := box.GenerateKey(rand.Reader)
	if err != nil {
		return "", err
	}
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return "", err
	}
	defer f.Close()
	if err := pem.Encode(f, &pem.Block{Type: PEMType, Bytes: priv[:]}); err != nil {
		return "", err
	}
	if err := f.Close(); err != nil {
		return "", err
	}
	return EncodePub(pub), nil
}

// EncodePub serializa a pública em base64.
func EncodePub(pub *[32]byte) string { return base64.StdEncoding.EncodeToString(pub[:]) }

// DecodePub lê a pública em base64 (exatamente 32 bytes).
func DecodePub(s string) (*[32]byte, error) {
	b, err := base64.StdEncoding.DecodeString(s)
	if err != nil || len(b) != 32 {
		return nil, errors.New("escrow: chave pública inválida (esperado X25519 de 32 bytes em base64)")
	}
	var pub [32]byte
	copy(pub[:], b)
	return &pub, nil
}

// LoadPrivate lê escrow.key. SÓ o comando offline `escrow abrir` chama isto.
func LoadPrivate(path string) (priv, pub *[32]byte, err error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, nil, err
	}
	blk, _ := pem.Decode(b)
	if blk == nil || blk.Type != PEMType || len(blk.Bytes) != 32 {
		return nil, nil, errors.New("escrow: arquivo de chave privada inválido")
	}
	priv, pub = new([32]byte), new([32]byte)
	copy(priv[:], blk.Bytes)
	curve25519.ScalarBaseMult(pub, priv)
	return priv, pub, nil
}

// PublicFromPrivate devolve a pública (base64) de escrow.key.
func PublicFromPrivate(path string) (string, error) {
	_, pub, err := LoadPrivate(path)
	if err != nil {
		return "", err
	}
	return EncodePub(pub), nil
}

// Seal sela o segredo para a pública do admin (anônimo) e devolve base64.
func Seal(pubB64 string, s Segredo) (string, error) {
	pub, err := DecodePub(pubB64)
	if err != nil {
		return "", err
	}
	if s.Chave == "" {
		return "", errors.New("escrow: chave de recuperação vazia")
	}
	s.V = Version
	pt, err := json.Marshal(s)
	if err != nil {
		return "", err
	}
	ct, err := box.SealAnonymous(nil, pt, pub, rand.Reader)
	if err != nil {
		return "", err
	}
	return base64.StdEncoding.EncodeToString(ct), nil
}

// Open decifra um blob com a privada do admin. Falha limpa (sem vazar nada)
// para blob malformado, chave errada ou blob adulterado.
func Open(privPath, blobB64 string) (Segredo, error) {
	var s Segredo
	if len(blobB64) > MaxBlob {
		return s, errors.New("escrow: blob grande demais")
	}
	ct, err := base64.StdEncoding.DecodeString(blobB64)
	if err != nil {
		return s, errors.New("escrow: blob não é base64 válido")
	}
	priv, pub, err := LoadPrivate(privPath)
	if err != nil {
		return s, err
	}
	pt, ok := box.OpenAnonymous(nil, ct, pub, priv)
	if !ok {
		return s, errors.New("escrow: não foi possível abrir o blob (chave privada errada ou blob corrompido)")
	}
	if err := json.Unmarshal(pt, &s); err != nil || s.V != Version || s.Chave == "" {
		return Segredo{}, fmt.Errorf("escrow: conteúdo do blob inesperado")
	}
	return s, nil
}

// redactRe casa o formato da senha de recuperação do BitLocker (8 grupos de 6 dígitos).
var redactRe = regexp.MustCompile(`\d{6}(?:-\d{6}){7}`)

// ExtrairChaveBitLocker acha a primeira senha de recuperação do BitLocker em um texto.
func ExtrairChaveBitLocker(s string) string { return redactRe.FindString(s) }

// Redigir troca qualquer senha de recuperação do BitLocker por [REDIGIDO].
// Defesa em profundidade: usada em mensagens de erro e na entrada de resultado.
func Redigir(s string) string { return redactRe.ReplaceAllString(s, "[REDIGIDO]") }
