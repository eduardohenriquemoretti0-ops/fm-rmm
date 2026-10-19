// Package pki é a CA própria: emite o certificado do servidor e um
// certificado de cliente por agente (mTLS). Só certificados desta CA conectam.
package pki

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"net"
	"os"
	"slices"
	"time"
)

const (
	CAValidity       = 10 * 365 * 24 * time.Hour
	ServerValidity   = 2 * 365 * 24 * time.Hour
	AgentValidity    = 365 * 24 * time.Hour
	OperatorValidity = 365 * 24 * time.Hour
)

// Organization dos certificados de cliente. O perfil é o que separa os dois
// papéis: cert de AGENTE não pode entrar como OPERADOR no console (T3b).
const (
	OrgAgente   = "FM-RMM agente"
	OrgOperador = "FM-RMM operador"
)

func serial() (*big.Int, error) {
	return rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 127))
}

func newKey() (*ecdsa.PrivateKey, error) { return ecdsa.GenerateKey(elliptic.P256(), rand.Reader) }

// WritePEM grava com 0600 e recusa sobrescrever.
func WritePEM(path, typ string, der []byte) error {
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return err
	}
	defer f.Close()
	if err := pem.Encode(f, &pem.Block{Type: typ, Bytes: der}); err != nil {
		return err
	}
	return f.Close()
}

func KeyDER(k crypto.Signer) ([]byte, error) { return x509.MarshalPKCS8PrivateKey(k) }

// NewCA cria a CA autoassinada.
func NewCA(name string) (*x509.Certificate, *ecdsa.PrivateKey, error) {
	key, err := newKey()
	if err != nil {
		return nil, nil, err
	}
	sn, err := serial()
	if err != nil {
		return nil, nil, err
	}
	now := time.Now()
	tpl := &x509.Certificate{
		SerialNumber:          sn,
		Subject:               pkix.Name{CommonName: name, Organization: []string{"FM-RMM"}},
		NotBefore:             now.Add(-time.Hour),
		NotAfter:              now.Add(CAValidity),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
		MaxPathLenZero:        true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tpl, tpl, &key.PublicKey, key)
	if err != nil {
		return nil, nil, err
	}
	cert, err := x509.ParseCertificate(der)
	return cert, key, err
}

// NewServerCert emite o certificado TLS do servidor com os nomes/IPs informados.
func NewServerCert(ca *x509.Certificate, caKey crypto.Signer, hosts []string) (*x509.Certificate, *ecdsa.PrivateKey, error) {
	if len(hosts) == 0 {
		return nil, nil, errors.New("informe ao menos um nome ou IP do servidor")
	}
	key, err := newKey()
	if err != nil {
		return nil, nil, err
	}
	sn, err := serial()
	if err != nil {
		return nil, nil, err
	}
	now := time.Now()
	tpl := &x509.Certificate{
		SerialNumber: sn,
		Subject:      pkix.Name{CommonName: hosts[0], Organization: []string{"FM-RMM"}},
		NotBefore:    now.Add(-time.Hour),
		NotAfter:     now.Add(ServerValidity),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	for _, h := range hosts {
		if ip := net.ParseIP(h); ip != nil {
			tpl.IPAddresses = append(tpl.IPAddresses, ip)
		} else {
			tpl.DNSNames = append(tpl.DNSNames, h)
		}
	}
	der, err := x509.CreateCertificate(rand.Reader, tpl, ca, &key.PublicKey, caKey)
	if err != nil {
		return nil, nil, err
	}
	cert, err := x509.ParseCertificate(der)
	return cert, key, err
}

// ParseCSR valida o CSR do agente: assinatura e tipo de chave aceito.
func ParseCSR(csrPEM string) (*x509.CertificateRequest, error) {
	blk, _ := pem.Decode([]byte(csrPEM))
	if blk == nil || blk.Type != "CERTIFICATE REQUEST" {
		return nil, errors.New("CSR: PEM inválido")
	}
	csr, err := x509.ParseCertificateRequest(blk.Bytes)
	if err != nil {
		return nil, fmt.Errorf("CSR: %w", err)
	}
	if err := csr.CheckSignature(); err != nil {
		return nil, fmt.Errorf("CSR: assinatura: %w", err)
	}
	switch k := csr.PublicKey.(type) {
	case *ecdsa.PublicKey:
		if k.Curve != elliptic.P256() {
			return nil, errors.New("CSR: só ECDSA P-256 é aceito")
		}
	case ed25519.PublicKey:
	default:
		return nil, errors.New("CSR: tipo de chave não aceito")
	}
	return csr, nil
}

// SignAgent emite o certificado de cliente. O CN é SEMPRE o agent_id
// definido pelo servidor (o subject do CSR é ignorado).
func SignAgent(ca *x509.Certificate, caKey crypto.Signer, csr *x509.CertificateRequest, agentID string) (*x509.Certificate, error) {
	sn, err := serial()
	if err != nil {
		return nil, err
	}
	now := time.Now()
	tpl := &x509.Certificate{
		SerialNumber: sn,
		Subject:      pkix.Name{CommonName: agentID, Organization: []string{OrgAgente}},
		NotBefore:    now.Add(-time.Hour),
		NotAfter:     now.Add(AgentValidity),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, tpl, ca, csr.PublicKey, caKey)
	if err != nil {
		return nil, err
	}
	return x509.ParseCertificate(der)
}

// SignOperator emite o certificado de cliente do OPERADOR do console. Espelha
// SignAgent, mas com perfil distinto (Organization "FM-RMM operador"): o
// console recusa cert sem esse perfil, então cert de agente não serve de operador.
// O CN é SEMPRE o id do operador definido pelo servidor.
func SignOperator(ca *x509.Certificate, caKey crypto.Signer, csr *x509.CertificateRequest, operadorID string) (*x509.Certificate, error) {
	sn, err := serial()
	if err != nil {
		return nil, err
	}
	now := time.Now()
	tpl := &x509.Certificate{
		SerialNumber: sn,
		Subject:      pkix.Name{CommonName: operadorID, Organization: []string{OrgOperador}},
		NotBefore:    now.Add(-time.Hour),
		NotAfter:     now.Add(OperatorValidity),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, tpl, ca, csr.PublicKey, caKey)
	if err != nil {
		return nil, err
	}
	return x509.ParseCertificate(der)
}

// EhOperador diz se o certificado tem o perfil de operador do console (e não
// o de agente). Não substitui a verificação de cadeia contra a CA.
func EhOperador(c *x509.Certificate) bool {
	return slices.Contains(c.Subject.Organization, OrgOperador) &&
		!slices.Contains(c.Subject.Organization, OrgAgente)
}

// NewAgentKeyAndCSR roda no agente: a chave privada nunca sai da máquina.
func NewAgentKeyAndCSR(hostname string) (*ecdsa.PrivateKey, string, error) {
	key, err := newKey()
	if err != nil {
		return nil, "", err
	}
	der, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{
		Subject: pkix.Name{CommonName: hostname},
	}, key)
	if err != nil {
		return nil, "", err
	}
	return key, string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: der})), nil
}

func CertPEM(c *x509.Certificate) string {
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: c.Raw}))
}

func ParseCertPEM(s string) (*x509.Certificate, error) {
	blk, _ := pem.Decode([]byte(s))
	if blk == nil || blk.Type != "CERTIFICATE" {
		return nil, errors.New("certificado: PEM inválido")
	}
	return x509.ParseCertificate(blk.Bytes)
}

func LoadCert(path string) (*x509.Certificate, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	return ParseCertPEM(string(b))
}

func LoadKey(path string) (crypto.Signer, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	blk, _ := pem.Decode(b)
	if blk == nil {
		return nil, errors.New("chave: PEM inválido")
	}
	k, err := x509.ParsePKCS8PrivateKey(blk.Bytes)
	if err != nil {
		return nil, err
	}
	s, ok := k.(crypto.Signer)
	if !ok {
		return nil, errors.New("chave não suporta assinatura")
	}
	return s, nil
}
