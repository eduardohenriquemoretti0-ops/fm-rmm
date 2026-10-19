package console

import (
	"crypto/tls"
	"crypto/x509"
	"errors"
)

// TLSConfigConsole monta o tls.Config do LISTENER do console web.
//
// Diferente do listener dos agentes (server.TLSConfig, que usa
// VerifyClientCertIfGiven porque o agente ainda não tem cert ao se inscrever),
// aqui o cert do cliente é OBRIGATÓRIO no handshake e tem de ser da nossa CA.
// O middleware comCert ainda reverifica a cadeia; esta é a primeira barreira.
//
//   - ca: certificado da nossa CA (única raiz aceita para o cert do operador);
//   - certServidor: par cert+chave TLS do console (emitido pela mesma CA).
//
// Uso (ainda NÃO ligado no cmd/fmrmm-server): o console deve escutar em porta
// PRÓPRIA. Não compartilhar com o listener dos agentes, senão o handshake
// obrigatório derrubaria a inscrição deles.
// TLS 1.2 é o mínimo (docs/console-seguranca.md).
func TLSConfigConsole(ca *x509.Certificate, certServidor tls.Certificate) (*tls.Config, error) {
	if ca == nil {
		return nil, errors.New("console tls: CA obrigatória")
	}
	if len(certServidor.Certificate) == 0 || certServidor.PrivateKey == nil {
		return nil, errors.New("console tls: par cert+chave do servidor obrigatório")
	}
	pool := x509.NewCertPool()
	pool.AddCert(ca)
	return &tls.Config{
		MinVersion:   tls.VersionTLS12,
		Certificates: []tls.Certificate{certServidor},
		ClientAuth:   tls.RequireAndVerifyClientCert,
		ClientCAs:    pool,
	}, nil
}
