// Package redfish é um cliente mínimo do Redfish (DMTF) para controle de energia
// de servidores via BMC (iDRAC, iLO, etc.), independente do SO (Plano v2, §3.2).
//
// Segurança:
//   - A credencial do BMC vive só em Config, na pilha da chamada: este pacote não
//     persiste, não loga e nunca a inclui em erros (os erros são sanitizados).
//   - TLS valida o certificado por padrão. O modo Insecure precisa ser pedido de
//     forma explícita (BMCs costumam ter cert self-signed) e é sinalizado por
//     AvisoInsecure para o chamador exibir/auditar.
//   - Redirecionamentos NÃO são seguidos (evita levar o Basic auth para outro host).
//   - Respostas têm teto de tamanho; todas as chamadas têm timeout.
package redfish

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"regexp"
	"strconv"
	"strings"
	"syscall"
	"time"
)

// Ação de energia aceitas (ResetType do Redfish).
const (
	AcaoOn               = "On"
	AcaoForceOff         = "ForceOff"
	AcaoGracefulShutdown = "GracefulShutdown"
	AcaoForceRestart     = "ForceRestart"
	AcaoGracefulRestart  = "GracefulRestart"
)

// AvisoInsecure é o texto de aviso quando a validação do certificado do BMC é desligada.
const AvisoInsecure = "validação do certificado TLS do BMC DESLIGADA (modo inseguro): " +
	"a identidade do BMC não foi verificada"

const (
	portaPadrao   = 443
	timeoutPadrao = 15 * time.Second
	limiteResp    = 1 << 20
)

// Erros sentinela. Nunca carregam senha, URL com credencial nem corpo do BMC.
var (
	ErrAcaoInvalida   = errors.New("redfish: ação de energia inválida")
	ErrHostInvalido   = errors.New("redfish: host inválido")
	ErrSystemInvalido = errors.New("redfish: system_id inválido")
	ErrAutenticacao   = errors.New("redfish: BMC recusou a credencial")
	ErrConexao        = errors.New("redfish: falha de conexão/TLS com o BMC")
	ErrDestinoBloq    = errors.New("redfish: destino não permitido")
	ErrRespostaBMC    = errors.New("redfish: resposta inesperada do BMC")
)

// ErroHTTP: o BMC respondeu com status de erro. Só o código é guardado.
type ErroHTTP struct{ Status int }

func (e *ErroHTTP) Error() string { return fmt.Sprintf("redfish: BMC respondeu HTTP %d", e.Status) }

var (
	hostRe   = regexp.MustCompile(`^[A-Za-z0-9]([A-Za-z0-9.-]{0,251}[A-Za-z0-9])?$`)
	systemRe = regexp.MustCompile(`^[A-Za-z0-9._-]{1,64}$`)
)

// Config descreve UM acesso a UM BMC. Usuario/Senha são usados e descartados.
type Config struct {
	Host     string // IP ou nome (sem esquema, porta, caminho nem credencial)
	Porta    int    // 0 = 443
	Usuario  string
	Senha    string
	Insecure bool // NÃO valida o certificado do BMC; exige pedido explícito
	Timeout  time.Duration

	// RootCAs: raízes extras para validar o BMC (CA privada). nil = do sistema.
	RootCAs *x509.CertPool
	// ProibirIP, se não nil, é consultado a cada conexão ANTES de discar (vale
	// também para o IP já resolvido: protege de DNS rebinding/SSRF).
	ProibirIP func(netip.Addr) bool
}

// Estado é a leitura read-only do sistema.
type Estado struct {
	SystemID   string `json:"system_id"`
	PowerState string `json:"power_state"`
	Health     string `json:"health,omitempty"`
	Modelo     string `json:"modelo,omitempty"`
}

// Cliente fala com um BMC.
type Cliente struct {
	cfg  Config
	base string
	http *http.Client
}

// ValidaHost recusa tudo que não for IP literal ou hostname simples.
func ValidaHost(h string) error {
	if a, err := netip.ParseAddr(h); err == nil {
		if a.Zone() != "" {
			return ErrHostInvalido
		}
		return nil
	}
	if !hostRe.MatchString(h) {
		return ErrHostInvalido
	}
	return nil
}

// ValidaAcao devolve o ResetType (idêntico à ação) ou ErrAcaoInvalida.
func ValidaAcao(a string) (string, error) {
	switch a {
	case AcaoOn, AcaoForceOff, AcaoGracefulShutdown, AcaoForceRestart, AcaoGracefulRestart:
		return a, nil
	}
	return "", ErrAcaoInvalida
}

// ValidaSystemID aceita vazio (será descoberto) ou um id seguro para caminho de URL.
func ValidaSystemID(id string) error {
	if id != "" && !systemRe.MatchString(id) {
		return ErrSystemInvalido
	}
	return nil
}

// Novo valida a configuração e monta o cliente.
func Novo(cfg Config) (*Cliente, error) {
	if err := ValidaHost(cfg.Host); err != nil {
		return nil, err
	}
	if cfg.Porta == 0 {
		cfg.Porta = portaPadrao
	}
	if cfg.Porta < 1 || cfg.Porta > 65535 {
		return nil, ErrHostInvalido
	}
	if cfg.Timeout <= 0 {
		cfg.Timeout = timeoutPadrao
	}
	tlsCfg := &tls.Config{MinVersion: tls.VersionTLS12, RootCAs: cfg.RootCAs}
	if cfg.Insecure {
		tlsCfg.InsecureSkipVerify = true // #nosec G402 -- modo inseguro explícito, sinalizado e auditado
	}
	dialer := &net.Dialer{Timeout: cfg.Timeout}
	if cfg.ProibirIP != nil {
		proibir := cfg.ProibirIP
		dialer.Control = func(_, address string, _ syscall.RawConn) error {
			ap, err := netip.ParseAddrPort(address)
			if err != nil || proibir(ap.Addr().Unmap()) {
				return ErrDestinoBloq
			}
			return nil
		}
	}
	tr := &http.Transport{
		TLSClientConfig:       tlsCfg,
		DialContext:           dialer.DialContext,
		TLSHandshakeTimeout:   cfg.Timeout,
		ResponseHeaderTimeout: cfg.Timeout,
		DisableKeepAlives:     true,
		Proxy:                 nil, // nunca por proxy de ambiente
	}
	c := &Cliente{
		cfg:  cfg,
		base: "https://" + net.JoinHostPort(cfg.Host, strconv.Itoa(cfg.Porta)),
		http: &http.Client{
			Transport:     tr,
			Timeout:       cfg.Timeout,
			CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
		},
	}
	return c, nil
}

// Insecure informa se este cliente não valida o certificado do BMC.
func (c *Cliente) Insecure() bool { return c.cfg.Insecure }

// do executa a requisição e devolve o corpo (limitado). Erros são sanitizados.
func (c *Cliente) do(ctx context.Context, metodo, caminho string, corpo any) ([]byte, error) {
	var rd io.Reader
	if corpo != nil {
		b, err := json.Marshal(corpo)
		if err != nil {
			return nil, ErrRespostaBMC
		}
		rd = bytes.NewReader(b)
	}
	req, err := http.NewRequestWithContext(ctx, metodo, c.base+caminho, rd)
	if err != nil {
		return nil, ErrHostInvalido
	}
	req.SetBasicAuth(c.cfg.Usuario, c.cfg.Senha)
	req.Header.Set("Accept", "application/json")
	req.Header.Set("OData-Version", "4.0")
	if corpo != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := c.http.Do(req)
	if err != nil {
		// descarta o *url.Error (traz URL) e o erro cru: só a categoria
		if errors.Is(err, ErrDestinoBloq) {
			return nil, ErrDestinoBloq
		}
		return nil, ErrConexao
	}
	defer resp.Body.Close()
	b, err := io.ReadAll(io.LimitReader(resp.Body, limiteResp))
	if err != nil {
		return nil, ErrConexao
	}
	switch {
	case resp.StatusCode == http.StatusUnauthorized || resp.StatusCode == http.StatusForbidden:
		return nil, ErrAutenticacao
	case resp.StatusCode < 200 || resp.StatusCode > 299:
		return nil, &ErroHTTP{Status: resp.StatusCode}
	}
	return b, nil
}

// DescobreSystem lê /redfish/v1/Systems e devolve o id do primeiro membro.
func (c *Cliente) DescobreSystem(ctx context.Context) (string, error) {
	b, err := c.do(ctx, http.MethodGet, "/redfish/v1/Systems", nil)
	if err != nil {
		return "", err
	}
	var col struct {
		Members []struct {
			ID string `json:"@odata.id"`
		} `json:"Members"`
	}
	if err := json.Unmarshal(b, &col); err != nil || len(col.Members) == 0 {
		return "", ErrRespostaBMC
	}
	trim := strings.TrimRight(col.Members[0].ID, "/")
	id := trim[strings.LastIndex(trim, "/")+1:]
	if !systemRe.MatchString(id) {
		return "", ErrRespostaBMC
	}
	return id, nil
}

func (c *Cliente) resolve(ctx context.Context, systemID string) (string, error) {
	if err := ValidaSystemID(systemID); err != nil {
		return "", err
	}
	if systemID != "" {
		return systemID, nil
	}
	return c.DescobreSystem(ctx)
}

// Status lê o estado de energia (GET /redfish/v1/Systems/{id}). systemID vazio = descobre.
func (c *Cliente) Status(ctx context.Context, systemID string) (Estado, error) {
	id, err := c.resolve(ctx, systemID)
	if err != nil {
		return Estado{}, err
	}
	b, err := c.do(ctx, http.MethodGet, "/redfish/v1/Systems/"+id, nil)
	if err != nil {
		return Estado{}, err
	}
	var s struct {
		PowerState string `json:"PowerState"`
		Model      string `json:"Model"`
		Status     struct {
			Health string `json:"Health"`
		} `json:"Status"`
	}
	if err := json.Unmarshal(b, &s); err != nil || s.PowerState == "" {
		return Estado{}, ErrRespostaBMC
	}
	return Estado{SystemID: id, PowerState: s.PowerState, Health: s.Status.Health, Modelo: s.Model}, nil
}

// Reset envia a ação de energia (POST .../Actions/ComputerSystem.Reset) e devolve
// o system_id usado.
func (c *Cliente) Reset(ctx context.Context, systemID, acao string) (string, error) {
	rt, err := ValidaAcao(acao)
	if err != nil {
		return "", err
	}
	id, err := c.resolve(ctx, systemID)
	if err != nil {
		return "", err
	}
	_, err = c.do(ctx, http.MethodPost, "/redfish/v1/Systems/"+id+"/Actions/ComputerSystem.Reset",
		map[string]string{"ResetType": rt})
	return id, err
}
