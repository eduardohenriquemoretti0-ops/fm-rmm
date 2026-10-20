// Package agent é o agente do FM-RMM. Roda como serviço (SYSTEM no Windows,
// root no Linux/macOS), nunca escuta porta e só conversa com o NOSSO servidor.
//
// Ciclo: inscrição (uma vez) -> check-in por mTLS -> para cada job:
// assinatura, destino, validade, replay, catálogo -> executa -> reporta.
package agent

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"math/rand/v2"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"github.com/eduardohenriquemoretti0-ops/fm-rmm/internal/catalog"
	"github.com/eduardohenriquemoretti0-ops/fm-rmm/internal/pki"
	"github.com/eduardohenriquemoretti0-ops/fm-rmm/internal/proto"
	"github.com/eduardohenriquemoretti0-ops/fm-rmm/internal/sign"
)

// Version é definido no build (-ldflags "-X .../agent.Version=x.y.z").
var Version = "dev"

const (
	defaultInterval = 60 * time.Second
	enrollPoll      = 5 * time.Second // ritmo de checagem enquanto aguarda aprovação
	maxBackoff      = 15 * time.Minute
	revokedBackoff  = time.Hour
)

// Arquivos dentro do diretório de dados.
const (
	fileBundle = "bundle.json"
	fileState  = "state.json"
	fileKey    = "agent.key"
	fileCert   = "agent.crt"
	fileSeen   = "seen.json"
)

// State é o que o agente guarda entre reinícios.
type State struct {
	AgentID    string `json:"agent_id,omitempty"`
	PollSecret string `json:"poll_secret,omitempty"`
	Token      string `json:"token,omitempty"` // apagado assim que a inscrição é aceita
	Hostname   string `json:"hostname,omitempty"`
}

type Agent struct {
	Dir      string
	Log      *slog.Logger
	bundle   proto.Bundle
	signer   ed25519.PublicKey // chave raiz (bundle): âncora do trust-set
	trust    *trustStore       // raiz + signers da lista assinada (T5a)
	soft     *softStore        // catálogo de software assinado (allow-list)
	scripts  *scriptStore      // biblioteca de scripts assinada
	caPool   *x509.CertPool
	state    State
	seen     *seenStore
	interval time.Duration
	now      func() time.Time
	// exec é trocável nos testes
	exec func(ctx context.Context, a catalog.Action, params map[string]string) (string, int, bool, error)
	// run/goos: execução de comandos do fluxo nativo de escrow (trocáveis nos testes)
	run  cmdRunner
	goos string
	// softRun executa o gerenciador de pacotes (winget/apt); trocado por fake nos testes
	softRun cmdRunner
	// wingetResolve devolve o caminho absoluto do winget (nil = usa o nome "winget"; testes)
	wingetResolve func() (string, error)
	// wingetUserRun executa o winget NA SESSÃO DO USUÁRIO LOGADO (Windows). nil =
	// usa softRun (testes e SOs sem winget). apt nunca passa por aqui.
	wingetUserRun cmdRunner
	// scriptRun executa o interpretador do script; trocado por fake nos testes
	scriptRun cmdRunner
	// wipe: único caminho destrutivo (wipe_remoto); trocado por fake nos testes
	wipe WipeExecutor
	// acesso remoto (opcional): sem os dois, concessões de sessão são recusadas
	indicator     Indicator
	media         SessionMedia            // padrão
	mediaByEngine map[string]SessionMedia // por motor (ex.: rustdesk)
}

// EnableRemote liga o acesso remoto autorizado com um plano de mídia padrão. O
// indicador é obrigatório: sem ele, o agente recusa toda sessão.
func (ag *Agent) EnableRemote(ind Indicator, media SessionMedia) {
	ag.indicator, ag.media = ind, media
}

// SetMediaEngine registra um plano de mídia para um motor específico (ex.:
// "rustdesk"). A concessão escolhe o motor; se não houver um registrado, cai no
// padrão de EnableRemote.
func (ag *Agent) SetMediaEngine(engine string, media SessionMedia) {
	if ag.mediaByEngine == nil {
		ag.mediaByEngine = map[string]SessionMedia{}
	}
	ag.mediaByEngine[engine] = media
}

func (ag *Agent) mediaFor(engine string) SessionMedia {
	if m, ok := ag.mediaByEngine[engine]; ok {
		return m
	}
	return ag.media
}

func New(dir string, log *slog.Logger) (*Agent, error) {
	ag := &Agent{Dir: dir, Log: log, interval: defaultInterval, now: time.Now, exec: runAction, run: runCmd, goos: runtime.GOOS, wipe: realWipe{run: runCmd}, softRun: runCmd, scriptRun: runScript}
	if runtime.GOOS == "windows" {
		ag.wingetResolve = resolverWinget
		ag.wingetUserRun = runInUserSession
	}
	b, err := os.ReadFile(filepath.Join(dir, fileBundle))
	if err != nil {
		return nil, fmt.Errorf("bundle do servidor: %w", err)
	}
	if err := json.Unmarshal(b, &ag.bundle); err != nil {
		return nil, fmt.Errorf("bundle do servidor: %w", err)
	}
	if !strings.HasPrefix(ag.bundle.ServerURL, "https://") {
		return nil, errors.New("bundle: server_url precisa ser https://")
	}
	if ag.signer, err = sign.DecodePub(ag.bundle.SignerPub); err != nil {
		return nil, err
	}
	ca, err := pki.ParseCertPEM(ag.bundle.CAPEM)
	if err != nil {
		return nil, fmt.Errorf("bundle: CA: %w", err)
	}
	ag.caPool = x509.NewCertPool()
	ag.caPool.AddCert(ca)
	if err := readJSONFile(filepath.Join(dir, fileState), &ag.state); err != nil && !errors.Is(err, os.ErrNotExist) {
		return nil, fmt.Errorf("estado: %w", err)
	}
	if ag.seen, err = openSeen(filepath.Join(dir, fileSeen)); err != nil {
		return nil, err
	}
	if ag.trust, err = openTrust(filepath.Join(dir, fileTrust), ag.signer, time.Now(), log); err != nil {
		return nil, err
	}
	if ag.soft, err = openSoft(filepath.Join(dir, fileSoftware), ag.signer, log); err != nil {
		return nil, err
	}
	if ag.scripts, err = openScripts(filepath.Join(dir, fileScripts), ag.signer, log); err != nil {
		return nil, err
	}
	ag.enableRustDesk()
	return ag, nil
}

func readJSONFile(path string, v any) error {
	b, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	return json.Unmarshal(b, v)
}

// writeFileAtomic grava em arquivo temporário e renomeia (sem arquivo pela metade).
func writeFileAtomic(path string, data []byte) error {
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, data, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}

func (ag *Agent) saveState() error {
	b, _ := json.MarshalIndent(ag.state, "", "  ")
	return writeFileAtomic(filepath.Join(ag.Dir, fileState), b)
}

func (ag *Agent) enrolled() bool {
	_, err := os.Stat(filepath.Join(ag.Dir, fileCert))
	return err == nil && ag.state.AgentID != ""
}

// client monta o HTTPS: SÓ confia na nossa CA (pinning) e apresenta o
// certificado do agente quando já inscrito.
func (ag *Agent) client() (*http.Client, error) {
	tc := &tls.Config{MinVersion: tls.VersionTLS12, RootCAs: ag.caPool}
	if ag.enrolled() {
		cert, err := tls.LoadX509KeyPair(filepath.Join(ag.Dir, fileCert), filepath.Join(ag.Dir, fileKey))
		if err != nil {
			return nil, fmt.Errorf("certificado do agente: %w", err)
		}
		tc.Certificates = []tls.Certificate{cert}
	}
	tr := &http.Transport{
		TLSClientConfig:     tc,
		Proxy:               http.ProxyFromEnvironment,
		TLSHandshakeTimeout: 15 * time.Second,
		ForceAttemptHTTP2:   true,
		MaxIdleConns:        2,
		IdleConnTimeout:     90 * time.Second,
	}
	return &http.Client{Transport: tr, Timeout: 60 * time.Second}, nil
}

// httpError carrega o status HTTP para o loop decidir o que fazer.
type httpError struct {
	code int
	msg  string
}

func (e *httpError) Error() string { return fmt.Sprintf("servidor respondeu %d: %s", e.code, e.msg) }

func (ag *Agent) post(ctx context.Context, c *http.Client, path string, in, out any) error {
	body, err := json.Marshal(in)
	if err != nil {
		return err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, strings.TrimRight(ag.bundle.ServerURL, "/")+path, bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", "fm-rmm-agent/"+Version)
	resp, err := c.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	data, err := io.ReadAll(io.LimitReader(resp.Body, 8<<20))
	if err != nil {
		return err
	}
	if resp.StatusCode != http.StatusOK {
		var e struct {
			Erro string `json:"erro"`
		}
		_ = json.Unmarshal(data, &e)
		return &httpError{code: resp.StatusCode, msg: e.Erro}
	}
	if out != nil {
		return json.Unmarshal(data, out)
	}
	return nil
}

// ---------------------------------------------------------------- inscrição

// enroll avança a inscrição um passo. Retorna true quando o certificado chegou.
func (ag *Agent) enroll(ctx context.Context) (bool, error) {
	c, err := ag.client()
	if err != nil {
		return false, err
	}
	keyPath := filepath.Join(ag.Dir, fileKey)
	if ag.state.AgentID == "" {
		if ag.state.Token == "" {
			return false, errors.New("sem token de inscrição: reinstale com --token")
		}
		host, _ := os.Hostname()
		key, csr, err := pki.NewAgentKeyAndCSR(host)
		if err != nil {
			return false, err
		}
		var resp proto.EnrollResponse
		err = ag.post(ctx, c, "/v1/enroll", proto.EnrollRequest{Token: ag.state.Token, CSRPEM: csr, Hostname: host, OS: runtime.GOOS}, &resp)
		if err != nil {
			return false, err
		}
		der, err := pki.KeyDER(key)
		if err != nil {
			return false, err
		}
		_ = os.Remove(keyPath)
		if err := pki.WritePEM(keyPath, "PRIVATE KEY", der); err != nil {
			return false, err
		}
		ag.state = State{AgentID: resp.AgentID, PollSecret: resp.PollSecret, Hostname: host}
		if err := ag.saveState(); err != nil {
			return false, err
		}
		ag.Log.Info("inscrição enviada; aguardando aprovação no servidor", "agente", resp.AgentID)
	}
	var st proto.EnrollStatusResponse
	if err := ag.post(ctx, c, "/v1/enroll/status", proto.EnrollStatusRequest{AgentID: ag.state.AgentID, PollSecret: ag.state.PollSecret}, &st); err != nil {
		return false, err
	}
	switch st.Status {
	case "approved":
		cert, err := pki.ParseCertPEM(st.CertPEM)
		if err != nil {
			return false, err
		}
		if _, err := cert.Verify(x509.VerifyOptions{Roots: ag.caPool, KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}}); err != nil {
			return false, fmt.Errorf("certificado recebido não é da nossa CA: %w", err)
		}
		if cert.Subject.CommonName != ag.state.AgentID {
			return false, errors.New("certificado recebido é de outro agente")
		}
		if err := writeFileAtomic(filepath.Join(ag.Dir, fileCert), []byte(st.CertPEM)); err != nil {
			return false, err
		}
		ag.state.PollSecret = ""
		if err := ag.saveState(); err != nil {
			return false, err
		}
		ag.Log.Info("inscrição aprovada; certificado instalado", "agente", ag.state.AgentID, "validade", cert.NotAfter.Format(time.DateOnly))
		return true, nil
	case "pending":
		return false, nil
	default:
		return false, fmt.Errorf("inscrição %s pelo servidor", st.Status)
	}
}

// ----------------------------------------------------------------- check-in

func (ag *Agent) heartbeat() proto.Heartbeat {
	host, _ := os.Hostname()
	hb := proto.Heartbeat{Hostname: host, OS: runtime.GOOS, Arch: runtime.GOARCH, AgentVersion: Version, UptimeSec: uptimeSeconds()}
	if runtime.GOOS == "linux" {
		hb.OSID, hb.OSVersionID = lerOSRelease("/etc/os-release")
	}
	return hb
}

// CheckinOnce faz um check-in completo: busca jobs, executa e reporta.
func (ag *Agent) CheckinOnce(ctx context.Context) error {
	c, err := ag.client()
	if err != nil {
		return err
	}
	var resp proto.CheckinResponse
	if err := ag.post(ctx, c, "/v1/checkin", proto.CheckinRequest{Heartbeat: ag.heartbeat()}, &resp); err != nil {
		return err
	}
	// lista de signers corrente (trust-set): ingerida ANTES dos jobs desta resposta
	if resp.Lista != nil {
		ag.aplicarListaDoCheckin(resp.Lista)
	}
	if resp.Software != nil {
		ag.aplicarSoftwareDoCheckin(resp.Software)
	}
	if resp.Scripts != nil {
		ag.aplicarScriptsDoCheckin(resp.Scripts)
	}
	if resp.IntervalSec >= 10 && resp.IntervalSec <= 3600 {
		ag.interval = time.Duration(resp.IntervalSec) * time.Second
	}
	for _, sj := range resp.Jobs {
		res := ag.handleJob(ctx, sj)
		if res.JobID == "" {
			continue // nem deu para ler o job: não há a quem reportar
		}
		if err := ag.post(ctx, c, "/v1/result", res, nil); err != nil {
			ag.Log.Error("falha ao reportar resultado", "job", res.JobID, "erro", err)
		}
	}
	// sessões remotas autorizadas: cada uma roda em sua própria goroutine para
	// não travar o loop de check-in (uma sessão dura minutos)
	for _, sg := range resp.Grants {
		go func(sg proto.SignedGrant) {
			ev := ag.handleGrant(ctx, sg)
			if ev.SessionID != "" {
				ag.reportSession(ctx, ev)
			}
		}(sg)
	}
	return nil
}

// handleJob aplica TODAS as travas antes de executar.
func (ag *Agent) handleJob(ctx context.Context, sj proto.SignedJob) proto.Result {
	now := ag.now()
	refuse := func(id, why string) proto.Result {
		ag.Log.Warn("job recusado", "job", id, "motivo", why)
		return proto.Result{JobID: id, Status: "recusado", ExitCode: -1, Error: why, StartedAt: now, FinishedAt: now}
	}
	p, err := sign.VerifyJobAny(ag.confianca(), sj, ag.state.AgentID, now)
	if err != nil {
		// assinatura inválida: o conteúdo não é confiável nem para reportar o ID
		if errors.Is(err, sign.ErrSignature) || errors.Is(err, sign.ErrMalformed) {
			ag.Log.Warn("job descartado: " + err.Error())
			return proto.Result{}
		}
		return refuse(p.JobID, err.Error())
	}
	if ag.seen.Has(p.JobID) {
		return refuse(p.JobID, "replay: job já executado")
	}
	action, err := catalog.Validate(p.Action, runtime.GOOS, p.Params)
	if err != nil {
		return refuse(p.JobID, err.Error())
	}
	// marca ANTES de executar: no máximo uma execução por job, mesmo se cair no meio
	if err := ag.seen.Add(p.JobID, p.ExpiresAt.Add(proto.ClockSkew)); err != nil {
		return refuse(p.JobID, "não consegui registrar o job (replay): "+err.Error())
	}
	ag.Log.Info("executando", "job", p.JobID, "acao", p.Action, "emissor", p.Issuer)
	res := proto.Result{JobID: p.JobID, StartedAt: ag.now()}
	var out string
	var code int
	var trunc bool
	if action.Native {
		// ação nativa: intercepta ANTES do pipeline de script
		out, code, res.Escrow, err = ag.runNative(ctx, action, p)
	} else {
		out, code, trunc, err = ag.exec(ctx, action, p.Params)
	}
	res.FinishedAt, res.Output, res.ExitCode, res.Truncated = ag.now(), out, code, trunc
	res.Status = "ok"
	if err != nil {
		res.Status, res.Error = "erro", err.Error()
	} else if code != 0 {
		res.Status = "erro"
	}
	ag.Log.Info("concluído", "job", p.JobID, "status", res.Status, "codigo", code)
	return res
}

// Run é o loop do serviço; termina quando ctx é cancelado.
func (ag *Agent) Run(ctx context.Context) {
	lock, err := lockDir(ag.Dir)
	if err != nil {
		ag.Log.Error("não iniciei: " + err.Error())
		return
	}
	defer lock.unlock()
	ag.Log.Info("agente iniciado", "versao", Version, "servidor", ag.bundle.ServerURL, "dados", ag.Dir)
	backoff := time.Duration(0)
	for {
		var err error
		wait := ag.interval
		if !ag.enrolled() {
			var ok bool
			ok, err = ag.enroll(ctx)
			// enquanto aguarda aprovação, checa de novo em segundos (o
			// intervalo de check-in só passa a valer depois de inscrito)
			wait = enrollPoll
			if ok {
				wait = time.Second
			}
		} else {
			err = ag.CheckinOnce(ctx)
		}
		if err != nil {
			var he *httpError
			switch {
			case errors.As(err, &he) && he.code == http.StatusForbidden && ag.enrolled():
				ag.Log.Error("servidor recusou o agente (revogado?)", "erro", err)
				backoff = revokedBackoff
			default:
				ag.Log.Error("ciclo falhou", "erro", err)
				backoff = min(max(2*backoff, 30*time.Second), maxBackoff)
			}
			wait = backoff
		} else {
			backoff = 0
		}
		// jitter de até 10% para 200+ máquinas não baterem juntas
		wait += time.Duration(rand.Int64N(int64(wait)/10 + 1))
		select {
		case <-ctx.Done():
			ag.Log.Info("agente parando")
			return
		case <-time.After(wait):
		}
	}
}

// Status resume o estado local (comando `status`).
func (ag *Agent) Status() string {
	var b strings.Builder
	fmt.Fprintf(&b, "versão:    %s\nservidor:  %s\ndados:     %s\n", Version, ag.bundle.ServerURL, ag.Dir)
	fmt.Fprintf(&b, "agente:    %s\n", ag.state.AgentID)
	if cert, err := pki.LoadCert(filepath.Join(ag.Dir, fileCert)); err == nil {
		fmt.Fprintf(&b, "inscrito:  sim (certificado até %s)\n", cert.NotAfter.Format(time.DateOnly))
	} else if ag.state.AgentID != "" {
		b.WriteString("inscrito:  aguardando aprovação no servidor\n")
	} else {
		b.WriteString("inscrito:  não\n")
	}
	return b.String()
}
