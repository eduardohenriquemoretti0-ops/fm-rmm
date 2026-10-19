// fmrmm-server: servidor e console de administração do FM-RMM.
//
// Rode `fmrmm-server ajuda` para a lista de comandos.
package main

import (
	"bufio"
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"github.com/eduardohenriquemoretti0-ops/fm-rmm/internal/agent"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"os/user"
	"path/filepath"
	"strings"
	"syscall"
	"text/tabwriter"
	"time"

	"github.com/eduardohenriquemoretti0-ops/fm-rmm/internal/audit"
	"github.com/eduardohenriquemoretti0-ops/fm-rmm/internal/catalog"
	"github.com/eduardohenriquemoretti0-ops/fm-rmm/internal/console"
	"github.com/eduardohenriquemoretti0-ops/fm-rmm/internal/pki"
	"github.com/eduardohenriquemoretti0-ops/fm-rmm/internal/proto"
	"github.com/eduardohenriquemoretti0-ops/fm-rmm/internal/server"
	"github.com/eduardohenriquemoretti0-ops/fm-rmm/internal/sign"
)

var Version = "dev"

const help = `fmrmm-server — servidor do FM-RMM

Configuração (uma vez):
  init     --dir D --hosts rmm.exemplo.com,203.0.113.10   cria CA, certificado do servidor e banco
  keygen   --out admin.key                                 chave de assinatura do ADMIN (guarde fora do servidor)
  bundle   --dir D --url https://rmm.exemplo.com --key admin.key --out bundle.json
                                                           pacote público do agente (CA + chave pública do admin)
Operação:
  serve    --dir D [--listen :443] [--relay :8443] [--relay-url wss://rmm.exemplo.com:8443] [--interval 60s]
  token    --dir D [--label X] [--uses 1] [--ttl 24h]      token de inscrição (mostrado uma vez)
  agents   --dir D [list|approve ID...|approve-all|reject ID|revoke ID|group ID GRUPO]
  jobs     --dir D new --key admin.key --agent ID|todos --action A [--param k=v] [--ttl 1h]
  jobs     --dir D list [--agent ID] | show JOB
  techs    --dir D [list|add NOME|disable NOME|enable NOME|grant NOME GRUPO|revoke NOME GRUPO]  (acesso remoto; GRUPO '*' = todas)
  session  --dir D new --key admin.key --agent ID --tech NOME [--mode view|control] [--ttl 15m]  (indicador SEMPRE visível)
  session  --dir D list
  view     --dir D --relay-url wss://host:8443 --session ses-... --token TOK --out DIR [--frames N]  (console: recebe e salva a tela)
  audit    --dir D verify | list [--tail 50]
Operadores do console (ver docs/console-onboarding-operador.md):
  operadores create --dir D --tech TECNICO --nome N [--display X]   cria (status pendente); imprime o id
  operadores csr    --nome N --out DIR                      MÁQUINA DO OPERADOR: gera operador.key (0600, fica aqui) + operador.csr
  operadores assinar-csr --dir D --id OPID --csr operador.csr --out DIR [--reemitir]
                                                           PRODUÇÃO: valida o CSR, emite operador.crt + ca.crt e liga o thumbprint
  operadores cert   --dir D --id OPID --out DIR [--reemitir]        SÓ LAB: gera a chave NO servidor + cert (não use em produção)
  operadores list   --dir D                                         id, técnico, status, tem_cert, credenciais, tem_signing_pub
  operadores activate --dir D --id OPID                             ativa (exige cert e 2 credenciais WebAuthn)
Lista de signers (trust-set dos agentes; a RAIZ fica OFFLINE):
  signers  --dir D export [--out export.json]              versão atual + operadores aptos (sem segredos)
  signers  build --key admin.key (--export export.json | --operators-file ops.json [--versao-atual N]) [--out DIR]
                                                           OFFLINE: monta e assina trust-list.json + trust-list.sig
  signers  --dir D publish --raiz KEYID --lista trust-list.json --sig trust-list.sig
                                                           publica a lista assinada (confere a raiz; só versão maior)
  cve      --dir D scan --agent ID|todos [--linux-ecosystem Debian:12]   cruza o inventário software com o OSV.dev (read-only)
  cve      --dir D show --agent ID                         resumo (JSON) das vulnerabilidades já gravadas
  catalog                                                  ações disponíveis
  version`

func main() {
	if len(os.Args) < 2 {
		fmt.Println(help)
		os.Exit(2)
	}
	cmd, args := os.Args[1], os.Args[2:]
	var err error
	switch cmd {
	case "init":
		err = cmdInit(args)
	case "keygen":
		err = cmdKeygen(args)
	case "bundle":
		err = cmdBundle(args)
	case "serve":
		err = cmdServe(args)
	case "token":
		err = cmdToken(args)
	case "agents":
		err = cmdAgents(args)
	case "jobs":
		err = cmdJobs(args)
	case "techs":
		err = cmdTechs(args)
	case "session":
		err = cmdSession(args)
	case "view":
		err = cmdView(args)
	case "audit":
		err = cmdAudit(args)
	case "signers":
		err = cmdSigners(args)
	case "operadores":
		err = cmdOperadores(args)
	case "cve":
		err = cmdCVE(args)
	case "catalog":
		cmdCatalog()
	case "version":
		fmt.Println(Version)
	default:
		fmt.Println(help)
		os.Exit(2)
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "erro:", err)
		os.Exit(1)
	}
}

func actor() string {
	if u, err := user.Current(); err == nil {
		return "admin:" + u.Username
	}
	return "admin"
}

func dirFlag(fs *flag.FlagSet) *string {
	return fs.String("dir", "/var/lib/fmrmm-server", "diretório do servidor")
}

func openStore(dir string) (*server.Store, error) {
	if _, err := os.Stat(filepath.Join(dir, server.FileCA)); err != nil {
		return nil, fmt.Errorf("servidor não inicializado em %s (rode init)", dir)
	}
	return server.OpenStore(filepath.Join(dir, server.FileDB))
}

// ------------------------------------------------------------- configuração

func cmdInit(args []string) error {
	fs := flag.NewFlagSet("init", flag.ExitOnError)
	dir := dirFlag(fs)
	hosts := fs.String("hosts", "", "nomes/IPs do servidor, separados por vírgula")
	name := fs.String("ca-name", "FM-RMM CA", "nome da CA")
	fs.Parse(args)
	if *hosts == "" {
		return errors.New("informe --hosts")
	}
	if err := os.MkdirAll(*dir, 0o700); err != nil {
		return err
	}
	if _, err := os.Stat(filepath.Join(*dir, server.FileCA)); err == nil {
		return errors.New("já inicializado (recriar a CA invalida TODOS os agentes)")
	}
	ca, caKey, err := pki.NewCA(*name)
	if err != nil {
		return err
	}
	srv, srvKey, err := pki.NewServerCert(ca, caKey, strings.Split(*hosts, ","))
	if err != nil {
		return err
	}
	caDER, _ := pki.KeyDER(caKey)
	srvDER, _ := pki.KeyDER(srvKey)
	for _, f := range []struct {
		name, typ string
		der       []byte
	}{{server.FileCA, "CERTIFICATE", ca.Raw}, {server.FileCAKey, "PRIVATE KEY", caDER}, {server.FileCert, "CERTIFICATE", srv.Raw}, {server.FileKey, "PRIVATE KEY", srvDER}} {
		if err := pki.WritePEM(filepath.Join(*dir, f.name), f.typ, f.der); err != nil {
			return err
		}
	}
	st, err := server.OpenStore(filepath.Join(*dir, server.FileDB))
	if err != nil {
		return err
	}
	defer st.Close()
	fmt.Printf("servidor inicializado em %s\nCA: %s (válida até %s)\ncertificado do servidor para: %s\n", *dir, *name, ca.NotAfter.Format(time.DateOnly), *hosts)
	return st.Audit("servidor.inicializado", actor(), map[string]any{"hosts": *hosts})
}

func cmdKeygen(args []string) error {
	fs := flag.NewFlagSet("keygen", flag.ExitOnError)
	out := fs.String("out", "admin.key", "arquivo da chave privada")
	fs.Parse(args)
	pub, err := sign.GenerateKey(*out)
	if err != nil {
		return err
	}
	fmt.Printf("chave criada: %s (permissão 600)\nkey_id: %s\npública: %s\nGuarde a chave privada FORA do servidor. Quem tem essa chave emite comandos.\n",
		*out, sign.KeyID(pub), sign.EncodePub(pub))
	return nil
}

func cmdBundle(args []string) error {
	fs := flag.NewFlagSet("bundle", flag.ExitOnError)
	dir := dirFlag(fs)
	url := fs.String("url", "", "URL https do servidor vista pelos agentes")
	key := fs.String("key", "", "chave privada do admin (só a pública vai para o bundle)")
	pubFlag := fs.String("signer-pub", "", "OU a chave pública do admin em base64")
	rdHost := fs.String("rustdesk-host", "", "host do hbbs do RustDesk self-hosted (opcional)")
	rdKey := fs.String("rustdesk-key", "", "chave pública do hbbs do RustDesk (base64; pinning)")
	out := fs.String("out", "bundle.json", "arquivo de saída")
	fs.Parse(args)
	if !strings.HasPrefix(*url, "https://") {
		return errors.New("--url precisa ser https://")
	}
	var pubB64 string
	switch {
	case *key != "":
		priv, err := sign.LoadPrivate(*key)
		if err != nil {
			return err
		}
		pubB64 = sign.EncodePub(priv.Public().(ed25519.PublicKey))
	case *pubFlag != "":
		pubB64 = *pubFlag
	default:
		return errors.New("informe --key ou --signer-pub")
	}
	pub, err := sign.DecodePub(pubB64)
	if err != nil {
		return err
	}
	caPEM, err := os.ReadFile(filepath.Join(*dir, server.FileCA))
	if err != nil {
		return err
	}
	if err := server.AddSigner(*dir, pub); err != nil {
		return err
	}
	b, _ := json.MarshalIndent(proto.Bundle{ServerURL: *url, CAPEM: string(caPEM), SignerPub: sign.EncodePub(pub), SignerID: sign.KeyID(pub), RustDeskHost: *rdHost, RustDeskKey: *rdKey}, "", "  ")
	if err := os.WriteFile(*out, b, 0o644); err != nil {
		return err
	}
	rd := "sem RustDesk"
	if *rdHost != "" {
		rd = "RustDesk " + *rdHost
	}
	fmt.Printf("bundle gravado: %s (público: CA + chave pública do admin %s; %s)\n", *out, sign.KeyID(pub), rd)
	return nil
}

// ----------------------------------------------------------------- operação

func cmdServe(args []string) error {
	fs := flag.NewFlagSet("serve", flag.ExitOnError)
	dir := dirFlag(fs)
	listen := fs.String("listen", ":443", "endereço:porta do servidor de controle")
	relayListen := fs.String("relay", ":8443", "endereço:porta do relay de sessão (vazio desliga)")
	interval := fs.Duration("interval", 60*time.Second, "intervalo de check-in dos agentes")
	relayURL := fs.String("relay-url", "", "URL wss:// do relay entregue ao console (obrigatória para concessões de sessão remota)")
	consoleAddr := fs.String("console-addr", "", "endereço:porta do console web (listener dedicado, mTLS obrigatório); vazio desliga")
	rpID := fs.String("rp-id", "", "WebAuthn: domínio do console, sem porta (obrigatório com --console-addr)")
	var rpOrigins multi
	fs.Var(&rpOrigins, "rp-origin", "WebAuthn: origem https do console, ex. https://rmm.exemplo.com:9443 (repetível; obrigatória com --console-addr)")
	webDist := fs.String("web-dist", "web/dist", "diretório do SPA compilado servido pelo console")
	fs.Parse(args)
	if *consoleAddr != "" && (*rpID == "" || len(rpOrigins) == 0) {
		return errors.New("--console-addr exige --rp-id e ao menos um --rp-origin")
	}
	st, err := openStore(*dir)
	if err != nil {
		return err
	}
	defer st.Close()
	entries, err := st.AuditEntries()
	if err != nil {
		return err
	}
	if err := audit.Verify(entries); err != nil {
		return fmt.Errorf("log de auditoria adulterado, servidor não sobe: %w", err)
	}
	ca, err := pki.LoadCert(filepath.Join(*dir, server.FileCA))
	if err != nil {
		return err
	}
	caKey, err := pki.LoadKey(filepath.Join(*dir, server.FileCAKey))
	if err != nil {
		return err
	}
	cert, err := tls.LoadX509KeyPair(filepath.Join(*dir, server.FileCert), filepath.Join(*dir, server.FileKey))
	if err != nil {
		return err
	}
	signers, err := server.LoadSigners(*dir)
	if err != nil {
		return err
	}
	if len(signers) == 0 {
		return errors.New("nenhuma chave de admin cadastrada (rode bundle)")
	}
	log := slog.New(slog.NewTextHandler(os.Stderr, nil))
	s := &server.Server{Store: st, CA: ca, CAKey: caKey, Signers: signers, Interval: *interval, Log: log}
	hs := server.NewHTTPServer(*listen, s.Handler(), server.TLSConfig(ca, cert))
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	// relay de sessão: TLS simples (sem exigir cert de cliente; o pareamento é
	// pelo token da concessão). Roda em porta própria.
	var relaySrv *http.Server
	if *relayListen != "" {
		rl := server.NewRelay(st, log)
		relaySrv = &http.Server{Addr: *relayListen, Handler: rl.Handler(),
			TLSConfig:         &tls.Config{MinVersion: tls.VersionTLS12, Certificates: []tls.Certificate{cert}},
			ReadHeaderTimeout: 10 * time.Second}
		go func() {
			log.Info("relay de sessão no ar", "endereco", *relayListen)
			if err := relaySrv.ListenAndServeTLS("", ""); err != nil && !errors.Is(err, http.ErrServerClosed) {
				log.Error("relay", "erro", err)
			}
		}()
	}
	// console web: listener dedicado, separado do dos agentes (que não exige
	// cert de cliente no handshake).
	var consoleSrv *http.Server
	if *consoleAddr != "" {
		var consoleSM *console.SessionManager
		consoleSrv, consoleSM, err = novoServidorConsole(*consoleAddr, st, ca, cert, *interval, console.ConfigWebAuthn{
			RPID: *rpID, RPOrigins: rpOrigins}, *relayURL, *webDist)
		if err != nil {
			return err
		}
		go func() {
			log.Info("console no ar (mTLS obrigatório)", "endereco", *consoleAddr, "rp_id", *rpID)
			if err := consoleSrv.ListenAndServeTLS("", ""); err != nil && !errors.Is(err, http.ErrServerClosed) {
				log.Error("console", "erro", err)
			}
		}()
		go func() {
			t := time.NewTicker(time.Minute)
			defer t.Stop()
			for {
				select {
				case <-ctx.Done():
					return
				case <-t.C:
					consoleSM.GC()
				}
			}
		}()
	}
	go func() {
		<-ctx.Done()
		sctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		_ = hs.Shutdown(sctx)
		if consoleSrv != nil {
			_ = consoleSrv.Shutdown(sctx)
		}
		if relaySrv != nil {
			_ = relaySrv.Shutdown(sctx)
		}
	}()
	log.Info("servidor no ar", "endereco", *listen, "versao", Version, "agentes_aprovados", countApproved(st), "chaves_admin", len(signers))
	_ = st.Audit("servidor.iniciado", "servidor", map[string]any{"endereco": *listen, "versao": Version})
	if err := hs.ListenAndServeTLS("", ""); err != nil && !errors.Is(err, http.ErrServerClosed) {
		return err
	}
	return nil
}

// novoServidorConsole monta o http.Server do console: mTLS obrigatório
// (TLSConfigConsole), sessões 15min/10min ocioso (docs/console-seguranca.md),
// API + estáticos do SPA na mesma origem sob SecurityHeaders.
func novoServidorConsole(addr string, st *server.Store, ca *x509.Certificate, cert tls.Certificate,
	interval time.Duration, wa console.ConfigWebAuthn, relayURL, webDist string) (*http.Server, *console.SessionManager, error) {
	if relayURL != "" {
		u, err := url.Parse(relayURL)
		if err != nil || u.Scheme != "wss" || u.Host == "" {
			return nil, nil, fmt.Errorf("--relay-url %q inválida: exige wss://host", relayURL)
		}
	}
	if fi, err := os.Stat(filepath.Join(webDist, "index.html")); err != nil || fi.IsDir() {
		return nil, nil, fmt.Errorf("--web-dist %q sem index.html (rode o build em web/)", webDist)
	}
	tc, err := console.TLSConfigConsole(ca, cert)
	if err != nil {
		return nil, nil, err
	}
	pool := x509.NewCertPool()
	pool.AddCert(ca)
	sm := console.NewSessionManager(15*time.Minute, 10*time.Minute)
	aut, err := console.NovoAutenticador(wa, st, sm)
	if err != nil {
		return nil, nil, err
	}
	c, err := console.NovoConsole(sm, aut, st, pool, interval)
	if err != nil {
		return nil, nil, err
	}
	c.ConfigurarRelay(relayURL)
	c.ServirEstaticos(webDist)
	return server.NewHTTPServer(addr, c.Roteador(), tc), sm, nil
}

func countApproved(st *server.Store) int {
	a, _ := st.Agents("approved")
	return len(a)
}

func cmdToken(args []string) error {
	fs := flag.NewFlagSet("token", flag.ExitOnError)
	dir := dirFlag(fs)
	label := fs.String("label", "", "descrição (ex.: cliente-x lote 1)")
	uses := fs.Int("uses", 1, "quantas máquinas podem usar (todas ainda precisam de aprovação)")
	ttl := fs.Duration("ttl", 24*time.Hour, "validade")
	fs.Parse(args)
	st, err := openStore(*dir)
	if err != nil {
		return err
	}
	defer st.Close()
	id, tok, err := st.NewToken(*label, *uses, *ttl)
	if err != nil {
		return err
	}
	if err := st.Audit("token.criado", actor(), map[string]any{"token": id, "label": *label, "usos": *uses, "validade": ttl.String()}); err != nil {
		return err
	}
	fmt.Printf("token %s (%d uso(s), vale %s) — mostrado só agora:\n%s\n", id, *uses, *ttl, tok)
	return nil
}

func cmdAgents(args []string) error {
	fs := flag.NewFlagSet("agents", flag.ExitOnError)
	dir := dirFlag(fs)
	fs.Parse(args)
	rest := fs.Args()
	sub := "list"
	if len(rest) > 0 {
		sub, rest = rest[0], rest[1:]
	}
	st, err := openStore(*dir)
	if err != nil {
		return err
	}
	defer st.Close()
	loadCA := func() (*server.Server, error) {
		ca, err := pki.LoadCert(filepath.Join(*dir, server.FileCA))
		if err != nil {
			return nil, err
		}
		k, err := pki.LoadKey(filepath.Join(*dir, server.FileCAKey))
		return &server.Server{CA: ca, CAKey: k}, err
	}
	switch sub {
	case "list":
		ags, err := st.Agents("")
		if err != nil {
			return err
		}
		tw := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
		fmt.Fprintln(tw, "AGENTE\tHOST\tSO\tSTATUS\tCONEXÃO\tÚLTIMO CONTATO\tIP DA INSCRIÇÃO")
		now := time.Now()
		// tolerância = 2× o intervalo padrão do check-in (60s); uma batida perdida
		// ainda conta como online.
		const checkinInterval = 60 * time.Second
		for _, a := range ags {
			seen := "-"
			if a.LastSeen > 0 {
				seen = time.Since(time.Unix(a.LastSeen, 0)).Round(time.Second).String() + " atrás"
			}
			conexao := "offline"
			if a.Online(checkinInterval, now) {
				conexao = "online"
			}
			fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%s\t%s\t%s\n", a.ID, a.Hostname, a.OS, a.Status, conexao, seen, a.RemoteAddr)
		}
		return tw.Flush()
	case "approve", "approve-all":
		s, err := loadCA()
		if err != nil {
			return err
		}
		ids := rest
		if sub == "approve-all" {
			pend, err := st.Agents("pending")
			if err != nil {
				return err
			}
			ids = nil
			for _, a := range pend {
				ids = append(ids, a.ID)
			}
		}
		if len(ids) == 0 {
			return errors.New("nenhum agente para aprovar")
		}
		for _, id := range ids {
			if err := server.ApproveAgent(st, s.CA, s.CAKey, id, actor()); err != nil {
				return fmt.Errorf("%s: %w", id, err)
			}
			fmt.Println("aprovado:", id)
		}
		return nil
	case "reject", "revoke":
		if len(rest) != 1 {
			return fmt.Errorf("uso: agents %s ID", sub)
		}
		from, to := "pending", "rejected"
		if sub == "revoke" {
			from, to = "approved", "revoked"
		}
		if err := st.SetStatus(rest[0], from, to); err != nil {
			return fmt.Errorf("%s: agente não está %s", rest[0], from)
		}
		fmt.Printf("%s: %s\n", rest[0], to)
		return st.Audit("agente."+to, actor(), map[string]any{"agente": rest[0]})
	case "group":
		if len(rest) != 2 {
			return errors.New("uso: agents group ID GRUPO")
		}
		if err := st.SetAgentGroup(rest[0], rest[1]); err != nil {
			return err
		}
		fmt.Printf("%s -> grupo %s\n", rest[0], rest[1])
		return st.Audit("agente.grupo", actor(), map[string]any{"agente": rest[0], "grupo": rest[1]})
	}
	return fmt.Errorf("subcomando desconhecido: %s", sub)
}

type kv map[string]string

func (m kv) String() string { return fmt.Sprint(map[string]string(m)) }
func (m kv) Set(s string) error {
	k, v, ok := strings.Cut(s, "=")
	if !ok {
		return errors.New("use chave=valor")
	}
	m[k] = v
	return nil
}

type multi []string

func (m *multi) String() string     { return strings.Join(*m, ",") }
func (m *multi) Set(s string) error { *m = append(*m, s); return nil }

func cmdJobs(args []string) error {
	fs := flag.NewFlagSet("jobs", flag.ExitOnError)
	dir := dirFlag(fs)
	fs.Parse(args)
	rest := fs.Args()
	if len(rest) == 0 {
		return errors.New("uso: jobs new|list|show")
	}
	st, err := openStore(*dir)
	if err != nil {
		return err
	}
	defer st.Close()
	switch rest[0] {
	case "new":
		nf := flag.NewFlagSet("jobs new", flag.ExitOnError)
		key := nf.String("key", "", "chave privada do admin")
		var agents multi
		nf.Var(&agents, "agent", "ID do agente (repita para vários) ou 'todos'")
		action := nf.String("action", "", "ação do catálogo")
		params := kv{}
		nf.Var(params, "param", "parâmetro chave=valor")
		ttl := nf.Duration("ttl", time.Hour, "validade do job")
		by := nf.String("by", actor(), "quem emite (vai na assinatura e na auditoria)")
		nf.Parse(rest[1:])
		priv, err := sign.LoadPrivate(*key)
		if err != nil {
			return fmt.Errorf("chave do admin: %w", err)
		}
		signers, err := server.LoadSigners(*dir)
		if err != nil {
			return err
		}
		if len(agents) == 1 && agents[0] == "todos" {
			ap, err := st.Agents("approved")
			if err != nil {
				return err
			}
			agents = nil
			for _, a := range ap {
				agents = append(agents, a.ID)
			}
		}
		if len(agents) == 0 {
			return errors.New("informe --agent")
		}
		failed := 0
		for _, id := range agents {
			jid, err := server.NewJob(st, priv, signers, id, *action, params, *ttl, *by)
			if err != nil {
				fmt.Fprintf(os.Stderr, "%s: %v\n", id, err)
				failed++
				continue
			}
			fmt.Printf("%s -> %s (%s)\n", jid, id, *action)
		}
		if failed > 0 {
			return fmt.Errorf("%d job(s) não criados", failed)
		}
		return nil
	case "list":
		lf := flag.NewFlagSet("jobs list", flag.ExitOnError)
		agent := lf.String("agent", "", "filtrar por agente")
		limit := lf.Int("limit", 50, "máximo de linhas")
		lf.Parse(rest[1:])
		jobs, err := st.Jobs(*agent, *limit)
		if err != nil {
			return err
		}
		tw := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
		fmt.Fprintln(tw, "JOB\tAGENTE\tAÇÃO\tSTATUS\tCRIADO\tEMISSOR")
		for _, j := range jobs {
			fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%s\t%s\n", j.ID, j.AgentID, j.Action, j.Status, time.Unix(j.CreatedAt, 0).Format("02/01 15:04:05"), j.Issuer)
		}
		return tw.Flush()
	case "show":
		if len(rest) != 2 {
			return errors.New("uso: jobs show JOB")
		}
		j, err := st.Job(rest[1])
		if err != nil {
			return err
		}
		fmt.Printf("job:      %s\nagente:   %s\nação:     %s %s\nstatus:   %s\nemissor:  %s\n", j.ID, j.AgentID, j.Action, j.Params, j.Status, j.Issuer)
		if j.Result == "" {
			return nil
		}
		var r proto.Result
		if err := json.Unmarshal([]byte(j.Result), &r); err != nil {
			return err
		}
		fmt.Printf("resultado: %s (código %d) em %s\n", r.Status, r.ExitCode, r.FinishedAt.Sub(r.StartedAt).Round(time.Millisecond))
		if r.Error != "" {
			fmt.Println("erro:", r.Error)
		}
		if r.Truncated {
			fmt.Println("(saída truncada)")
		}
		fmt.Println("----")
		fmt.Println(r.Output)
		return nil
	}
	return fmt.Errorf("subcomando desconhecido: %s", rest[0])
}

func cmdTechs(args []string) error {
	fs := flag.NewFlagSet("techs", flag.ExitOnError)
	dir := dirFlag(fs)
	fs.Parse(args)
	rest := fs.Args()
	st, err := openStore(*dir)
	if err != nil {
		return err
	}
	defer st.Close()
	sub := "list"
	if len(rest) > 0 {
		sub, rest = rest[0], rest[1:]
	}
	switch sub {
	case "list":
		ts, err := st.Techs()
		if err != nil {
			return err
		}
		tw := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
		fmt.Fprintln(tw, "TÉCNICO\tSTATUS\tGRUPOS")
		for _, t := range ts {
			status := "ativo"
			if t.Disabled {
				status = "DESABILITADO"
			}
			fmt.Fprintf(tw, "%s\t%s\t%s\n", t.Name, status, strings.Join(t.Groups, ", "))
		}
		return tw.Flush()
	case "add":
		if len(rest) != 1 {
			return errors.New("uso: techs add NOME")
		}
		if err := st.AddTech(rest[0]); err != nil {
			return err
		}
		fmt.Println("técnico:", rest[0])
		return st.Audit("tecnico.criado", actor(), map[string]any{"tecnico": rest[0]})
	case "disable", "enable":
		if len(rest) != 1 {
			return fmt.Errorf("uso: techs %s NOME", sub)
		}
		if err := st.DisableTech(rest[0], sub == "disable"); err != nil {
			return err
		}
		fmt.Printf("%s: %s\n", rest[0], sub+"d")
		return st.Audit("tecnico."+sub, actor(), map[string]any{"tecnico": rest[0]})
	case "grant":
		if len(rest) != 2 {
			return errors.New("uso: techs grant NOME GRUPO  (GRUPO '*' = todas)")
		}
		if err := st.GrantGroup(rest[0], rest[1]); err != nil {
			return err
		}
		fmt.Printf("%s -> grupo %s\n", rest[0], rest[1])
		return st.Audit("tecnico.grupo.concedido", actor(), map[string]any{"tecnico": rest[0], "grupo": rest[1]})
	case "revoke":
		if len(rest) != 2 {
			return errors.New("uso: techs revoke NOME GRUPO")
		}
		if err := st.RevokeGroup(rest[0], rest[1]); err != nil {
			return err
		}
		fmt.Printf("%s: grupo %s removido\n", rest[0], rest[1])
		return st.Audit("tecnico.grupo.revogado", actor(), map[string]any{"tecnico": rest[0], "grupo": rest[1]})
	}
	return fmt.Errorf("subcomando desconhecido: %s", sub)
}

func cmdSession(args []string) error {
	fs := flag.NewFlagSet("session", flag.ExitOnError)
	dir := dirFlag(fs)
	fs.Parse(args)
	rest := fs.Args()
	if len(rest) == 0 {
		return errors.New("uso: session new|list")
	}
	st, err := openStore(*dir)
	if err != nil {
		return err
	}
	defer st.Close()
	switch rest[0] {
	case "new":
		nf := flag.NewFlagSet("session new", flag.ExitOnError)
		key := nf.String("key", "", "chave privada do admin")
		agentID := nf.String("agent", "", "agente alvo")
		tech := nf.String("tech", "", "técnico que vai acessar")
		mode := nf.String("mode", "view", "view|control")
		engine := nf.String("engine", "", "screenshot|rustdesk (vazio = automático pelo SO do agente)")
		relayURL := nf.String("relay-url", "", "URL do relay (wss://...); padrão: pergunta ao operador")
		ttl := nf.Duration("ttl", 15*time.Minute, "validade da sessão (máx 30m)")
		by := nf.String("by", actor(), "quem autoriza")
		nf.Parse(rest[1:])
		priv, err := sign.LoadPrivate(*key)
		if err != nil {
			return fmt.Errorf("chave do admin: %w", err)
		}
		signers, err := server.LoadSigners(*dir)
		if err != nil {
			return err
		}
		if *relayURL == "" {
			return errors.New("informe --relay-url (ex.: wss://rmm.exemplo.com:8443)")
		}
		// motor automático: Windows usa RustDesk (resolve Session 0), demais usam captura em quadros
		eng := *engine
		if eng == "" {
			a, err := st.Agent(*agentID)
			if err != nil {
				return err
			}
			eng = proto.EngineScreenshot
			if a.OS == "windows" {
				eng = proto.EngineRustDesk
			}
		}
		g, relayToken, err := server.CreateSession(st, priv, signers, *agentID, *tech, *mode, eng, *relayURL, *ttl, *by)
		if err != nil {
			return err
		}
		fmt.Printf("sessão %s autorizada para %s acessar %s (%s, motor %s), vale %s\n", g.SessionID, *tech, *agentID, *mode, eng, *ttl)
		fmt.Printf("indicador de sessão: SEMPRE visível no endpoint\n")
		if eng == proto.EngineRustDesk {
			fmt.Printf("RustDesk: o console recebe o ID pelo canal de controle; senha de uso único desta sessão: %s\n", g.MediaSecret)
		}
		fmt.Printf("console conecta em %s  (X-Session-ID: %s  X-Relay-Token: %s)\n", *relayURL, g.SessionID, relayToken)
		return nil
	case "list":
		ss, err := st.Sessions(50)
		if err != nil {
			return err
		}
		tw := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
		fmt.Fprintln(tw, "SESSÃO\tAGENTE\tTÉCNICO\tMODO\tSTATUS\tCRIADA")
		for _, x := range ss {
			fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%s\t%s\n", x.ID, x.AgentID, x.Technician, x.Mode, x.Status, time.Unix(x.CreatedAt, 0).Format("02/01 15:04"))
		}
		return tw.Flush()
	}
	return fmt.Errorf("subcomando desconhecido: %s", rest[0])
}

func cmdAudit(args []string) error {
	fs := flag.NewFlagSet("audit", flag.ExitOnError)
	dir := dirFlag(fs)
	fs.Parse(args)
	rest := fs.Args()
	st, err := openStore(*dir)
	if err != nil {
		return err
	}
	defer st.Close()
	entries, err := st.AuditEntries()
	if err != nil {
		return err
	}
	sub := "verify"
	if len(rest) > 0 {
		sub = rest[0]
	}
	switch sub {
	case "verify":
		if err := audit.Verify(entries); err != nil {
			return err
		}
		fmt.Printf("auditoria íntegra: %d entradas, cadeia de hash confere\n", len(entries))
		return nil
	case "list":
		lf := flag.NewFlagSet("audit list", flag.ExitOnError)
		tail := lf.Int("tail", 50, "últimas N entradas")
		lf.Parse(rest[1:])
		if len(entries) > *tail {
			entries = entries[len(entries)-*tail:]
		}
		for _, e := range entries {
			fmt.Printf("%5d %s %-22s %-28s %s\n", e.Seq, e.TS.Local().Format("02/01 15:04:05"), e.Event, e.Actor, e.Data)
		}
		return nil
	}
	return fmt.Errorf("subcomando desconhecido: %s", sub)
}

// cmdView é o lado CONSOLE da sessão: conecta no relay (verificando a nossa CA),
// faz o upgrade "fm-relay" e salva os quadros de tela recebidos do agente.
func cmdView(args []string) error {
	fs := flag.NewFlagSet("view", flag.ExitOnError)
	dir := dirFlag(fs)
	relayURL := fs.String("relay-url", "", "wss://host:porta do relay")
	sid := fs.String("session", "", "id da sessão (ses-...)")
	tok := fs.String("token", "", "token de relay da sessão")
	out := fs.String("out", "sessao-frames", "pasta para salvar os quadros PNG")
	frames := fs.Int("frames", 0, "parar após N quadros (0 = até Ctrl+C)")
	fs.Parse(args)
	if *relayURL == "" || *sid == "" || *tok == "" {
		return errors.New("informe --relay-url, --session e --token")
	}
	u, err := url.Parse(*relayURL)
	if err != nil {
		return err
	}
	// pinning: o console também só confia na nossa CA
	caPEM, err := os.ReadFile(filepath.Join(*dir, server.FileCA))
	if err != nil {
		return err
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(caPEM) {
		return errors.New("CA inválida")
	}
	host := u.Host
	if u.Port() == "" {
		host = net.JoinHostPort(u.Hostname(), "443")
	}
	conn, err := tls.Dial("tcp", host, &tls.Config{MinVersion: tls.VersionTLS12, RootCAs: pool, ServerName: u.Hostname()})
	if err != nil {
		return err
	}
	defer conn.Close()
	req := fmt.Sprintf("POST /relay HTTP/1.1\r\nHost: %s\r\nUpgrade: fm-relay\r\nConnection: Upgrade\r\nX-Session-ID: %s\r\nX-Relay-Token: %s\r\n\r\n", u.Hostname(), *sid, *tok)
	if _, err := conn.Write([]byte(req)); err != nil {
		return err
	}
	br := bufio.NewReader(conn)
	resp, err := http.ReadResponse(br, nil)
	if err != nil {
		return err
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusSwitchingProtocols {
		return fmt.Errorf("relay respondeu %s", resp.Status)
	}
	// o primeiro frame do canal de controle pode ser metadados do motor RustDesk
	first, err := agent.ReadFrame(br)
	if err != nil {
		if err == io.EOF {
			fmt.Println("sessão encerrada pelo agente")
			return nil
		}
		return err
	}
	var meta struct{ Engine, ID, Host string }
	if json.Unmarshal(first, &meta) == nil && meta.Engine == "rustdesk" {
		// motor RustDesk: os pixels passam pelo hbbr do RustDesk, não por aqui.
		// O console abre o cliente RustDesk apontado para o nosso servidor.
		fmt.Printf("sessão RustDesk pronta.\n  ID do endpoint: %s\n  servidor (hbbs): %s\n", meta.ID, meta.Host)
		fmt.Printf("  No cliente RustDesk (apontado para o nosso hbbs, com a nossa chave): conecte ao ID %s e use a senha de uso único mostrada no 'session new'.\n", meta.ID)
		fmt.Printf("  Mantendo o canal de controle aberto; Ctrl+C encerra a sessão.\n")
		io.Copy(io.Discard, br) // segura o canal até o agente encerrar/expirar
		fmt.Println("sessão encerrada.")
		return nil
	}
	// motor de quadros: o primeiro frame já é uma imagem
	if err := os.MkdirAll(*out, 0o755); err != nil {
		return err
	}
	fmt.Printf("conectado à sessão %s; salvando quadros em %s/\n", *sid, *out)
	save := func(i int, img []byte) error {
		p := filepath.Join(*out, fmt.Sprintf("frame-%04d.png", i))
		if err := os.WriteFile(p, img, 0o644); err != nil {
			return err
		}
		fmt.Printf("quadro %d: %d bytes -> %s\n", i, len(img), p)
		return nil
	}
	if err := save(1, first); err != nil {
		return err
	}
	for i := 2; *frames == 0 || i <= *frames; i++ {
		img, err := agent.ReadFrame(br)
		if err != nil {
			if err == io.EOF {
				fmt.Println("sessão encerrada pelo agente")
				return nil
			}
			return err
		}
		if err := save(i, img); err != nil {
			return err
		}
	}
	return nil
}

// cmdSigners: lista de signers. export e publish falam com o banco (no host do
// servidor); build é OFFLINE e nunca abre o banco nem recebe nada do servidor.
func cmdSigners(args []string) error {
	if len(args) > 0 && args[0] == "build" {
		return cmdSignersBuild(args[1:])
	}
	fs := flag.NewFlagSet("signers", flag.ExitOnError)
	dir := dirFlag(fs)
	fs.Parse(args)
	rest := fs.Args()
	if len(rest) == 0 {
		return errors.New("uso: signers export|build|publish")
	}
	switch rest[0] {
	case "export":
		ef := flag.NewFlagSet("signers export", flag.ExitOnError)
		out := ef.String("out", "", "arquivo de saída (vazio = stdout)")
		ef.Parse(rest[1:])
		st, err := openStore(*dir)
		if err != nil {
			return err
		}
		defer st.Close()
		exp, err := st.ExportarLista()
		if err != nil {
			return err
		}
		b, err := json.MarshalIndent(exp, "", "  ")
		if err != nil {
			return err
		}
		if *out == "" {
			fmt.Println(string(b))
			return nil
		}
		if err := os.WriteFile(*out, append(b, '\n'), 0o600); err != nil {
			return err
		}
		fmt.Printf("export gravado: %s (versão atual %d, %d operador(es) apto(s))\n", *out, exp.VersaoAtual, len(exp.Operadores))
		return nil
	case "publish":
		pf := flag.NewFlagSet("signers publish", flag.ExitOnError)
		raizID := pf.String("raiz", "", "key_id da chave RAIZ (o SignerID do bundle)")
		lista := pf.String("lista", "", "arquivo trust-list.json")
		sigArq := pf.String("sig", "", "arquivo trust-list.sig (base64)")
		pf.Parse(rest[1:])
		if *raizID == "" || *lista == "" || *sigArq == "" {
			return errors.New("informe --raiz, --lista e --sig")
		}
		raw, err := os.ReadFile(*lista)
		if err != nil {
			return err
		}
		sigB64, err := os.ReadFile(*sigArq)
		if err != nil {
			return err
		}
		sig, err := base64.StdEncoding.DecodeString(strings.TrimSpace(string(sigB64)))
		if err != nil {
			return fmt.Errorf("assinatura: base64 inválido: %w", err)
		}
		signers, err := server.LoadSigners(*dir)
		if err != nil {
			return err
		}
		raiz, ok := signers[*raizID]
		if !ok {
			return fmt.Errorf("raiz %s não está nos signers do servidor (use o SignerID do bundle)", *raizID)
		}
		st, err := openStore(*dir)
		if err != nil {
			return err
		}
		defer st.Close()
		versao, err := server.PublicarLista(st, raiz, bytes.TrimRight(raw, "\n"), sig, actor())
		if err != nil {
			return err
		}
		fmt.Printf("lista de signers v%d publicada; os agentes recebem no próximo check-in\n", versao)
		return nil
	}
	return fmt.Errorf("subcomando desconhecido: %s", rest[0])
}

// cmdSignersBuild roda OFFLINE, na máquina do admin que guarda a chave raiz.
func cmdSignersBuild(args []string) error {
	fs := flag.NewFlagSet("signers build", flag.ExitOnError)
	key := fs.String("key", "", "chave privada RAIZ (offline)")
	export := fs.String("export", "", "export do servidor (signers export)")
	opsArq := fs.String("operators-file", "", "OU: JSON com a lista de operadores (array de signer)")
	versaoAtual := fs.Int("versao-atual", 0, "com --operators-file: versão da lista em vigor (a nova será +1)")
	outDir := fs.String("out", ".", "pasta de saída de trust-list.json e trust-list.sig")
	fs.Parse(args)
	if *key == "" {
		return errors.New("informe --key (chave raiz)")
	}
	if (*export == "") == (*opsArq == "") {
		return errors.New("informe exatamente um de --export ou --operators-file")
	}
	priv, err := sign.LoadPrivate(*key)
	if err != nil {
		return fmt.Errorf("chave raiz: %w", err)
	}
	var ops []sign.SignerEntry
	atual := *versaoAtual
	if *export != "" {
		var exp server.ExportLista
		if err := lerJSONEstrito(*export, &exp); err != nil {
			return fmt.Errorf("export: %w", err)
		}
		ops, atual = exp.Operadores, exp.VersaoAtual
	} else if err := lerJSONEstrito(*opsArq, &ops); err != nil {
		return fmt.Errorf("operadores: %w", err)
	}
	raw, sig, versao, err := server.ConstruirLista(priv, atual, ops, time.Now().UTC())
	if err != nil {
		return err
	}
	if err := os.MkdirAll(*outDir, 0o755); err != nil {
		return err
	}
	// O-EXCL: nunca sobrescreve uma lista anterior (guarde as versões)
	if err := escreveNovo(filepath.Join(*outDir, "trust-list.json"), append(raw, '\n')); err != nil {
		return err
	}
	if err := escreveNovo(filepath.Join(*outDir, "trust-list.sig"), []byte(base64.StdEncoding.EncodeToString(sig)+"\n")); err != nil {
		return err
	}
	fmt.Printf("lista v%d assinada pela raiz (offline): %s e %s\n", versao, filepath.Join(*outDir, "trust-list.json"), filepath.Join(*outDir, "trust-list.sig"))
	fmt.Printf("%d operador(es) + raiz. Leve os dois arquivos ao servidor e rode: signers publish\n", len(ops))
	return nil
}

func lerJSONEstrito(path string, v any) error {
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	defer f.Close()
	dec := json.NewDecoder(f)
	dec.DisallowUnknownFields()
	return dec.Decode(v)
}

func escreveNovo(path string, b []byte) error {
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o644)
	if err != nil {
		return fmt.Errorf("%s: %w (mova a versão anterior antes)", path, err)
	}
	if _, err := f.Write(b); err != nil {
		f.Close()
		return err
	}
	return f.Close()
}

func cmdCatalog() {
	tw := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
	fmt.Fprintln(tw, "AÇÃO\tALTERA?\tSISTEMAS\tPARÂMETROS\tDESCRIÇÃO")
	for _, n := range catalog.Names() {
		a, _ := catalog.Get(n)
		var oss, ps []string
		for _, o := range []string{"windows", "linux", "darwin"} {
			if _, ok := a.Scripts[o]; ok {
				oss = append(oss, o)
			}
		}
		for k, p := range a.Params {
			ps = append(ps, fmt.Sprintf("%s=%v", k, p.Allowed))
		}
		alt := "não"
		if a.Changes {
			alt = "SIM"
		}
		fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%s\n", n, alt, strings.Join(oss, ","), strings.Join(ps, " "), a.Desc)
	}
	tw.Flush()
}

// cmdOperadores: onboarding de operador do console (ação de ADMIN, local).
// O grupo/acesso do operador é o do técnico ao qual ele está ligado.
func cmdOperadores(args []string) error {
	if len(args) == 0 {
		return errors.New("uso: operadores create|csr|assinar-csr|cert|list|activate")
	}
	sub, rest := args[0], args[1:]
	fs := flag.NewFlagSet("operadores "+sub, flag.ExitOnError)
	dir := dirFlag(fs)
	tech := fs.String("tech", "", "técnico existente (create)")
	nome := fs.String("nome", "", "nome do operador (create)")
	display := fs.String("display", "", "nome de exibição (create; padrão = nome)")
	id := fs.String("id", "", "id do operador (cert/activate)")
	out := fs.String("out", "", "diretório de saída do cert (cert)")
	reemitir := fs.Bool("reemitir", false, "cert: reemite mesmo já havendo cert (invalida o anterior)")
	csrArq := fs.String("csr", "", "arquivo CSR do operador (assinar-csr)")
	fs.Parse(rest)
	if sub == "csr" { // roda na máquina do operador: não toca no banco/CA
		if *nome == "" || *out == "" {
			return errors.New("informe --nome e --out")
		}
		keyP, csrP, err := server.GerarCSROperador(*nome, *out)
		if err != nil {
			return err
		}
		fmt.Printf("chave privada: %s (0600; NUNCA envie; fica só nesta máquina)\nCSR: %s (envie ao admin)\n", keyP, csrP)
		return nil
	}
	st, err := openStore(*dir)
	if err != nil {
		return err
	}
	defer st.Close()
	switch sub {
	case "assinar-csr":
		if *id == "" || *out == "" || *csrArq == "" {
			return errors.New("informe --id, --csr e --out")
		}
		thumb, cert, err := server.AssinarCSROperador(st, *dir, *id, *csrArq, *out, *reemitir)
		if err != nil {
			return err
		}
		fmt.Printf("operador %s: cert emitido por CSR (válido até %s)\nthumbprint: %s\narquivos em %s: %s, %s\n",
			*id, cert.NotAfter.Format(time.DateOnly), thumb, *out, server.FileOperadorCrt, server.FileOperadorCA)
		fmt.Println("Devolva operador.crt e ca.crt ao operador; ele monta o .p12 com a SUA operador.key.")
		return st.Audit("operador.cert.emitido", actor(), map[string]any{"operador": *id, "thumbprint": thumb, "modo": "csr"})
	case "create":
		if *tech == "" || *nome == "" {
			return errors.New("informe --tech e --nome")
		}
		opID, err := server.NovoIDOperador()
		if err != nil {
			return err
		}
		if *display == "" {
			*display = *nome
		}
		if err := st.CreateOperator(server.Operator{ID: opID, Nome: *nome, DisplayName: *display, TechName: *tech}); err != nil {
			return err
		}
		fmt.Println(opID)
		return st.Audit("operador.criado", actor(), map[string]any{"operador": opID, "tecnico": *tech})
	case "cert":
		if *id == "" || *out == "" {
			return errors.New("informe --id e --out")
		}
		thumb, cert, err := server.EmitirCertOperador(st, *dir, *id, *out, *reemitir)
		if err != nil {
			return err
		}
		fmt.Printf("operador %s: cert emitido (válido até %s)\nthumbprint: %s\narquivos em %s: %s, %s, %s\n",
			*id, cert.NotAfter.Format(time.DateOnly), thumb, *out, server.FileOperadorKey, server.FileOperadorCrt, server.FileOperadorCA)
		fmt.Printf("importar no navegador (.p12): openssl pkcs12 -export -inkey %s -in %s -certfile %s -out operador.p12\n",
			filepath.Join(*out, server.FileOperadorKey), filepath.Join(*out, server.FileOperadorCrt), filepath.Join(*out, server.FileOperadorCA))
		fmt.Println("ATENÇÃO: modo direto (SÓ LAB, não use em produção; prefira csr + assinar-csr) - a chave privada foi gerada aqui; entregue por canal seguro e apague as cópias.")
		return st.Audit("operador.cert.emitido", actor(), map[string]any{"operador": *id, "thumbprint": thumb})
	case "list":
		ops, err := st.Operators()
		if err != nil {
			return err
		}
		tw := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
		fmt.Fprintln(tw, "ID\tTÉCNICO\tNOME\tSTATUS\tTEM_CERT\tCREDENCIAIS\tTEM_SIGNING_PUB")
		for _, o := range ops {
			creds, err := st.Credentials(o.ID)
			if err != nil {
				return err
			}
			fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%t\t%d\t%t\n", o.ID, o.TechName, o.Nome, o.Status, o.CertThumbprint != "", len(creds), o.SigningPub != "")
		}
		return tw.Flush()
	case "activate":
		if *id == "" {
			return errors.New("informe --id")
		}
		if err := server.AtivarOperador(st, *id); err != nil {
			return err
		}
		fmt.Printf("operador %s: ativo\n", *id)
		return st.Audit("operador.ativado", actor(), map[string]any{"operador": *id})
	}
	return fmt.Errorf("subcomando desconhecido: %s", sub)
}
