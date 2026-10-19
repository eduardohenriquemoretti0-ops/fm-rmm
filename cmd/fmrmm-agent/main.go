// fmrmm-agent: agente do FM-RMM.
//
//	fmrmm-agent install --bundle bundle.json --token fmr_...   instala/atualiza o serviço
//	fmrmm-agent uninstall [--purge]                            remove (purge apaga a identidade)
//	fmrmm-agent status                                         estado local
//	fmrmm-agent run [--dir D]                                  loop em primeiro plano (diagnóstico)
//	fmrmm-agent version
package main

import (
	"context"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"os"
	"os/signal"
	"path/filepath"
	"time"

	"github.com/eduardohenriquemoretti0-ops/fm-rmm/internal/agent"
)

func main() {
	if agent.IsService() {
		os.Exit(serve(agent.DataDir(), false))
	}
	if len(os.Args) < 2 {
		usage()
		os.Exit(2)
	}
	cmd, args := os.Args[1], os.Args[2:]
	switch cmd {
	case "install":
		fs := flag.NewFlagSet("install", flag.ExitOnError)
		bundle := fs.String("bundle", "bundle.json", "bundle.json gerado pelo servidor")
		token := fs.String("token", "", "token de inscrição (1ª instalação)")
		fs.Parse(args)
		if err := agent.Install(agent.InstallOptions{BundlePath: *bundle, Token: *token}); err != nil {
			fatal(err)
		}
		fmt.Println("agente instalado e iniciado; serviço:", agent.ServiceName)
	case "uninstall":
		fs := flag.NewFlagSet("uninstall", flag.ExitOnError)
		purge := fs.Bool("purge", false, "apaga também chave, certificado e estado")
		fs.Parse(args)
		if err := agent.Uninstall(*purge); err != nil {
			fatal(err)
		}
		fmt.Println("agente removido")
	case "status":
		ag, err := agent.New(agent.DataDir(), slog.New(slog.NewTextHandler(io.Discard, nil)))
		if err != nil {
			fatal(err)
		}
		fmt.Print(ag.Status())
	case "service":
		// chamado pelo systemd/launchd (no Windows, IsService já desviou acima)
		os.Exit(serve(agent.DataDir(), false))
	case "run":
		fs := flag.NewFlagSet("run", flag.ExitOnError)
		dir := fs.String("dir", agent.DataDir(), "diretório de dados")
		fs.Parse(args)
		os.Exit(serve(*dir, true))
	case "version":
		fmt.Println(agent.Version)
	default:
		usage()
		os.Exit(2)
	}
}

func serve(dir string, foreground bool) int {
	var out io.Writer = os.Stderr
	if lf, err := agent.OpenRotating(filepath.Join(dir, "agent.log"), 5<<20); err == nil {
		if foreground {
			out = io.MultiWriter(os.Stderr, lf)
		} else {
			out = lf
		}
	}
	log := slog.New(slog.NewTextHandler(out, &slog.HandlerOptions{Level: slog.LevelInfo}))
	ag, err := agent.New(dir, log)
	if err != nil {
		log.Error("não foi possível iniciar", "erro", err)
		return 1
	}
	// acesso remoto autorizado: indicador de sessão sempre visível + plano de
	// mídia de visualização (captura de tela em quadros; 1 quadro/s)
	ag.EnableRemote(agent.NewOSIndicator(log), agent.NewScreenMedia(log, time.Second))
	if foreground {
		ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
		defer stop()
		ag.Run(ctx)
		return 0
	}
	if err := agent.RunService(ag.Run, log); err != nil {
		log.Error("serviço", "erro", err)
		return 1
	}
	return 0
}

func usage() {
	fmt.Fprintln(os.Stderr, `uso: fmrmm-agent install --bundle bundle.json --token TOKEN
       fmrmm-agent uninstall [--purge]
       fmrmm-agent status | run [--dir D] | version`)
}

func fatal(err error) {
	fmt.Fprintln(os.Stderr, "erro:", err)
	os.Exit(1)
}
