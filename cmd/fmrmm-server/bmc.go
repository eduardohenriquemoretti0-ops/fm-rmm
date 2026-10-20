package main

import (
	"bufio"
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"strings"
	"time"

	"github.com/eduardohenriquemoretti0-ops/fm-rmm/internal/redfish"
)

const (
	envBMCUser = "FMRMM_BMC_USER"
	envBMCPass = "FMRMM_BMC_PASS"
)

// cmdBMC: controle de energia por BMC/Redfish para o admin (automação).
//
//	bmc status --host H [--porta 443] [--system-id ID] [--usuario U] [--insecure] [--dir D]
//	bmc power  --host H --acao On|ForceOff|GracefulShutdown|ForceRestart|GracefulRestart ...
//
// A senha do BMC NUNCA vem de flag (apareceria em `ps`/histórico): é lida de
// $FMRMM_BMC_PASS ou, com --senha-stdin, da entrada padrão. Nada é persistido.
// Com --dir, o resultado é auditado (host/ação/resultado, sem credencial).
func cmdBMC(args []string) error {
	return cmdBMCCom(args, os.Stdin, os.Stdout)
}

func cmdBMCCom(args []string, stdin io.Reader, out io.Writer) error {
	if len(args) == 0 || (args[0] != "power" && args[0] != "status") {
		return errors.New("uso: bmc status|power --host H [--acao A] [--senha-stdin] (senha: $" + envBMCPass + " ou stdin)")
	}
	sub := args[0]
	fs := flag.NewFlagSet("bmc "+sub, flag.ContinueOnError)
	host := fs.String("host", "", "IP/nome do BMC")
	porta := fs.Int("porta", 443, "porta HTTPS do BMC")
	sysID := fs.String("system-id", "", "id do sistema Redfish (vazio = descobre)")
	acao := fs.String("acao", "", "On|ForceOff|GracefulShutdown|ForceRestart|GracefulRestart (só em power)")
	usuario := fs.String("usuario", os.Getenv(envBMCUser), "usuário do BMC (ou $"+envBMCUser+")")
	senhaStdin := fs.Bool("senha-stdin", false, "ler a senha da entrada padrão em vez de $"+envBMCPass)
	insecure := fs.Bool("insecure", false, "NÃO validar o certificado TLS do BMC (self-signed); use só em rede confiável")
	dir := fs.String("dir", "", "diretório do servidor: se informado, audita a operação (sem credencial)")
	fs.SetOutput(os.Stderr)
	if err := fs.Parse(args[1:]); err != nil {
		return err
	}
	if *host == "" || *usuario == "" {
		return errors.New("--host e usuário do BMC (--usuario ou $" + envBMCUser + ") são obrigatórios")
	}
	var senha string
	if *senhaStdin {
		l, err := bufio.NewReader(stdin).ReadString('\n')
		if err != nil && !(errors.Is(err, io.EOF) && l != "") {
			return errors.New("não consegui ler a senha da entrada padrão")
		}
		senha = strings.TrimRight(l, "\r\n")
	} else {
		senha = os.Getenv(envBMCPass)
	}
	if senha == "" {
		return errors.New("senha do BMC ausente: defina $" + envBMCPass + " ou use --senha-stdin")
	}
	if sub == "power" {
		if _, err := redfish.ValidaAcao(*acao); err != nil {
			return err
		}
	}
	cli, err := redfish.Novo(redfish.Config{
		Host: *host, Porta: *porta, Usuario: *usuario, Senha: senha,
		Insecure: *insecure, Timeout: 20 * time.Second,
	})
	senha = ""
	if err != nil {
		return err
	}
	if *insecure {
		fmt.Fprintln(os.Stderr, "AVISO: "+redfish.AvisoInsecure)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	var erroBMC error
	id := *sysID
	if sub == "power" {
		id, erroBMC = cli.Reset(ctx, *sysID, *acao)
		if erroBMC == nil {
			fmt.Fprintf(out, "ok: %s enviado a %s (system %s)\n", *acao, *host, id)
		}
	} else {
		var e redfish.Estado
		e, erroBMC = cli.Status(ctx, *sysID)
		id = e.SystemID
		if erroBMC == nil {
			fmt.Fprintf(out, "system=%s power=%s health=%s modelo=%s\n", e.SystemID, e.PowerState, e.Health, e.Modelo)
		}
	}
	if *dir != "" {
		if st, err := openStore(*dir); err != nil {
			fmt.Fprintln(os.Stderr, "aviso: sem auditoria:", err)
		} else {
			resultado := "ok"
			if erroBMC != nil {
				resultado = erroBMC.Error()
			}
			_ = st.Audit("cli.bmc."+sub, actor(), map[string]any{
				"host": *host, "porta": *porta, "system_id": id, "acao": *acao,
				"resultado": resultado, "insecure": *insecure,
			})
			st.Close()
		}
	}
	return erroBMC
}
