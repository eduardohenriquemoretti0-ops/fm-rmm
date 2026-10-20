package main

import (
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"text/tabwriter"
	"time"

	"github.com/eduardohenriquemoretti0-ops/fm-rmm/internal/escrow"
	"github.com/eduardohenriquemoretti0-ops/fm-rmm/internal/server"
)

// gerarEscrow cria escrow.key (0600) + escrow.pub no diretório. Recusa sobrescrever.
func gerarEscrow(dir string) (string, error) {
	pub, err := escrow.GenerateKey(filepath.Join(dir, server.FileEscrowKey))
	if err != nil {
		return "", fmt.Errorf("escrow.key: %w", err)
	}
	if err := os.WriteFile(filepath.Join(dir, server.FileEscrowPub), []byte(pub+"\n"), 0o644); err != nil {
		return "", err
	}
	return pub, nil
}

// resolverEscrowPub escolhe a pública de escrow: flag, escrow.key ou escrow.pub do dir.
// Vazio (sem erro) = não configurada.
func resolverEscrowPub(dir, pubFlag, keyFlag string) (string, error) {
	switch {
	case pubFlag != "":
		if _, err := escrow.DecodePub(pubFlag); err != nil {
			return "", err
		}
		return pubFlag, nil
	case keyFlag != "":
		return escrow.PublicFromPrivate(keyFlag)
	}
	b, err := os.ReadFile(filepath.Join(dir, server.FileEscrowPub))
	if errors.Is(err, os.ErrNotExist) {
		return "", nil
	}
	if err != nil {
		return "", err
	}
	pub := strings.TrimSpace(string(b))
	if _, err := escrow.DecodePub(pub); err != nil {
		return "", err
	}
	return pub, nil
}

func cmdEscrow(args []string) error {
	if len(args) == 0 {
		return errors.New("uso: escrow gerar|listar|exportar|abrir")
	}
	sub, rest := args[0], args[1:]
	switch sub {
	case "abrir":
		return cmdEscrowAbrir(rest, os.Stdin, os.Stdout, os.Stderr)
	case "gerar":
		fs := flag.NewFlagSet("escrow gerar", flag.ExitOnError)
		dir := dirFlag(fs)
		fs.Parse(rest)
		pub, err := gerarEscrow(*dir)
		if err != nil {
			return err
		}
		fmt.Printf("escrow.key criada em %s (0600). MOVA para fora do servidor.\nEscrowPub: %s\nRefaça o bundle para os agentes receberem a EscrowPub.\n", *dir, pub)
		return nil
	case "listar", "exportar":
		fs := flag.NewFlagSet("escrow "+sub, flag.ExitOnError)
		dir := dirFlag(fs)
		agent := fs.String("agent", "", "filtra por agente")
		id := fs.Int64("id", 0, "id do registro (exportar)")
		fs.Parse(rest)
		st, err := openStore(*dir)
		if err != nil {
			return err
		}
		defer st.Close()
		if sub == "exportar" {
			e, err := st.EscrowByID(*id)
			if err != nil {
				return fmt.Errorf("registro %d: %w", *id, err)
			}
			fmt.Println(e.Blob) // só ciphertext
			return nil
		}
		rows, err := st.Escrows(*agent)
		if err != nil {
			return err
		}
		tw := tabwriter.NewWriter(os.Stdout, 0, 4, 2, ' ', 0)
		fmt.Fprintln(tw, "ID\tAGENTE\tVOLUME\tMETODO\tCRIADO\tJOB")
		for _, e := range rows {
			fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%s\t%s\n", strconv.FormatInt(e.ID, 10), e.AgentID, e.Volume, e.Metodo,
				time.Unix(e.CriadoEm, 0).Format("2006-01-02 15:04"), e.JobID)
		}
		return tw.Flush()
	}
	return errors.New("subcomando de escrow desconhecido: " + sub)
}

// cmdEscrowAbrir é OFFLINE: não abre o banco nem precisa do servidor. A chave
// de recuperação vai para stdout; o contexto (agente/volume) vai para stderr.
func cmdEscrowAbrir(args []string, stdin io.Reader, stdout, stderr io.Writer) error {
	fs := flag.NewFlagSet("escrow abrir", flag.ContinueOnError)
	fs.SetOutput(stderr)
	key := fs.String("escrow-key", "escrow.key", "chave privada de escrow do admin")
	blobArg := fs.String("blob", "-", "arquivo com o blob selado (base64) ou - para stdin")
	if err := fs.Parse(args); err != nil {
		return err
	}
	var raw []byte
	var err error
	if *blobArg == "-" {
		raw, err = io.ReadAll(io.LimitReader(stdin, escrow.MaxBlob+16))
	} else {
		raw, err = os.ReadFile(*blobArg)
	}
	if err != nil {
		return err
	}
	s, err := escrow.Open(*key, strings.TrimSpace(string(raw)))
	if err != nil {
		return err
	}
	fmt.Fprintf(stderr, "agente=%s volume=%s metodo=%s\n", s.AgentID, s.Volume, s.Metodo)
	fmt.Fprintln(stdout, s.Chave)
	return nil
}
