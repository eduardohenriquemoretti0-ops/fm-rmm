package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"os"
	"time"

	"github.com/eduardohenriquemoretti0-ops/fm-rmm/internal/server"
)

// cmdCVE: `cve scan` consulta o OSV.dev e a NVD (rede de SAÍDA do servidor, read-only
// para as máquinas); `cve show` só lê o banco. Ver docs/cve-osv.md.
func cmdCVE(args []string) error {
	fs := flag.NewFlagSet("cve", flag.ExitOnError)
	dir := dirFlag(fs)
	agente := fs.String("agent", "", "id do agente, ou 'todos' (scan)")
	eco := fs.String("linux-ecosystem", os.Getenv("FMRMM_CVE_LINUX_ECOSYSTEM"), "FALLBACK de ecossistema OSV p/ agentes Linux que não reportam os-release ou com distro não mapeada (ex.: Debian:12); o normal é derivar do heartbeat")
	semNVD := fs.Bool("sem-nvd", false, "não consulta a NVD (só OSV); chave opcional em FMRMM_NVD_API_KEY")
	if len(args) == 0 {
		return errors.New("uso: cve --dir D scan|show --agent ID")
	}
	sub := args[0]
	fs.Parse(args[1:])
	if *agente == "" {
		return errors.New("--agent é obrigatório")
	}
	st, err := openStore(*dir)
	if err != nil {
		return err
	}
	defer st.Close()
	switch sub {
	case "scan":
		eng := &server.Engine{St: st, EcossistemaLinux: *eco}
		if !*semNVD {
			eng.CPE = server.NovaFonteNVD(st) // keyless funciona (mais lento); chave via FMRMM_NVD_API_KEY
		}
		ids := []string{*agente}
		if *agente == "todos" {
			ags, err := st.Agents("approved")
			if err != nil {
				return err
			}
			ids = nil
			for _, a := range ags {
				ids = append(ids, a.ID)
			}
		}
		for _, id := range ids {
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
			r, err := eng.Scan(ctx, id)
			cancel()
			if errors.Is(err, server.ErrSemInventario) {
				fmt.Printf("%s: sem inventário `software` (rode: jobs new --action software)\n", id)
				continue
			}
			if err != nil {
				return fmt.Errorf("%s: %w", id, err)
			}
			_ = st.Audit("cve.scan", actor(), map[string]any{"agente": id, "achados": len(r.Achados), "erro": r.Resumo.Erro})
			fmt.Printf("%s: itens=%d avaliados=%d nao_avaliados=%d vulnerabilidades=%d", id, r.Resumo.ItensTotal, r.Resumo.Avaliados, r.Resumo.NaoAvaliados, len(r.Achados))
			if r.Resumo.Erro != "" {
				fmt.Printf(" AVISO=%q (achados anteriores mantidos)", r.Resumo.Erro)
			}
			fmt.Println()
		}
		return nil
	case "show":
		r, err := st.ResumoVulns(*agente)
		if err != nil {
			return err
		}
		b, _ := json.MarshalIndent(r, "", "  ")
		fmt.Println(string(b))
		return nil
	}
	return fmt.Errorf("subcomando desconhecido: %s", sub)
}
