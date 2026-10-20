package main

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/eduardohenriquemoretti0-ops/fm-rmm/internal/server"
	"github.com/eduardohenriquemoretti0-ops/fm-rmm/internal/sign"
)

// cmdSoftware: catálogo de software assinado. build é OFFLINE (nunca abre o
// banco); publish e show falam com o banco, no host do servidor.
func cmdSoftware(args []string) error {
	if len(args) > 0 && args[0] == "build" {
		return cmdSoftwareBuild(args[1:])
	}
	fs := flag.NewFlagSet("software", flag.ExitOnError)
	dir := dirFlag(fs)
	fs.Parse(args)
	rest := fs.Args()
	if len(rest) == 0 {
		return errors.New("uso: software build|publish|show")
	}
	switch rest[0] {
	case "show":
		st, err := openStore(*dir)
		if err != nil {
			return err
		}
		defer st.Close()
		versao, raw, _, err := st.CatalogoSoftwareAtual()
		if err != nil {
			return err
		}
		if versao == 0 {
			fmt.Println("nenhum catálogo de software publicado")
			return nil
		}
		var c sign.SoftwareCatalog
		if err := json.Unmarshal(raw, &c); err != nil {
			return err
		}
		b, _ := json.MarshalIndent(c, "", "  ")
		fmt.Println(string(b))
		return nil
	case "publish":
		pf := flag.NewFlagSet("software publish", flag.ExitOnError)
		raizID := pf.String("raiz", "", "key_id da chave RAIZ (o SignerID do bundle)")
		cat := pf.String("catalogo", "", "arquivo software-catalog.json")
		sigArq := pf.String("sig", "", "arquivo software-catalog.sig (base64)")
		pf.Parse(rest[1:])
		if *raizID == "" || *cat == "" || *sigArq == "" {
			return errors.New("informe --raiz, --catalogo e --sig")
		}
		raw, err := os.ReadFile(*cat)
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
		versao, err := server.PublicarCatalogoSoftware(st, raiz, bytes.TrimRight(raw, "\n"), sig, actor())
		if err != nil {
			return err
		}
		fmt.Printf("catálogo de software v%d publicado; os agentes recebem no próximo check-in\n", versao)
		return nil
	}
	return fmt.Errorf("subcomando desconhecido: %s", rest[0])
}

// cmdSoftwareBuild roda OFFLINE, na máquina do admin que guarda a chave raiz.
// itens.json é um array de {id, nome, gerenciador, pkg_id, versao?, publisher?, sha256?}.
func cmdSoftwareBuild(args []string) error {
	fs := flag.NewFlagSet("software build", flag.ExitOnError)
	key := fs.String("key", "", "chave privada RAIZ (offline)")
	itens := fs.String("items", "", "JSON com os itens (array)")
	versaoAtual := fs.Int("versao-atual", 0, "versão do catálogo em vigor (a nova será +1; veja `software show`)")
	outDir := fs.String("out", ".", "pasta de saída de software-catalog.json e software-catalog.sig")
	fs.Parse(args)
	if *key == "" || *itens == "" {
		return errors.New("informe --key (chave raiz) e --items")
	}
	priv, err := sign.LoadPrivate(*key)
	if err != nil {
		return fmt.Errorf("chave raiz: %w", err)
	}
	var its []sign.SoftwareItem
	if err := lerJSONEstrito(*itens, &its); err != nil {
		return fmt.Errorf("itens: %w", err)
	}
	raw, sig, versao, err := server.ConstruirCatalogoSoftware(priv, *versaoAtual, its, time.Now().UTC())
	if err != nil {
		return err
	}
	if err := os.MkdirAll(*outDir, 0o755); err != nil {
		return err
	}
	jsonP, sigP := filepath.Join(*outDir, "software-catalog.json"), filepath.Join(*outDir, "software-catalog.sig")
	if err := escreveNovo(jsonP, append(raw, '\n')); err != nil {
		return err
	}
	if err := escreveNovo(sigP, []byte(base64.StdEncoding.EncodeToString(sig)+"\n")); err != nil {
		return err
	}
	fmt.Printf("catálogo v%d assinado pela raiz (offline): %s e %s\n", versao, jsonP, sigP)
	fmt.Printf("%d item(ns). Leve os dois arquivos ao servidor e rode: software publish\n", len(its))
	return nil
}
