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

// cmdScripts: biblioteca de scripts assinada (NÃO é terminal remoto: o
// operador só escolhe id+versão de uma lista revisada). build é OFFLINE (nunca
// abre o banco); publish e show falam com o banco, no host do servidor.
func cmdScripts(args []string) error {
	if len(args) > 0 && args[0] == "build" {
		return cmdScriptsBuild(args[1:])
	}
	fs := flag.NewFlagSet("scripts", flag.ExitOnError)
	dir := dirFlag(fs)
	fs.Parse(args)
	rest := fs.Args()
	if len(rest) == 0 {
		return errors.New("uso: scripts build|publish|show")
	}
	switch rest[0] {
	case "show":
		st, err := openStore(*dir)
		if err != nil {
			return err
		}
		defer st.Close()
		versao, raw, _, err := st.BibliotecaScriptsAtual()
		if err != nil {
			return err
		}
		if versao == 0 {
			fmt.Println("nenhuma biblioteca de scripts publicada")
			return nil
		}
		var l sign.ScriptLibrary
		if err := json.Unmarshal(raw, &l); err != nil {
			return err
		}
		fmt.Printf("biblioteca de scripts v%d (emitida %s), %d script(s)\n", l.Version, l.IssuedAt.Format(time.RFC3339), len(l.Scripts))
		for _, e := range l.Scripts {
			fmt.Printf("  %s v%s [%s] sha256=%s  %s\n", e.ID, e.Versao, e.Interprete, e.SHA256[:12], e.Nome)
		}
		return nil
	case "publish":
		pf := flag.NewFlagSet("scripts publish", flag.ExitOnError)
		raizID := pf.String("raiz", "", "key_id da chave RAIZ (o SignerID do bundle)")
		arq := pf.String("biblioteca", "", "arquivo script-library.json")
		sigArq := pf.String("sig", "", "arquivo script-library.sig (base64)")
		pf.Parse(rest[1:])
		if *raizID == "" || *arq == "" || *sigArq == "" {
			return errors.New("informe --raiz, --biblioteca e --sig")
		}
		raw, err := os.ReadFile(*arq)
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
		versao, err := server.PublicarBibliotecaScripts(st, raiz, bytes.TrimRight(raw, "\n"), sig, actor())
		if err != nil {
			return err
		}
		fmt.Printf("biblioteca de scripts v%d publicada; os agentes recebem no próximo check-in\n", versao)
		return nil
	}
	return fmt.Errorf("subcomando desconhecido: %s", rest[0])
}

// scriptEntrada é a forma aceita no arquivo do admin: o corpo vem inline
// ("corpo") OU de um arquivo ao lado ("corpo_arquivo"); sha256 é opcional
// (preenchido; se informado, tem de conferir).
type scriptEntrada struct {
	ID           string `json:"id"`
	Nome         string `json:"nome"`
	Versao       string `json:"versao"`
	Interprete   string `json:"interprete"`
	Corpo        string `json:"corpo,omitempty"`
	CorpoArquivo string `json:"corpo_arquivo,omitempty"`
	SHA256       string `json:"sha256,omitempty"`
}

// cmdScriptsBuild roda OFFLINE, na máquina do admin que guarda a chave raiz.
func cmdScriptsBuild(args []string) error {
	fs := flag.NewFlagSet("scripts build", flag.ExitOnError)
	key := fs.String("key", "", "chave privada RAIZ (offline)")
	arq := fs.String("scripts", "", "JSON com os scripts revisados (array)")
	versaoAtual := fs.Int("versao-atual", 0, "versão da biblioteca em vigor (a nova será +1; veja `scripts show`)")
	outDir := fs.String("out", ".", "pasta de saída de script-library.json e script-library.sig")
	fs.Parse(args)
	if *key == "" || *arq == "" {
		return errors.New("informe --key (chave raiz) e --scripts")
	}
	priv, err := sign.LoadPrivate(*key)
	if err != nil {
		return fmt.Errorf("chave raiz: %w", err)
	}
	var ents []scriptEntrada
	if err := lerJSONEstrito(*arq, &ents); err != nil {
		return fmt.Errorf("scripts: %w", err)
	}
	base := filepath.Dir(*arq)
	scripts := make([]sign.ScriptEntry, 0, len(ents))
	for _, e := range ents {
		corpo := e.Corpo
		switch {
		case e.CorpoArquivo != "" && corpo != "":
			return fmt.Errorf("script %q: use corpo OU corpo_arquivo, não os dois", e.ID)
		case e.CorpoArquivo != "":
			b, err := os.ReadFile(filepath.Join(base, filepath.Base(e.CorpoArquivo)))
			if err != nil {
				return fmt.Errorf("script %q: %w", e.ID, err)
			}
			corpo = string(b)
		}
		scripts = append(scripts, sign.ScriptEntry{ID: e.ID, Nome: e.Nome, Versao: e.Versao,
			Interprete: e.Interprete, Corpo: corpo, SHA256: e.SHA256})
	}
	raw, sig, versao, err := server.ConstruirBibliotecaScripts(priv, *versaoAtual, scripts, time.Now().UTC())
	if err != nil {
		return err
	}
	if err := os.MkdirAll(*outDir, 0o755); err != nil {
		return err
	}
	jsonP, sigP := filepath.Join(*outDir, "script-library.json"), filepath.Join(*outDir, "script-library.sig")
	if err := escreveNovo(jsonP, append(raw, '\n')); err != nil {
		return err
	}
	if err := escreveNovo(sigP, []byte(base64.StdEncoding.EncodeToString(sig)+"\n")); err != nil {
		return err
	}
	fmt.Printf("biblioteca v%d assinada pela raiz (offline): %s e %s\n", versao, jsonP, sigP)
	fmt.Printf("%d script(s). Leve os dois arquivos ao servidor e rode: scripts publish\n", len(scripts))
	return nil
}
