package server

import (
	"crypto/ed25519"
	"database/sql"
	"errors"
	"fmt"
	"time"

	"github.com/eduardohenriquemoretti0-ops/fm-rmm/internal/sign"
)

// Biblioteca de scripts assinada no servidor. Mesma regra do catálogo de
// software: a chave RAIZ nunca está aqui; a biblioteca é montada e assinada
// OFFLINE; o servidor confere, ARMAZENA (CLI do admin, sem rota HTTP) e SERVE
// no check-in. Versão publicada só cresce.

const bibliotecaScriptsSchema = `
CREATE TABLE IF NOT EXISTS biblioteca_scripts (
  id INTEGER PRIMARY KEY CHECK (id = 1),
  versao INTEGER NOT NULL, raw BLOB NOT NULL, sig BLOB NOT NULL, publicada_em INTEGER NOT NULL
);
`

func (s *Store) initBibliotecaScripts() error {
	_, err := s.db.Exec(bibliotecaScriptsSchema)
	return err
}

func (s *Store) bibliotecaScriptsAtual() (versao int, raw, sig []byte, err error) {
	err = s.db.QueryRow(`SELECT versao, raw, sig FROM biblioteca_scripts WHERE id = 1`).Scan(&versao, &raw, &sig)
	if errors.Is(err, sql.ErrNoRows) {
		return 0, nil, nil, nil
	}
	return versao, raw, sig, err
}

// BibliotecaScriptsAtual devolve versão, bytes e assinatura publicados (CLI/console).
func (s *Store) BibliotecaScriptsAtual() (int, []byte, []byte, error) {
	return s.bibliotecaScriptsAtual()
}

// ConstruirBibliotecaScripts monta e assina a biblioteca OFFLINE. Versão =
// versaoAtual+1. sha256 vazio é preenchido com o hash do corpo; informado,
// precisa conferir. O resultado passa pela mesma verificação do agente.
func ConstruirBibliotecaScripts(raiz ed25519.PrivateKey, versaoAtual int, scripts []sign.ScriptEntry, emitida time.Time) (raw, sig []byte, versao int, err error) {
	if len(raiz) != ed25519.PrivateKeySize {
		return nil, nil, 0, errors.New("chave raiz inválida")
	}
	if versaoAtual < 0 {
		return nil, nil, 0, fmt.Errorf("versão atual inválida: %d", versaoAtual)
	}
	preenchidos := make([]sign.ScriptEntry, len(scripts))
	copy(preenchidos, scripts)
	for i := range preenchidos {
		if preenchidos[i].SHA256 == "" {
			preenchidos[i].SHA256 = sign.HashCorpoScript(preenchidos[i].Corpo)
		}
	}
	versao = versaoAtual + 1
	raw, sig, err = sign.SignScriptLibrary(raiz, sign.ScriptLibrary{Version: versao, IssuedAt: emitida, Scripts: preenchidos})
	if err != nil {
		return nil, nil, 0, err
	}
	if _, err := sign.ParseScriptLibrary(raiz.Public().(ed25519.PublicKey), raw, sig); err != nil {
		return nil, nil, 0, fmt.Errorf("biblioteca gerada não passa na verificação do agente: %w", err)
	}
	return raw, sig, versao, nil
}

// PublicarBibliotecaScripts guarda uma biblioteca já assinada pela raiz. Recusa
// assinatura que não confere, forma não canônica e versão não maior que a publicada.
func PublicarBibliotecaScripts(st *Store, raiz ed25519.PublicKey, raw, sig []byte, actor string) (int, error) {
	l, err := sign.ParseScriptLibrary(raiz, raw, sig)
	if err != nil {
		return 0, err
	}
	tx, err := st.db.Begin()
	if err != nil {
		return 0, err
	}
	defer tx.Rollback()
	var atual int
	err = tx.QueryRow(`SELECT versao FROM biblioteca_scripts WHERE id = 1`).Scan(&atual)
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		return 0, err
	}
	if l.Version <= atual {
		return 0, fmt.Errorf("%w: publicar v%d, já publicada v%d", sign.ErrBibliotecaVersao, l.Version, atual)
	}
	if _, err := tx.Exec(`INSERT OR REPLACE INTO biblioteca_scripts(id, versao, raw, sig, publicada_em) VALUES (1,?,?,?,?)`,
		l.Version, raw, sig, time.Now().Unix()); err != nil {
		return 0, err
	}
	if err := tx.Commit(); err != nil {
		return 0, err
	}
	return l.Version, st.Audit("biblioteca_scripts.publicada", actor, map[string]any{"versao": l.Version, "scripts": len(l.Scripts)})
}
