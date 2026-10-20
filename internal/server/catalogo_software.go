package server

import (
	"crypto/ed25519"
	"database/sql"
	"errors"
	"fmt"
	"time"

	"github.com/eduardohenriquemoretti0-ops/fm-rmm/internal/sign"
)

// Catálogo de software (allow-list) no servidor. Mesma regra da lista de
// signers: a chave RAIZ nunca está aqui. O catálogo é montado e assinado
// OFFLINE (ConstruirCatalogoSoftware); o servidor só confere a assinatura,
// ARMAZENA (PublicarCatalogoSoftware, CLI do admin) e SERVE no check-in. Não há
// rota HTTP de publicação. Versão publicada só cresce.

const catalogoSoftwareSchema = `
CREATE TABLE IF NOT EXISTS catalogo_software (
  id INTEGER PRIMARY KEY CHECK (id = 1),
  versao INTEGER NOT NULL, raw BLOB NOT NULL, sig BLOB NOT NULL, publicada_em INTEGER NOT NULL
);
`

func (s *Store) initCatalogoSoftware() error {
	_, err := s.db.Exec(catalogoSoftwareSchema)
	return err
}

// catalogoSoftwareAtual devolve o catálogo publicado (versão 0 se não há).
func (s *Store) catalogoSoftwareAtual() (versao int, raw, sig []byte, err error) {
	err = s.db.QueryRow(`SELECT versao, raw, sig FROM catalogo_software WHERE id = 1`).Scan(&versao, &raw, &sig)
	if errors.Is(err, sql.ErrNoRows) {
		return 0, nil, nil, nil
	}
	return versao, raw, sig, err
}

// CatalogoSoftwareAtual devolve versão, bytes e assinatura publicados (CLI/console).
func (s *Store) CatalogoSoftwareAtual() (int, []byte, []byte, error) {
	return s.catalogoSoftwareAtual()
}

// ConstruirCatalogoSoftware monta e assina o catálogo OFFLINE com a chave raiz.
// Versão = versaoAtual+1. Confere o resultado com a mesma verificação do agente.
func ConstruirCatalogoSoftware(raiz ed25519.PrivateKey, versaoAtual int, itens []sign.SoftwareItem, emitida time.Time) (raw, sig []byte, versao int, err error) {
	if len(raiz) != ed25519.PrivateKeySize {
		return nil, nil, 0, errors.New("chave raiz inválida")
	}
	if versaoAtual < 0 {
		return nil, nil, 0, fmt.Errorf("versão atual inválida: %d", versaoAtual)
	}
	versao = versaoAtual + 1
	raw, sig, err = sign.SignSoftwareCatalog(raiz, sign.SoftwareCatalog{Version: versao, IssuedAt: emitida, Items: itens})
	if err != nil {
		return nil, nil, 0, err
	}
	if _, err := sign.ParseSoftwareCatalog(raiz.Public().(ed25519.PublicKey), raw, sig); err != nil {
		return nil, nil, 0, fmt.Errorf("catálogo gerado não passa na verificação do agente: %w", err)
	}
	return raw, sig, versao, nil
}

// PublicarCatalogoSoftware guarda um catálogo já assinado pela raiz. Recusa
// assinatura que não confere, forma não canônica e versão não maior que a publicada.
func PublicarCatalogoSoftware(st *Store, raiz ed25519.PublicKey, raw, sig []byte, actor string) (int, error) {
	c, err := sign.ParseSoftwareCatalog(raiz, raw, sig)
	if err != nil {
		return 0, err
	}
	tx, err := st.db.Begin()
	if err != nil {
		return 0, err
	}
	defer tx.Rollback()
	var atual int
	err = tx.QueryRow(`SELECT versao FROM catalogo_software WHERE id = 1`).Scan(&atual)
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		return 0, err
	}
	if c.Version <= atual {
		return 0, fmt.Errorf("%w: publicar v%d, já publicada v%d", sign.ErrCatalogoVersao, c.Version, atual)
	}
	if _, err := tx.Exec(`INSERT OR REPLACE INTO catalogo_software(id, versao, raw, sig, publicada_em) VALUES (1,?,?,?,?)`,
		c.Version, raw, sig, time.Now().Unix()); err != nil {
		return 0, err
	}
	if err := tx.Commit(); err != nil {
		return 0, err
	}
	return c.Version, st.Audit("catalogo_software.publicado", actor, map[string]any{"versao": c.Version, "itens": len(c.Items)})
}
