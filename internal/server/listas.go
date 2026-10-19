package server

import (
	"crypto/ed25519"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/eduardohenriquemoretti0-ops/fm-rmm/internal/sign"
)

// Lista de signers (trust-set do agente) no servidor.
//
// REGRA: a chave RAIZ nunca está no servidor. A lista é montada e assinada
// OFFLINE (ConstruirLista, na ferramenta de admin). O servidor só ARMAZENA a
// lista já assinada (PublicarLista, no CLI do admin, no próprio host) e a
// SERVE aos agentes no check-in. Não há rota HTTP de publicação: a superfície
// de ataque não cresce.
//
// O servidor também confere a assinatura contra a raiz antes de guardar e
// recusa versão que não seja maior que a publicada: uma lista ruim nunca chega
// aos agentes por engano.

const listasSchema = `
CREATE TABLE IF NOT EXISTS lista_signers (
  id INTEGER PRIMARY KEY CHECK (id = 1),
  versao INTEGER NOT NULL, raw BLOB NOT NULL, sig BLOB NOT NULL, publicada_em INTEGER NOT NULL
);
`

// initListas cria a tabela da lista e a coluna signing_pub dos operadores
// (idempotente: bancos antigos ganham a coluna sem perder dados).
func (s *Store) initListas() error {
	if _, err := s.db.Exec(listasSchema); err != nil {
		return err
	}
	_, err := s.db.Exec(`ALTER TABLE operators ADD COLUMN signing_pub TEXT NOT NULL DEFAULT ''`)
	if err != nil && !isDupColumn(err) {
		return err
	}
	// a mesma pública não pode servir a dois operadores (a lista a recusaria)
	_, err = s.db.Exec(`CREATE UNIQUE INDEX IF NOT EXISTS operators_signing_pub ON operators(signing_pub) WHERE signing_pub <> ''`)
	return err
}

// OperadoresParaLista devolve as entradas de operador aptas a entrar na lista:
// operador ativo, com chave de assinatura, de técnico NÃO desabilitado (quem
// não tem acesso não assina). Papel sempre operator; a raiz nunca vem daqui.
func (s *Store) OperadoresParaLista() ([]sign.SignerEntry, error) {
	rows, err := s.db.Query(`SELECT o.signing_pub FROM operators o
		JOIN techs t ON t.name = o.tech_name
		WHERE o.status = 'ativo' AND o.signing_pub <> '' AND t.disabled = 0
		ORDER BY o.id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []sign.SignerEntry
	for rows.Next() {
		var pubB64 string
		if err := rows.Scan(&pubB64); err != nil {
			return nil, err
		}
		pub, err := sign.DecodePub(pubB64)
		if err != nil {
			return nil, fmt.Errorf("operador com chave inválida no banco: %w", err)
		}
		out = append(out, sign.SignerEntry{KeyID: sign.KeyID(pub), Pub: sign.EncodePub(pub), Role: sign.RoleOperator})
	}
	return out, rows.Err()
}

// ExportLista é o que o admin leva para a ferramenta OFFLINE: a versão em vigor
// no servidor e os operadores aptos. Não contém nenhum segredo.
type ExportLista struct {
	VersaoAtual int                `json:"versao_atual"`
	Operadores  []sign.SignerEntry `json:"operadores"`
}

// ExportarLista monta o export para a ferramenta offline.
func (s *Store) ExportarLista() (ExportLista, error) {
	versao, _, _, err := s.listaAtual()
	if err != nil {
		return ExportLista{}, err
	}
	ops, err := s.OperadoresParaLista()
	if err != nil {
		return ExportLista{}, err
	}
	if ops == nil {
		ops = []sign.SignerEntry{}
	}
	return ExportLista{VersaoAtual: versao, Operadores: ops}, nil
}

// listaAtual devolve a lista publicada (versão 0 e nil se ainda não há).
func (s *Store) listaAtual() (versao int, raw, sig []byte, err error) {
	err = s.db.QueryRow(`SELECT versao, raw, sig FROM lista_signers WHERE id = 1`).Scan(&versao, &raw, &sig)
	if errors.Is(err, sql.ErrNoRows) {
		return 0, nil, nil, nil
	}
	return versao, raw, sig, err
}

// ConstruirLista monta e assina a lista de signers: a raiz (role admin) mais
// os operadores. Roda OFFLINE, com a chave raiz. A versão é versaoAtual+1
// (anti-downgrade). Antes de devolver, confere o resultado com a mesma
// verificação que o agente faz: o que sai daqui é aceito lá.
func ConstruirLista(raiz ed25519.PrivateKey, versaoAtual int, operadores []sign.SignerEntry, emitida time.Time) (raw, sig []byte, versao int, err error) {
	if len(raiz) != ed25519.PrivateKeySize {
		return nil, nil, 0, errors.New("chave raiz inválida")
	}
	if versaoAtual < 0 {
		return nil, nil, 0, fmt.Errorf("versão atual inválida: %d", versaoAtual)
	}
	raizPub := raiz.Public().(ed25519.PublicKey)
	entradas := []sign.SignerEntry{{KeyID: sign.KeyID(raizPub), Pub: sign.EncodePub(raizPub), Role: sign.RoleAdmin}}
	for _, o := range operadores {
		if o.Role != sign.RoleOperator {
			return nil, nil, 0, fmt.Errorf("signer %q: só operadores entram pela ferramenta (papel %q recusado)", o.KeyID, o.Role)
		}
		entradas = append(entradas, o)
	}
	versao = versaoAtual + 1
	raw, sig, err = sign.SignSignerList(raiz, sign.SignerList{Version: versao, IssuedAt: emitida, Signers: entradas})
	if err != nil {
		return nil, nil, 0, err
	}
	if _, err := sign.ParseSignerList(raizPub, raw, sig); err != nil {
		return nil, nil, 0, fmt.Errorf("lista gerada não passa na verificação do agente: %w", err)
	}
	return raw, sig, versao, nil
}

// PublicarLista guarda uma lista já assinada pela raiz. Recusa assinatura que
// não confere com a raiz, forma não canônica e versão que não seja maior que a
// publicada. Gravação e checagem de versão ficam numa só transação (IMMEDIATE).
func PublicarLista(st *Store, raiz ed25519.PublicKey, raw, sig []byte, actor string) (int, error) {
	l, err := sign.ParseSignerList(raiz, raw, sig)
	if err != nil {
		return 0, err
	}
	tx, err := st.db.Begin()
	if err != nil {
		return 0, err
	}
	defer tx.Rollback()
	var atual int
	err = tx.QueryRow(`SELECT versao FROM lista_signers WHERE id = 1`).Scan(&atual)
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		return 0, err
	}
	if l.Version <= atual {
		return 0, fmt.Errorf("%w: publicar v%d, já publicada v%d", sign.ErrListaVersao, l.Version, atual)
	}
	if _, err := tx.Exec(`INSERT OR REPLACE INTO lista_signers(id, versao, raw, sig, publicada_em) VALUES (1,?,?,?,?)`,
		l.Version, raw, sig, time.Now().Unix()); err != nil {
		return 0, err
	}
	if err := tx.Commit(); err != nil {
		return 0, err
	}
	// auditoria depois do commit: Audit abre a própria transação
	return l.Version, st.Audit("lista.publicada", actor, map[string]any{"versao": l.Version, "signers": len(l.Signers)})
}

// OperadorNaListaPublicada diz se keyID consta como signer de papel operator,
// ainda dentro da validade (not_after), na lista PUBLICADA em vigor. É o que o
// agente realmente confia: o status "ativo" no banco não basta. Sem lista
// publicada, ou com lista ilegível, devolve false (fail-closed). A assinatura da
// raiz já foi conferida em PublicarLista, antes de gravar.
func (s *Store) OperadorNaListaPublicada(keyID string, agora time.Time) (bool, error) {
	versao, raw, _, err := s.listaAtual()
	if err != nil {
		return false, err
	}
	if versao == 0 || len(raw) == 0 {
		return false, nil
	}
	var l sign.SignerList
	if err := json.Unmarshal(raw, &l); err != nil {
		return false, fmt.Errorf("lista publicada ilegível: %w", err)
	}
	for _, e := range l.Signers {
		if e.KeyID != keyID || e.Role != sign.RoleOperator {
			continue
		}
		if e.NotAfter != nil && !agora.Before(*e.NotAfter) {
			return false, nil
		}
		return true, nil
	}
	return false, nil
}
