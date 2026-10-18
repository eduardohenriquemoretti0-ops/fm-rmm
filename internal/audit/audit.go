// Package audit define a cadeia de hash do log de auditoria.
//
// Cada entrada leva o hash da anterior. Alterar, apagar ou reordenar qualquer
// entrada quebra a cadeia, e Verify aponta a primeira entrada inválida.
// O armazenamento (append-only, com gatilhos que bloqueiam UPDATE/DELETE)
// fica no store do servidor.
package audit

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"time"
)

// Genesis é o "hash anterior" da primeira entrada.
const Genesis = "0000000000000000000000000000000000000000000000000000000000000000"

type Entry struct {
	Seq   int64           `json:"seq"`
	TS    time.Time       `json:"ts"`
	Event string          `json:"event"`
	Actor string          `json:"actor"`
	Data  json.RawMessage `json:"data"`
	Prev  string          `json:"prev"`
	Hash  string          `json:"hash"`
}

// Hash calcula o hash da entrada (o campo Hash não entra no cálculo).
func Hash(e Entry) string {
	e.Hash = ""
	e.TS = e.TS.UTC()
	b, _ := json.Marshal(e) // só tipos serializáveis: não falha
	h := sha256.Sum256(b)
	return hex.EncodeToString(h[:])
}

// Verify confere a cadeia inteira, em ordem de Seq.
func Verify(entries []Entry) error {
	prev := Genesis
	for i, e := range entries {
		if e.Seq != int64(i+1) {
			return fmt.Errorf("auditoria: sequência quebrada na posição %d (seq %d)", i+1, e.Seq)
		}
		if e.Prev != prev {
			return fmt.Errorf("auditoria: encadeamento quebrado na entrada %d", e.Seq)
		}
		if Hash(e) != e.Hash {
			return fmt.Errorf("auditoria: entrada %d adulterada (hash não confere)", e.Seq)
		}
		prev = e.Hash
	}
	return nil
}
