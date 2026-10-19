package sign

import (
	"bytes"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"time"
)

// Lista de signers (trust-set do agente).
//
// A lista diz QUAIS chaves de operador o agente aceita além da chave raiz.
// Ela é assinada (Ed25519 destacada) pela chave RAIZ, que fica offline e cuja
// parte pública já vem no bundle do agente (Bundle.SignerPub). O agente só
// confia em lista cuja assinatura confere com essa raiz.
//
// Serialização canônica: JSON compacto, campos na ordem declarada, signers
// ordenados por key_id, instantes em UTC com precisão de segundo. O agente
// recusa lista cujos bytes NÃO sejam a própria forma canônica, para não haver
// duas representações válidas da mesma lista (maleabilidade).

// Papéis de um signer. Só informativos neste pacote; a autorização por papel
// é feita no servidor (RBAC) e não muda a verificação de assinatura.
const (
	RoleAdmin    = "admin"
	RoleOperator = "operator"
)

// ListaVersaoMinima é a primeira versão válida de uma lista (0 = nenhuma vista).
const ListaVersaoMinima = 1

// Erros de lista de signers. O agente registra o motivo e não altera o trust-set.
var (
	ErrListaAssinatura = errors.New("lista de signers: assinatura inválida (não confere com a raiz)")
	ErrListaMalformada = errors.New("lista de signers malformada")
	ErrListaVersao     = errors.New("lista de signers: versão não é maior que a já aceita (downgrade ou replay)")
)

// SignerEntry é um signer autorizado dentro da lista.
type SignerEntry struct {
	KeyID    string     `json:"key_id"`
	Pub      string     `json:"pub"`                 // Ed25519, base64
	Role     string     `json:"role"`                // admin | operator
	NotAfter *time.Time `json:"not_after,omitempty"` // opcional: validade do signer
}

// SignerList é o corpo assinado. Versão cresce a cada alteração.
type SignerList struct {
	Version  int           `json:"version"`
	IssuedAt time.Time     `json:"issued_at"`
	Signers  []SignerEntry `json:"signers"`
}

// CanonicalSignerList valida a lista e devolve seus bytes canônicos. Não muda
// a entrada: trabalha numa cópia (signers ordenados, instantes normalizados).
func CanonicalSignerList(l SignerList) ([]byte, error) {
	if l.Version < ListaVersaoMinima {
		return nil, fmt.Errorf("%w: versão %d inválida", ErrListaMalformada, l.Version)
	}
	if l.IssuedAt.IsZero() {
		return nil, fmt.Errorf("%w: issued_at ausente", ErrListaMalformada)
	}
	out := SignerList{
		Version:  l.Version,
		IssuedAt: l.IssuedAt.UTC().Truncate(time.Second),
		Signers:  make([]SignerEntry, 0, len(l.Signers)),
	}
	ids := map[string]bool{}
	pubs := map[string]bool{}
	for _, s := range l.Signers {
		pub, err := DecodePub(s.Pub)
		if err != nil {
			return nil, fmt.Errorf("%w: signer %q: %v", ErrListaMalformada, s.KeyID, err)
		}
		if s.KeyID != KeyID(pub) {
			return nil, fmt.Errorf("%w: key_id %q não confere com a chave pública", ErrListaMalformada, s.KeyID)
		}
		if s.Role != RoleAdmin && s.Role != RoleOperator {
			return nil, fmt.Errorf("%w: papel %q desconhecido", ErrListaMalformada, s.Role)
		}
		if ids[s.KeyID] || pubs[s.Pub] {
			return nil, fmt.Errorf("%w: signer duplicado %q", ErrListaMalformada, s.KeyID)
		}
		ids[s.KeyID], pubs[s.Pub] = true, true
		e := SignerEntry{KeyID: s.KeyID, Pub: base64.StdEncoding.EncodeToString(pub), Role: s.Role}
		if s.NotAfter != nil {
			na := s.NotAfter.UTC().Truncate(time.Second)
			e.NotAfter = &na
		}
		out.Signers = append(out.Signers, e)
	}
	sort.Slice(out.Signers, func(i, j int) bool { return out.Signers[i].KeyID < out.Signers[j].KeyID })
	return json.Marshal(out)
}

// SignSignerList assina a forma canônica da lista com a chave RAIZ offline.
// Devolve os bytes canônicos e a assinatura destacada.
func SignSignerList(raiz ed25519.PrivateKey, l SignerList) (raw, sig []byte, err error) {
	raw, err = CanonicalSignerList(l)
	if err != nil {
		return nil, nil, err
	}
	return raw, ed25519.Sign(raiz, raw), nil
}

// ParseSignerList verifica a assinatura de raw contra a RAIZ e só então
// interpreta a lista. Recusa bytes que não sejam a forma canônica.
func ParseSignerList(raiz ed25519.PublicKey, raw, sig []byte) (SignerList, error) {
	var l SignerList
	if len(raiz) != ed25519.PublicKeySize || len(sig) != ed25519.SignatureSize || !ed25519.Verify(raiz, raw, sig) {
		return l, ErrListaAssinatura
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&l); err != nil {
		return l, fmt.Errorf("%w: %v", ErrListaMalformada, err)
	}
	canon, err := CanonicalSignerList(l)
	if err != nil {
		return l, err
	}
	if !bytes.Equal(canon, raw) {
		return l, fmt.Errorf("%w: bytes não estão na forma canônica", ErrListaMalformada)
	}
	return l, nil
}

// TrustedKey é uma chave aceita para verificar jobs e concessões.
type TrustedKey struct {
	KeyID    string
	Pub      ed25519.PublicKey
	Role     string
	NotAfter time.Time // zero = sem validade
}

// TrustSet é o conjunto de chaves aceitas. O valor zero não aceita nada.
type TrustSet struct {
	Keys []TrustedKey
}

// SingleKey é um trust-set com uma chave só, sem validade (compatível com o
// fluxo de uma chave de admin).
func SingleKey(pub ed25519.PublicKey) TrustSet {
	return TrustSet{Keys: []TrustedKey{{KeyID: KeyID(pub), Pub: pub, Role: RoleAdmin}}}
}

// TrustFromList monta o trust-set = raiz + signers da lista que ainda estão
// válidos em now (signers com not_after vencido são descartados).
func TrustFromList(raiz ed25519.PublicKey, l SignerList, now time.Time) (TrustSet, error) {
	ts := SingleKey(raiz)
	for _, s := range l.Signers {
		pub, err := DecodePub(s.Pub)
		if err != nil {
			return TrustSet{}, fmt.Errorf("%w: %v", ErrListaMalformada, err)
		}
		k := TrustedKey{KeyID: s.KeyID, Pub: pub, Role: s.Role}
		if s.NotAfter != nil {
			if !now.Before(*s.NotAfter) {
				continue // vencido: descartado na ingestão
			}
			k.NotAfter = *s.NotAfter
		}
		ts.Keys = append(ts.Keys, k)
	}
	return ts, nil
}

// Usable devolve as chaves que valem em now (não vencidas). Chaves com
// comprimento inválido nunca são devolvidas.
func (ts TrustSet) Usable(now time.Time) []ed25519.PublicKey {
	out := make([]ed25519.PublicKey, 0, len(ts.Keys))
	for _, k := range ts.Keys {
		if len(k.Pub) != ed25519.PublicKeySize {
			continue
		}
		if !k.NotAfter.IsZero() && !now.Before(k.NotAfter) {
			continue
		}
		out = append(out, k.Pub)
	}
	return out
}

// assina confere msg/sig contra QUALQUER chave usável em now.
func (ts TrustSet) assina(msg, sig []byte, now time.Time) bool {
	if len(sig) != ed25519.SignatureSize {
		return false
	}
	for _, pub := range ts.Usable(now) {
		if ed25519.Verify(pub, msg, sig) {
			return true
		}
	}
	return false
}
