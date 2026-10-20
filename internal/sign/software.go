package sign

import (
	"bytes"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"sort"
	"time"
	"unicode"
)

// Catálogo de software (allow-list curada pelo admin).
//
// Mesmo modelo da lista de signers: o catálogo é montado e assinado OFFLINE
// (chave RAIZ), versionado (anti-downgrade no agente), distribuído no check-in
// e guardado pelo agente. O operador nunca digita pkg_id nem comando: ele só
// escolhe o id de um item; o agente resolve o item neste catálogo confiável e
// roda a receita correspondente.
//
// Serialização canônica: JSON compacto, campos na ordem declarada, itens
// ordenados por id, instantes em UTC com precisão de segundo. O agente recusa
// bytes que não sejam a forma canônica (sem maleabilidade). O campo "kind"
// separa este documento da lista de signers: a assinatura de um nunca vale
// como a do outro.

// Gerenciadores de pacote suportados.
const (
	GerenciadorWinget = "winget" // Windows
	GerenciadorApt    = "apt"    // Linux (Debian/Ubuntu)
)

// KindCatalogoSoftware identifica o tipo do documento assinado.
const KindCatalogoSoftware = "software-catalog"

// CatalogoVersaoMinima é a primeira versão válida (0 = nenhum visto).
const CatalogoVersaoMinima = 1

// Erros do catálogo de software. O agente registra o motivo e não o altera.
var (
	ErrCatalogoAssinatura = errors.New("catálogo de software: assinatura inválida (não confere com a raiz)")
	ErrCatalogoMalformado = errors.New("catálogo de software malformado")
	ErrCatalogoVersao     = errors.New("catálogo de software: versão não é maior que a já aceita (downgrade ou replay)")
)

// Alfabetos estritos: nada de espaço, aspas, ';', '$', '`', '|', '&' ou '/'.
// pkg_id e versão NUNCA começam com '-' (não viram opção do gerenciador).
var (
	itemIDRe   = regexp.MustCompile(`^[a-z0-9][a-z0-9.-]{0,47}$`)
	wingetIDRe = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._+-]{0,127}$`)
	aptPkgRe   = regexp.MustCompile(`^[a-z0-9][a-z0-9.+-]{1,127}$`)
	versaoRe   = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._+~:-]{0,63}$`)
	sha256Re   = regexp.MustCompile(`^[0-9a-f]{64}$`)
)

// SoftwareItem é um item da allow-list.
type SoftwareItem struct {
	ID          string `json:"id"`                  // o que o operador escolhe
	Nome        string `json:"nome"`                // texto exibido
	Gerenciador string `json:"gerenciador"`         // winget | apt
	PkgID       string `json:"pkg_id"`              // id EXATO no gerenciador
	Versao      string `json:"versao,omitempty"`    // fixa a versão (opcional)
	Publisher   string `json:"publisher,omitempty"` // informativo/auditoria (opcional)
	SHA256      string `json:"sha256,omitempty"`    // sha256 do instalador; se presente o agente CONFERE e recusa se diverge
}

// SoftwareCatalog é o corpo assinado.
type SoftwareCatalog struct {
	Kind     string         `json:"kind"`
	Version  int            `json:"version"`
	IssuedAt time.Time      `json:"issued_at"`
	Items    []SoftwareItem `json:"items"`
}

func semControle(s string) bool {
	for _, r := range s {
		if unicode.IsControl(r) {
			return false
		}
	}
	return true
}

// Validar confere o item (alfabetos estritos, gerenciador conhecido).
func (it SoftwareItem) Validar() error {
	if !itemIDRe.MatchString(it.ID) {
		return fmt.Errorf("item %q: id inválido (use a-z, 0-9, '.' e '-')", it.ID)
	}
	if it.Nome == "" || len(it.Nome) > 80 || !semControle(it.Nome) {
		return fmt.Errorf("item %q: nome vazio, longo demais ou com caractere de controle", it.ID)
	}
	switch it.Gerenciador {
	case GerenciadorWinget:
		if !wingetIDRe.MatchString(it.PkgID) {
			return fmt.Errorf("item %q: pkg_id winget inválido", it.ID)
		}
	case GerenciadorApt:
		if !aptPkgRe.MatchString(it.PkgID) {
			return fmt.Errorf("item %q: pacote apt inválido", it.ID)
		}
	default:
		return fmt.Errorf("item %q: gerenciador %q desconhecido (winget|apt)", it.ID, it.Gerenciador)
	}
	if it.Versao != "" && !versaoRe.MatchString(it.Versao) {
		return fmt.Errorf("item %q: versão inválida", it.ID)
	}
	if it.SHA256 != "" && !sha256Re.MatchString(it.SHA256) {
		return fmt.Errorf("item %q: sha256 inválido (64 hex minúsculos)", it.ID)
	}
	if len(it.Publisher) > 80 || !semControle(it.Publisher) {
		return fmt.Errorf("item %q: publisher longo demais ou com caractere de controle", it.ID)
	}
	return nil
}

// Item procura um item pelo id.
func (c SoftwareCatalog) Item(id string) (SoftwareItem, bool) {
	for _, it := range c.Items {
		if it.ID == id {
			return it, true
		}
	}
	return SoftwareItem{}, false
}

// CanonicalSoftwareCatalog valida o catálogo e devolve seus bytes canônicos.
func CanonicalSoftwareCatalog(c SoftwareCatalog) ([]byte, error) {
	if c.Kind != "" && c.Kind != KindCatalogoSoftware {
		return nil, fmt.Errorf("%w: kind %q", ErrCatalogoMalformado, c.Kind)
	}
	if c.Version < CatalogoVersaoMinima {
		return nil, fmt.Errorf("%w: versão %d inválida", ErrCatalogoMalformado, c.Version)
	}
	if c.IssuedAt.IsZero() {
		return nil, fmt.Errorf("%w: issued_at ausente", ErrCatalogoMalformado)
	}
	out := SoftwareCatalog{
		Kind:     KindCatalogoSoftware,
		Version:  c.Version,
		IssuedAt: c.IssuedAt.UTC().Truncate(time.Second),
		Items:    make([]SoftwareItem, 0, len(c.Items)),
	}
	ids := map[string]bool{}
	for _, it := range c.Items {
		if err := it.Validar(); err != nil {
			return nil, fmt.Errorf("%w: %v", ErrCatalogoMalformado, err)
		}
		if ids[it.ID] {
			return nil, fmt.Errorf("%w: id duplicado %q", ErrCatalogoMalformado, it.ID)
		}
		ids[it.ID] = true
		out.Items = append(out.Items, it)
	}
	sort.Slice(out.Items, func(i, j int) bool { return out.Items[i].ID < out.Items[j].ID })
	return json.Marshal(out)
}

// SignSoftwareCatalog assina a forma canônica com a chave RAIZ offline.
func SignSoftwareCatalog(raiz ed25519.PrivateKey, c SoftwareCatalog) (raw, sig []byte, err error) {
	raw, err = CanonicalSoftwareCatalog(c)
	if err != nil {
		return nil, nil, err
	}
	return raw, ed25519.Sign(raiz, raw), nil
}

// ParseSoftwareCatalog verifica a assinatura de raw contra a RAIZ e só então
// interpreta o catálogo. Recusa bytes que não sejam a forma canônica.
func ParseSoftwareCatalog(raiz ed25519.PublicKey, raw, sig []byte) (SoftwareCatalog, error) {
	var c SoftwareCatalog
	if len(raiz) != ed25519.PublicKeySize || len(sig) != ed25519.SignatureSize || !ed25519.Verify(raiz, raw, sig) {
		return c, ErrCatalogoAssinatura
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&c); err != nil {
		return c, fmt.Errorf("%w: %v", ErrCatalogoMalformado, err)
	}
	if c.Kind != KindCatalogoSoftware {
		return c, fmt.Errorf("%w: kind %q", ErrCatalogoMalformado, c.Kind)
	}
	canon, err := CanonicalSoftwareCatalog(c)
	if err != nil {
		return c, err
	}
	if !bytes.Equal(canon, raw) {
		return c, fmt.Errorf("%w: bytes não estão na forma canônica", ErrCatalogoMalformado)
	}
	return c, nil
}
