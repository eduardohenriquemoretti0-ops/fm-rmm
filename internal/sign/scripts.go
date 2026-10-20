package sign

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"sort"
	"time"
	"unicode"
	"unicode/utf8"
)

// Biblioteca de scripts ASSINADA.
//
// NÃO é terminal remoto. Cada script é escrito e revisado UMA vez, vira uma
// entrada NOMEADA (id), VERSIONADA (versao) e com o hash do corpo (sha256), e
// a biblioteca inteira é assinada OFFLINE pela chave RAIZ. O operador escolhe
// (script_id + versao); nunca digita nem edita o corpo. O agente resolve a
// entrada na biblioteca confiável, reconfere o sha256 e só então executa.
//
// Mesmo modelo do catálogo de software: forma canônica estrita (JSON compacto,
// campos na ordem declarada, entradas ordenadas por id e versão, UTC em
// segundos), anti-downgrade no agente e "kind" próprio, de modo que a
// assinatura desta lista nunca vale como a de outra.

// Interpretadores suportados (lista fechada).
const (
	InterpretePowerShell = "powershell" // Windows
	InterpreteBash       = "bash"       // Linux
)

// KindBibliotecaScripts identifica o tipo do documento assinado.
const KindBibliotecaScripts = "script-library"

// Limites: um script revisado é curto; o teto evita biblioteca abusiva.
const (
	ScriptCorpoMax     = 64 * 1024
	BibliotecaMaxItens = 200
)

// Erros da biblioteca de scripts.
var (
	ErrBibliotecaAssinatura = errors.New("biblioteca de scripts: assinatura inválida (não confere com a raiz)")
	ErrBibliotecaMalformada = errors.New("biblioteca de scripts malformada")
	ErrBibliotecaVersao     = errors.New("biblioteca de scripts: versão não é maior que a já aceita (downgrade ou replay)")
)

// Alfabetos estritos (os mesmos Patterns do catálogo de ações, que ainda os
// confere contra o alfabeto anti-injeção). Nunca começam com '-'.
var (
	scriptIDRe     = regexp.MustCompile(`^[a-z0-9][a-z0-9.-]{0,47}$`)
	scriptVersaoRe = regexp.MustCompile(`^[0-9][0-9A-Za-z.-]{0,31}$`)
)

// ScriptEntry é uma versão de um script revisado.
type ScriptEntry struct {
	ID         string `json:"id"`         // o que o operador escolhe
	Nome       string `json:"nome"`       // texto exibido
	Versao     string `json:"versao"`     // o que o operador escolhe
	Interprete string `json:"interprete"` // powershell | bash
	Corpo      string `json:"corpo"`      // revisado; NUNCA vem de um job
	SHA256     string `json:"sha256"`     // hash (hex) do corpo
}

// ScriptLibrary é o corpo assinado.
type ScriptLibrary struct {
	Kind     string        `json:"kind"`
	Version  int           `json:"version"`
	IssuedAt time.Time     `json:"issued_at"`
	Scripts  []ScriptEntry `json:"scripts"`
}

// HashCorpoScript devolve o sha256 (hex minúsculo) do corpo.
func HashCorpoScript(corpo string) string {
	h := sha256.Sum256([]byte(corpo))
	return hex.EncodeToString(h[:])
}

// ScriptIDValido / ScriptVersaoValida expõem os alfabetos aceitos.
func ScriptIDValido(s string) bool     { return scriptIDRe.MatchString(s) }
func ScriptVersaoValida(s string) bool { return scriptVersaoRe.MatchString(s) }

func corpoSemControle(s string) bool {
	for _, r := range s {
		if r == '\n' || r == '\r' || r == '\t' {
			continue
		}
		if unicode.IsControl(r) {
			return false
		}
	}
	return true
}

// Validar confere a entrada, inclusive o sha256 contra o corpo.
func (e ScriptEntry) Validar() error {
	if !scriptIDRe.MatchString(e.ID) {
		return fmt.Errorf("script %q: id inválido (use a-z, 0-9, '.' e '-')", e.ID)
	}
	if !scriptVersaoRe.MatchString(e.Versao) {
		return fmt.Errorf("script %q: versão %q inválida (comece com dígito; A-Z a-z 0-9 '.' '-')", e.ID, e.Versao)
	}
	if e.Nome == "" || len(e.Nome) > 80 || !semControle(e.Nome) {
		return fmt.Errorf("script %q: nome vazio, longo demais ou com caractere de controle", e.ID)
	}
	switch e.Interprete {
	case InterpretePowerShell, InterpreteBash:
	default:
		return fmt.Errorf("script %q: interpretador %q desconhecido (powershell|bash)", e.ID, e.Interprete)
	}
	if e.Corpo == "" || len(e.Corpo) > ScriptCorpoMax || !utf8.ValidString(e.Corpo) || !corpoSemControle(e.Corpo) {
		return fmt.Errorf("script %q: corpo vazio, maior que %d bytes, UTF-8 inválido ou com caractere de controle", e.ID, ScriptCorpoMax)
	}
	if !sha256Re.MatchString(e.SHA256) {
		return fmt.Errorf("script %q: sha256 inválido (64 hex minúsculos)", e.ID)
	}
	if HashCorpoScript(e.Corpo) != e.SHA256 {
		return fmt.Errorf("script %q v%s: sha256 não confere com o corpo", e.ID, e.Versao)
	}
	return nil
}

// Script procura a entrada exata (id + versão).
func (l ScriptLibrary) Script(id, versao string) (ScriptEntry, bool) {
	for _, e := range l.Scripts {
		if e.ID == id && e.Versao == versao {
			return e, true
		}
	}
	return ScriptEntry{}, false
}

// CanonicalScriptLibrary valida a biblioteca e devolve seus bytes canônicos.
func CanonicalScriptLibrary(l ScriptLibrary) ([]byte, error) {
	if l.Kind != "" && l.Kind != KindBibliotecaScripts {
		return nil, fmt.Errorf("%w: kind %q", ErrBibliotecaMalformada, l.Kind)
	}
	if l.Version < CatalogoVersaoMinima {
		return nil, fmt.Errorf("%w: versão %d inválida", ErrBibliotecaMalformada, l.Version)
	}
	if l.IssuedAt.IsZero() {
		return nil, fmt.Errorf("%w: issued_at ausente", ErrBibliotecaMalformada)
	}
	if len(l.Scripts) > BibliotecaMaxItens {
		return nil, fmt.Errorf("%w: mais de %d scripts", ErrBibliotecaMalformada, BibliotecaMaxItens)
	}
	out := ScriptLibrary{
		Kind:     KindBibliotecaScripts,
		Version:  l.Version,
		IssuedAt: l.IssuedAt.UTC().Truncate(time.Second),
		Scripts:  make([]ScriptEntry, 0, len(l.Scripts)),
	}
	vistos := map[string]bool{}
	for _, e := range l.Scripts {
		if err := e.Validar(); err != nil {
			return nil, fmt.Errorf("%w: %v", ErrBibliotecaMalformada, err)
		}
		k := e.ID + "\x00" + e.Versao
		if vistos[k] {
			return nil, fmt.Errorf("%w: %q versão %q duplicada", ErrBibliotecaMalformada, e.ID, e.Versao)
		}
		vistos[k] = true
		out.Scripts = append(out.Scripts, e)
	}
	sort.Slice(out.Scripts, func(i, j int) bool {
		if out.Scripts[i].ID != out.Scripts[j].ID {
			return out.Scripts[i].ID < out.Scripts[j].ID
		}
		return out.Scripts[i].Versao < out.Scripts[j].Versao
	})
	return json.Marshal(out)
}

// SignScriptLibrary assina a forma canônica com a chave RAIZ offline.
func SignScriptLibrary(raiz ed25519.PrivateKey, l ScriptLibrary) (raw, sig []byte, err error) {
	raw, err = CanonicalScriptLibrary(l)
	if err != nil {
		return nil, nil, err
	}
	return raw, ed25519.Sign(raiz, raw), nil
}

// ParseScriptLibrary verifica a assinatura de raw contra a RAIZ e só então
// interpreta a biblioteca. Recusa bytes que não sejam a forma canônica.
func ParseScriptLibrary(raiz ed25519.PublicKey, raw, sig []byte) (ScriptLibrary, error) {
	var l ScriptLibrary
	if len(raiz) != ed25519.PublicKeySize || len(sig) != ed25519.SignatureSize || !ed25519.Verify(raiz, raw, sig) {
		return l, ErrBibliotecaAssinatura
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&l); err != nil {
		return l, fmt.Errorf("%w: %v", ErrBibliotecaMalformada, err)
	}
	if l.Kind != KindBibliotecaScripts {
		return l, fmt.Errorf("%w: kind %q", ErrBibliotecaMalformada, l.Kind)
	}
	canon, err := CanonicalScriptLibrary(l)
	if err != nil {
		return l, err
	}
	if !bytes.Equal(canon, raw) {
		return l, fmt.Errorf("%w: bytes não estão na forma canônica", ErrBibliotecaMalformada)
	}
	return l, nil
}
