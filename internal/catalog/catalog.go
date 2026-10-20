// Package catalog é a lista FECHADA de ações que o agente sabe executar.
//
// Não existe ação "rodar comando livre". O servidor recusa enfileirar o que
// não está aqui, e o agente recusa executar o que não está aqui (os dois
// conferem, com o mesmo código). Parâmetros só aceitam valores de lista.
package catalog

import (
	"fmt"
	"regexp"
	"sort"
	"time"
)

// Param descreve um parâmetro da ação. O valor é aceito se estiver em
// Allowed (lista fechada, por GOOS) OU casar com Pattern (regex). Se nenhum
// dos dois estiver definido, nada é aceito (falha fechada).
type Param struct {
	Desc    string
	Allowed map[string][]string // por GOOS: valores aceitos
	// Pattern é uma regex (RE2) para valores livres, como MAC e IP. É
	// ancorada automaticamente (^(?:...)$). Mesmo casando, o valor precisa
	// ter só [A-Za-z0-9.:-] e até 64 chars: ';', espaço, aspas, $, `, etc.
	// nunca passam, independente do Pattern.
	Pattern string
	// Optional permite omitir o parâmetro (o script usa um default).
	Optional bool

	re *regexp.Regexp // Pattern compilado em register
}

type Action struct {
	Name    string
	Desc    string
	Changes bool // altera o estado da máquina (não é só leitura)
	// Native: a ação NÃO roda script; o agente a trata por código próprio
	// (ex.: forcar_criptografia, que sela a chave de recuperação). Scripts só
	// lista os SOs suportados (valores vazios); runAction recusa ações nativas.
	Native bool
	// Destructive: a ação é IRREVERSÍVEL (ex.: wipe_remoto). Exige, além da
	// concessão assinada, step-up no console e uma confirmação explícita tipada
	// no payload; o agente recusa se qualquer uma faltar. Sempre implica Changes.
	Destructive bool
	Timeout     time.Duration
	Params      map[string]Param
	Scripts     map[string]string // GOOS -> script (powershell no windows, sh nos demais)
}

var safeValue = regexp.MustCompile(`^[A-Za-z0-9._-]{1,64}$`)

// patternSafe é o alfabeto máximo de um valor validado por Pattern. É a trava
// anti-injeção: vale ANTES do Pattern, então um Pattern frouxo não abre brecha.
var patternSafe = regexp.MustCompile(`^[A-Za-z0-9.:-]{1,64}$`)

var actions = map[string]Action{}

func register(a Action) {
	if a.Timeout == 0 {
		a.Timeout = 60 * time.Second
	}
	if a.Destructive && !a.Changes {
		panic("catalog: ação destrutiva precisa ser Changes: " + a.Name)
	}
	ps := make(map[string]Param, len(a.Params))
	for k, p := range a.Params {
		if p.Pattern != "" {
			p.re = regexp.MustCompile(`^(?:` + p.Pattern + `)$`) // panic na carga se inválido
		}
		ps[k] = p
	}
	a.Params = ps
	actions[a.Name] = a
}

func Get(name string) (Action, bool) { a, ok := actions[name]; return a, ok }

// Names lista as ações em ordem alfabética.
func Names() []string {
	n := make([]string, 0, len(actions))
	for k := range actions {
		n = append(n, k)
	}
	sort.Strings(n)
	return n
}

// Validate confere ação, sistema e parâmetros. Usado pelo servidor (ao
// enfileirar) e pelo agente (antes de executar).
func Validate(name, goos string, params map[string]string) (Action, error) {
	a, ok := actions[name]
	if !ok {
		return a, fmt.Errorf("ação fora do catálogo: %q", name)
	}
	if _, ok := a.Scripts[goos]; !ok {
		return a, fmt.Errorf("ação %q não existe para %s", name, goos)
	}
	for k := range params {
		if _, ok := a.Params[k]; !ok {
			return a, fmt.Errorf("parâmetro desconhecido: %q", k)
		}
	}
	for k, p := range a.Params {
		v, ok := params[k]
		if !ok {
			if p.Optional {
				continue
			}
			return a, fmt.Errorf("parâmetro obrigatório ausente: %q", k)
		}
		// Aceito por lista fechada (alfabeto restrito) OU por Pattern (alfabeto
		// restrito + regex). Fora disso, recusa.
		if safeValue.MatchString(v) && contains(p.Allowed[goos], v) {
			continue
		}
		if p.re != nil && patternSafe.MatchString(v) && p.re.MatchString(v) {
			continue
		}
		if p.re != nil {
			return a, fmt.Errorf("valor inválido para %q: fora do padrão aceito", k)
		}
		if !safeValue.MatchString(v) {
			return a, fmt.Errorf("valor inválido para %q", k)
		}
		return a, fmt.Errorf("valor %q não permitido para %q em %s (aceitos: %v)", v, k, goos, p.Allowed[goos])
	}
	return a, nil
}

func contains(l []string, v string) bool {
	for _, x := range l {
		if x == v {
			return true
		}
	}
	return false
}
