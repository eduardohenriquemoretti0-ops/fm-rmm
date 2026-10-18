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

type Param struct {
	Desc    string
	Allowed map[string][]string // por GOOS: valores aceitos
}

type Action struct {
	Name    string
	Desc    string
	Changes bool // altera o estado da máquina (não é só leitura)
	Timeout time.Duration
	Params  map[string]Param
	Scripts map[string]string // GOOS -> script (powershell no windows, sh nos demais)
}

var safeValue = regexp.MustCompile(`^[A-Za-z0-9._-]{1,64}$`)

var actions = map[string]Action{}

func register(a Action) {
	if a.Timeout == 0 {
		a.Timeout = 60 * time.Second
	}
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
			return a, fmt.Errorf("parâmetro obrigatório ausente: %q", k)
		}
		if !safeValue.MatchString(v) {
			return a, fmt.Errorf("valor inválido para %q", k)
		}
		if !contains(p.Allowed[goos], v) {
			return a, fmt.Errorf("valor %q não permitido para %q em %s (aceitos: %v)", v, k, goos, p.Allowed[goos])
		}
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
