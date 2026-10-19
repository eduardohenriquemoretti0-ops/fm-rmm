package agent

import (
	"fmt"
	"os"
	"strings"
)

// Edição mínima de TOML para dirigir o config do RustDesk. Usa strings LITERAIS
// (key = 'valor'), que no TOML não têm escape: um valor com aspa simples não tem
// representação válida. Por isso validamos a entrada e RECUSAMOS o que não cabe,
// em vez de remover a aspa silenciosamente — remover corromperia a senha gravada.
//
// Fica fora do build tag de Windows de propósito: é lógica de string/arquivo pura,
// testável em qualquer SO (ver toml_edit_test.go).
//
// TODO(2026-10-19): avaliar trocar por uma lib de TOML (ex.: BurntSushi/toml ou
// pelletier/go-toml). Adiado de propósito: o RustDesk grava num formato próprio
// (strings literais, chaves soltas antes de seções) e reescrever com uma lib
// pode mudar o arquivo de um jeito que o cliente RustDesk não espera — precisa
// de validação na VM fm-lab-win10 antes. O bug real (senha corrompida / world-
// readable) já foi fechado aqui com validação + 0o600 + ACL.

const tomlFileMode = 0o600 // senha de sessão: só o dono lê (ACL reforça no Windows)

// validTOMLLiteral recusa valores que não cabem numa string literal de TOML.
func validTOMLLiteral(v string) error {
	for _, r := range v {
		if r == '\'' || r == '\n' || r == '\r' || r < 0x20 {
			return fmt.Errorf("valor TOML inválido (aspa simples ou caractere de controle): %q", v)
		}
	}
	return nil
}

func validateSet(set map[string]string) error {
	for k, v := range set {
		if err := validTOMLLiteral(v); err != nil {
			return fmt.Errorf("chave %q: %w", k, err)
		}
	}
	return nil
}

// editTOML regrava chaves de topo (key = 'valor') e remove as de `drop`.
func editTOML(path string, set map[string]string, drop []string) error {
	if err := validateSet(set); err != nil {
		return err
	}
	b, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	lines := strings.Split(string(b), "\n")
	var out []string
	seen := map[string]bool{}
	skip := func(k string) bool {
		for _, d := range drop {
			if k == d {
				return true
			}
		}
		return false
	}
	for _, ln := range lines {
		t := strings.TrimSpace(ln)
		if i := strings.Index(t, "="); i > 0 && !strings.HasPrefix(t, "[") {
			k := strings.TrimSpace(t[:i])
			if skip(k) {
				continue
			}
			if v, ok := set[k]; ok {
				out = append(out, fmt.Sprintf("%s = '%s'", k, v))
				seen[k] = true
				continue
			}
		}
		out = append(out, ln)
	}
	// chaves novas vão no topo (antes de qualquer [secao])
	var head []string
	for k, v := range set {
		if !seen[k] {
			head = append(head, fmt.Sprintf("%s = '%s'", k, v))
		}
	}
	final := append(head, out...)
	return os.WriteFile(path, []byte(strings.Join(final, "\n")), tomlFileMode)
}

// editTOMLOptions grava chaves sob a seção [options].
func editTOMLOptions(path string, set map[string]string) error {
	if err := validateSet(set); err != nil {
		return err
	}
	b, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	lines := strings.Split(string(b), "\n")
	var out []string
	inOpts := false
	seen := map[string]bool{}
	flush := func() {
		for k, v := range set {
			if !seen[k] {
				out = append(out, fmt.Sprintf("%s = '%s'", k, v))
				seen[k] = true
			}
		}
	}
	for _, ln := range lines {
		t := strings.TrimSpace(ln)
		if strings.HasPrefix(t, "[") {
			if inOpts {
				flush() // fim da [options]: grava as que faltaram
			}
			inOpts = t == "[options]"
			out = append(out, ln)
			continue
		}
		if inOpts {
			if i := strings.Index(t, "="); i > 0 {
				k := strings.TrimSpace(t[:i])
				if v, ok := set[k]; ok {
					out = append(out, fmt.Sprintf("%s = '%s'", k, v))
					seen[k] = true
					continue
				}
			}
		}
		out = append(out, ln)
	}
	if inOpts {
		flush()
	}
	if !hasSection(lines, "[options]") {
		out = append(out, "[options]")
		for k, v := range set {
			if !seen[k] {
				out = append(out, fmt.Sprintf("%s = '%s'", k, v))
			}
		}
	}
	return os.WriteFile(path, []byte(strings.Join(out, "\n")), tomlFileMode)
}

func hasSection(lines []string, sec string) bool {
	for _, l := range lines {
		if strings.TrimSpace(l) == sec {
			return true
		}
	}
	return false
}
