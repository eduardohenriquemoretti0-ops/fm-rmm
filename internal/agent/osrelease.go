package agent

import (
	"bufio"
	"io"
	"os"
	"strings"
)

// lerOSRelease devolve ID e VERSION_ID do arquivo os-release (vazios se não
// existir/ilegível). Leitura somente; sem execução de nada.
func lerOSRelease(path string) (id, versaoID string) {
	f, err := os.Open(path)
	if err != nil {
		return "", ""
	}
	defer f.Close()
	sc := bufio.NewScanner(io.LimitReader(f, 64<<10))
	var linhas []string
	for sc.Scan() {
		linhas = append(linhas, sc.Text())
	}
	return parseOSRelease(strings.Join(linhas, "\n"))
}

// parseOSRelease extrai ID e VERSION_ID (aspas simples/duplas removidas).
func parseOSRelease(conteudo string) (id, versaoID string) {
	for _, ln := range strings.Split(conteudo, "\n") {
		k, v, ok := strings.Cut(strings.TrimSpace(ln), "=")
		if !ok {
			continue
		}
		v = strings.Trim(strings.TrimSpace(v), `"'`)
		if len(v) > 64 {
			continue
		}
		switch k {
		case "ID":
			id = strings.ToLower(v)
		case "VERSION_ID":
			versaoID = v
		}
	}
	return id, versaoID
}
