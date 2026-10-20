package console

import (
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/eduardohenriquemoretti0-ops/fm-rmm/internal/server"
)

// Limites contra brute-force de credencial de BMC. Só FALHAS contam (credencial
// recusada pelo BMC, host fora do inventário/de outro grupo); sucesso nunca
// consome cota, então o uso normal não trava. Janela deslizante em memória
// (instância única); entradas vazias são removidas.
const (
	bmcMaxFalhasOperador = 5
	bmcMaxFalhasHost     = 10
	bmcJanelaFalhas      = 10 * time.Minute
)

type limitadorBMC struct {
	mu      sync.Mutex
	falhas  map[string][]time.Time
	janela  time.Duration
	maxOp   int
	maxHost int
}

func novoLimitadorBMC() *limitadorBMC {
	return &limitadorBMC{falhas: map[string][]time.Time{}, janela: bmcJanelaFalhas,
		maxOp: bmcMaxFalhasOperador, maxHost: bmcMaxFalhasHost}
}

func chaveOp(opID string) string { return "op:" + opID }

func chaveHost(host string, porta int) string {
	h, err := server.NormalizaBMCHost(host)
	if err != nil {
		h = strings.ToLower(host)
	}
	if porta == 0 {
		porta = server.PortaBMCPadrao
	}
	return "host:" + h + ":" + strconv.Itoa(porta)
}

// poda descarta falhas fora da janela (chamar com mu preso).
func (l *limitadorBMC) poda(k string, agora time.Time) []time.Time {
	v := l.falhas[k]
	i := 0
	for i < len(v) && !v[i].After(agora.Add(-l.janela)) {
		i++
	}
	v = v[i:]
	if len(v) == 0 {
		delete(l.falhas, k)
		return nil
	}
	l.falhas[k] = v
	return v
}

func (l *limitadorBMC) limite(k string) int {
	if strings.HasPrefix(k, "op:") {
		return l.maxOp
	}
	return l.maxHost
}

// falha registra uma tentativa malsucedida.
func (l *limitadorBMC) falha(k string, agora time.Time) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if len(l.falhas) > 4096 { // varredura oportunista: memória limitada
		for kk := range l.falhas {
			l.poda(kk, agora)
		}
	}
	l.poda(k, agora)
	l.falhas[k] = append(l.falhas[k], agora)
}

// bloqueado devolve >0 (tempo até liberar) se a chave estourou o limite na janela.
func (l *limitadorBMC) bloqueado(k string, agora time.Time) time.Duration {
	l.mu.Lock()
	defer l.mu.Unlock()
	v := l.poda(k, agora)
	lim := l.limite(k)
	if len(v) < lim {
		return 0
	}
	// libera quando a falha (len-lim)-ésima sair da janela
	return v[len(v)-lim].Add(l.janela).Sub(agora)
}
