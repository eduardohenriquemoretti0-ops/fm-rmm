package agent

import (
	"bytes"
	"context"
	"errors"
	"os/exec"
	"sort"
	"time"

	"github.com/eduardohenriquemoretti0-ops/fm-rmm/internal/catalog"
	"github.com/eduardohenriquemoretti0-ops/fm-rmm/internal/proto"
)

// capWriter guarda até max bytes e descarta o resto (marca truncado).
type capWriter struct {
	buf       bytes.Buffer
	max       int
	truncated bool
}

func (w *capWriter) Write(p []byte) (int, error) {
	room := w.max - w.buf.Len()
	if room <= 0 {
		w.truncated = true
		return len(p), nil
	}
	if len(p) > room {
		w.buf.Write(p[:room])
		w.truncated = true
		return len(p), nil
	}
	return w.buf.Write(p)
}

// runAction executa o script da ação para este sistema, com timeout e saída
// limitada. Os parâmetros já passaram por catalog.Validate (lista fechada).
func runAction(ctx context.Context, a catalog.Action, params map[string]string) (string, int, bool, error) {
	ctx, cancel := context.WithTimeout(ctx, a.Timeout)
	defer cancel()
	keys := make([]string, 0, len(params))
	for k := range params {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	cmd := scriptCommand(ctx, a, keys, params)
	out := &capWriter{max: proto.MaxOutputSize}
	cmd.Stdout, cmd.Stderr = out, out
	cmd.WaitDelay = 5 * time.Second
	err := cmd.Run()
	code := 0
	var ee *exec.ExitError
	switch {
	case errors.Is(ctx.Err(), context.DeadlineExceeded):
		return out.buf.String(), -1, out.truncated, errors.New("tempo limite da ação excedido (" + a.Timeout.String() + ")")
	case errors.As(err, &ee):
		code = ee.ExitCode()
		err = nil
	case err != nil:
		return out.buf.String(), -1, out.truncated, err
	}
	return out.buf.String(), code, out.truncated, nil
}
