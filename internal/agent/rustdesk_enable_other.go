//go:build !windows

package agent

// Fora do Windows não há motor RustDesk embutido (a captura usa o motor de
// quadros). Mantido para a chamada em New() ser multiplataforma.
func (ag *Agent) enableRustDesk() {}
