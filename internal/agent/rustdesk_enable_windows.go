//go:build windows

package agent

// enableRustDesk registra o motor RustDesk se o bundle trouxer host+chave do
// nosso servidor. Windows usa RustDesk para captura (resolve Session 0).
func (ag *Agent) enableRustDesk() {
	if ag.bundle.RustDeskHost != "" && ag.bundle.RustDeskKey != "" {
		ag.SetMediaEngine("rustdesk", NewRustDeskMedia(ag.Log, ag.bundle.RustDeskHost, ag.bundle.RustDeskKey))
	}
}
