package server

import (
	"errors"
	"io"
	"log/slog"
	"net"
	"net/http"
	"sync"
	"time"
)

// Relay faz a ponte TLS da mídia/controle quando não há P2P (requisito do
// brief). Ele NÃO lê o conteúdo: só junta as duas pontas de uma sessão
// autorizada (agente + console) e copia bytes nos dois sentidos.
//
// A sessão é identificada pelo par (session_id, relay_token). O token foi
// entregue ao agente na concessão assinada e ao console na criação da sessão;
// o relay confere os dois contra o banco antes de parear.
type Relay struct {
	Store *Store
	Log   *slog.Logger
	mu    sync.Mutex
	wait  map[string]*parked // session_id -> ponta já esperando
}

type parked struct {
	conn  net.Conn
	ready chan net.Conn // recebe a outra ponta
}

func NewRelay(st *Store, log *slog.Logger) *Relay {
	return &Relay{Store: st, Log: log, wait: map[string]*parked{}}
}

func (rl *Relay) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("POST /relay", rl.handle)
	return mux
}

// pairTimeout: quanto a 1ª ponta espera a 2ª antes de desistir.
const pairTimeout = 30 * time.Second

func (rl *Relay) handle(w http.ResponseWriter, r *http.Request) {
	sid := r.Header.Get("X-Session-ID")
	token := r.Header.Get("X-Relay-Token")
	ses, err := rl.Store.CheckRelayToken(sid, token)
	// aceita enquanto a sessão está autorizada e não terminou (o console pode
	// chegar ao relay antes de o agente pegar a concessão no check-in)
	if err != nil || (ses.Status != "queued" && ses.Status != "delivered" && ses.Status != "active") {
		http.Error(w, "sessão inválida", http.StatusForbidden)
		return
	}
	hj, ok := w.(http.Hijacker)
	if !ok {
		http.Error(w, "sem hijack", http.StatusInternalServerError)
		return
	}
	conn, _, err := hj.Hijack()
	if err != nil {
		return
	}
	// sinaliza ao cliente que a ponte está de pé
	_, _ = conn.Write([]byte("HTTP/1.1 101 Switching Protocols\r\nUpgrade: fm-relay\r\nConnection: Upgrade\r\n\r\n"))

	other, err := rl.rendezvous(sid, conn)
	if errors.Is(err, errBridged) {
		return // a outra ponta assumiu a cópia; não feche esta conexão aqui
	}
	if err != nil {
		conn.Close()
		return
	}
	bridge(conn, other)
}

// rendezvous pareia duas pontas da mesma sessão.
func (rl *Relay) rendezvous(sid string, conn net.Conn) (net.Conn, error) {
	rl.mu.Lock()
	if p, ok := rl.wait[sid]; ok {
		delete(rl.wait, sid)
		rl.mu.Unlock()
		p.ready <- conn // entrega esta ponta à 1ª, que faz a ponte
		return nil, errBridged
	}
	p := &parked{conn: conn, ready: make(chan net.Conn, 1)}
	rl.wait[sid] = p
	rl.mu.Unlock()

	select {
	case other := <-p.ready:
		return other, nil
	case <-time.After(pairTimeout):
		rl.mu.Lock()
		if rl.wait[sid] == p {
			delete(rl.wait, sid)
		}
		rl.mu.Unlock()
		return nil, errors.New("sem par no tempo limite")
	}
}

// errBridged: a 2ª ponta entregou sua conexão à 1ª; quem faz a cópia é a 1ª.
var errBridged = errors.New("ponte assumida pela outra ponta")

func bridge(a, b net.Conn) {
	defer a.Close()
	defer b.Close()
	done := make(chan struct{}, 2)
	cp := func(dst, src net.Conn) {
		_, _ = io.Copy(dst, src)
		if c, ok := dst.(interface{ CloseWrite() error }); ok {
			_ = c.CloseWrite()
		}
		done <- struct{}{}
	}
	go cp(a, b)
	go cp(b, a)
	<-done
}
