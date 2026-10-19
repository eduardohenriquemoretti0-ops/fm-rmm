package agent

import (
	"bufio"
	"crypto/rand"
	"crypto/subtle"
	"encoding/hex"
	"fmt"
	"net"
	"sync"
	"time"
)

// hbServer é o lado do serviço (SYSTEM) do indicador de sessão do Windows: um
// canal de liveness em loopback (127.0.0.1) com o helper que roda na sessão do
// usuário. Fica neutro de propósito — sem dependência de Win32 — para ser
// testável em qualquer SO (ver indicator_hb_test.go).
//
// Protocolo (linhas \n):
//   helper -> serviço: "HELLO <token>"  (prova de que subiu na sessão = ack)
//   helper -> serviço: "HB"             (heartbeat periódico)
//   serviço -> helper: "QUIT"           (no Stop: helper retira o aviso e sai)
//
// Modelo de ameaça: o indicador existe para o USUÁRIO do endpoint saber da
// sessão (transparência/LGPD). O token (passado só ao helper) barra heartbeat
// espúrio; não é a autenticação da sessão — essa é mTLS + concessão assinada.
type hbServer struct {
	ln       net.Listener
	tok      string
	timeout  time.Duration
	acked    chan struct{}
	lost     chan struct{}
	done     chan struct{}
	stopOnce sync.Once
	lostOnce sync.Once
	ackOnce  sync.Once
}

// newHBServer abre o listener em 127.0.0.1:porta-efêmera e começa a aceitar.
func newHBServer(timeout time.Duration) (*hbServer, error) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return nil, err
	}
	b := make([]byte, 24)
	if _, err := rand.Read(b); err != nil {
		ln.Close()
		return nil, err
	}
	s := &hbServer{
		ln:      ln,
		tok:     hex.EncodeToString(b),
		timeout: timeout,
		acked:   make(chan struct{}),
		lost:    make(chan struct{}),
		done:    make(chan struct{}),
	}
	go s.accept()
	return s, nil
}

func (s *hbServer) addr() string           { return s.ln.Addr().String() }
func (s *hbServer) token() string          { return s.tok }
func (s *hbServer) Lost() <-chan struct{}  { return s.lost }
func (s *hbServer) signalAck()             { s.ackOnce.Do(func() { close(s.acked) }) }
func (s *hbServer) signalLost()            { s.lostOnce.Do(func() { close(s.lost) }) }

func (s *hbServer) accept() {
	for {
		c, err := s.ln.Accept()
		if err != nil {
			select {
			case <-s.done: // Stop fechou o listener: normal
			default:
				s.signalLost() // listener morreu sozinho: perde
			}
			return
		}
		go s.serveConn(c)
	}
}

func (s *hbServer) serveConn(c net.Conn) {
	defer c.Close()
	// no Stop: avisa o helper a retirar o aviso e derruba a conexão
	go func() {
		<-s.done
		fmt.Fprint(c, "QUIT\n")
		c.Close()
	}()
	br := bufio.NewReader(c)
	_ = c.SetReadDeadline(time.Now().Add(s.timeout))
	line, err := br.ReadString('\n')
	if err != nil || !validHello(line, s.tok) {
		return // conexão inválida ou token errado: ignora (não é o helper)
	}
	s.signalAck() // helper comprovadamente ativo na sessão do usuário
	for {
		_ = c.SetReadDeadline(time.Now().Add(s.timeout))
		hb, err := br.ReadString('\n')
		if err != nil {
			select {
			case <-s.done: // encerrando: silêncio
			default:
				s.signalLost()
			}
			return
		}
		if hb != "HB\n" {
			s.signalLost() // linha inesperada: trata como perda
			return
		}
	}
}

func validHello(line, tok string) bool {
	const p = "HELLO "
	if len(line) < len(p)+1 || line[:len(p)] != p || line[len(line)-1] != '\n' {
		return false
	}
	got := line[len(p) : len(line)-1]
	return subtle.ConstantTimeCompare([]byte(got), []byte(tok)) == 1
}

// waitAck bloqueia até o ack, a perda, ou o timeout d (fail-closed).
func (s *hbServer) waitAck(d time.Duration) error {
	select {
	case <-s.acked:
		return nil
	case <-s.lost:
		return fmt.Errorf("indicador perdido antes de confirmar visibilidade")
	case <-time.After(d):
		return fmt.Errorf("indicador não confirmou visibilidade em %s", d)
	}
}

func (s *hbServer) Stop() {
	s.stopOnce.Do(func() {
		close(s.done)
		s.ln.Close()
	})
}
