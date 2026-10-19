package agent

import (
	"bufio"
	"fmt"
	"net"
	"testing"
	"time"
)

// cliente de teste faz o papel do helper: HELLO + HB periódico.
func dialHelper(t *testing.T, s *hbServer, token string) net.Conn {
	t.Helper()
	c, err := net.Dial("tcp", s.addr())
	if err != nil {
		t.Fatal(err)
	}
	fmt.Fprintf(c, "HELLO %s\n", token)
	return c
}

func TestHBAckEHeartbeat(t *testing.T) {
	s, err := newHBServer(200 * time.Millisecond)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Stop()
	c := dialHelper(t, s, s.token())
	defer c.Close()

	if err := s.waitAck(time.Second); err != nil {
		t.Fatalf("ack: %v", err)
	}
	// manda HB por um tempo; Lost não pode disparar
	stop := make(chan struct{})
	go func() {
		tk := time.NewTicker(50 * time.Millisecond)
		defer tk.Stop()
		for {
			select {
			case <-stop:
				return
			case <-tk.C:
				fmt.Fprint(c, "HB\n")
			}
		}
	}()
	select {
	case <-s.Lost():
		t.Fatal("Lost disparou com heartbeat ativo")
	case <-time.After(500 * time.Millisecond):
	}
	close(stop)
}

func TestHBTokenErradoNaoConfirma(t *testing.T) {
	s, err := newHBServer(200 * time.Millisecond)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Stop()
	c := dialHelper(t, s, "token-errado")
	defer c.Close()
	if err := s.waitAck(300 * time.Millisecond); err == nil {
		t.Fatal("não devia confirmar visibilidade com token errado")
	}
}

func TestHBPerdeSemHeartbeat(t *testing.T) {
	s, err := newHBServer(150 * time.Millisecond)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Stop()
	c := dialHelper(t, s, s.token())
	defer c.Close()
	if err := s.waitAck(time.Second); err != nil {
		t.Fatalf("ack: %v", err)
	}
	// para de mandar HB: Lost tem de disparar dentro de ~timeout
	select {
	case <-s.Lost():
	case <-time.After(2 * time.Second):
		t.Fatal("Lost não disparou após parar o heartbeat")
	}
}

func TestHBStopMandaQuit(t *testing.T) {
	s, err := newHBServer(time.Second)
	if err != nil {
		t.Fatal(err)
	}
	c := dialHelper(t, s, s.token())
	defer c.Close()
	if err := s.waitAck(time.Second); err != nil {
		t.Fatalf("ack: %v", err)
	}
	s.Stop()
	br := bufio.NewReader(c)
	_ = c.SetReadDeadline(time.Now().Add(time.Second))
	line, err := br.ReadString('\n')
	if err != nil || line != "QUIT\n" {
		t.Fatalf("esperava QUIT no Stop, veio %q err=%v", line, err)
	}
}
