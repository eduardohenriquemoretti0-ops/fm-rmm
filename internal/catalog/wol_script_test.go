package catalog

import (
	"net"
	"os/exec"
	"testing"
	"time"
)

// Monta o pacote pelo script Linux real e confere 102 bytes (6xFF + 16xMAC)
// numa escuta em loopback. As portas 9 e 7 são privilegiadas: sem permissão
// para escutá-las o teste é pulado (rode como root/unshare -rn para exercitar).
func TestWoLScriptLinuxPacote(t *testing.T) {
	if _, err := exec.LookPath("python3"); err != nil {
		t.Skip("sem python3")
	}
	var conns []*net.UDPConn
	for _, p := range []int{9, 7} {
		c, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: p})
		if err != nil {
			t.Skipf("não consigo escutar UDP %d: %v", p, err)
		}
		defer c.Close()
		conns = append(conns, c)
	}
	a, _ := Get("wake_on_lan")
	cmd := exec.Command("/bin/sh", "-c", a.Scripts["linux"])
	cmd.Env = []string{"P_MAC=aa-bb-cc-dd-ee-0f", "P_BROADCAST=127.0.0.1"}
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("script falhou: %v\n%s", err, out)
	}
	mac := []byte{0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0x0F}
	for i, c := range conns {
		buf := make([]byte, 512)
		c.SetReadDeadline(time.Now().Add(3 * time.Second))
		n, _, err := c.ReadFromUDP(buf)
		if err != nil {
			t.Fatalf("porta %d: %v", []int{9, 7}[i], err)
		}
		if n != 102 {
			t.Fatalf("porta %d: %d bytes, esperado 102", []int{9, 7}[i], n)
		}
		for j := 0; j < 6; j++ {
			if buf[j] != 0xFF {
				t.Fatalf("cabeçalho errado no byte %d", j)
			}
		}
		for r := 0; r < 16; r++ {
			if string(buf[6+r*6:12+r*6]) != string(mac) {
				t.Fatalf("repetição %d do MAC errada", r)
			}
		}
	}
}
