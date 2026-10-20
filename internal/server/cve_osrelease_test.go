package server

import (
	"context"
	"sync/atomic"
	"testing"
	"time"

	"encoding/json"
	"github.com/eduardohenriquemoretti0-ops/fm-rmm/internal/proto"
)

func TestEcossistemaOSV(t *testing.T) {
	casos := []struct{ id, ver, quer string }{
		{"debian", "12", "Debian:12"},
		{"debian", "11", "Debian:11"},
		{"ubuntu", "22.04", "Ubuntu:22.04"},
		{"Ubuntu", "24.04", "Ubuntu:24.04"},
		{"debian", "", ""},         // sid/testing: sem VERSION_ID
		{"arch", "1", ""},          // desconhecido
		{"fedora", "40", ""},       // rpm: não mapeado
		{"ubuntu", "22", ""},       // formato inesperado
		{"debian", "12; DROP", ""}, // fora do alfabeto
		{"", "", ""},
	}
	for _, c := range casos {
		got, ok := EcossistemaOSV(c.id, c.ver)
		if got != c.quer || ok != (c.quer != "") {
			t.Errorf("%q %q -> %q,%v; quer %q", c.id, c.ver, got, ok, c.quer)
		}
	}
}

func setHeartbeat(t *testing.T, st *Store, id string, hb proto.Heartbeat) {
	t.Helper()
	b, _ := json.Marshal(hb)
	if err := st.Seen(id, string(b), "linux"); err != nil {
		t.Fatal(err)
	}
}

// O CVE usa o ecossistema derivado do heartbeat (sem EcossistemaLinux manual);
// distro desconhecida => não avaliado; sem heartbeat/os-release => fallback manual.
func TestCVEUsaEcossistemaDoOSRelease(t *testing.T) {
	st := novoStoreCVE(t)
	inv := "openssl\t3.0.1-1\nbash\t5.2-1\n"
	agenteComInventario(t, st, "deb12", "linux", inv)
	agenteComInventario(t, st, "arch", "linux", inv)
	agenteComInventario(t, st, "velho", "linux", inv)
	setHeartbeat(t, st, "deb12", proto.Heartbeat{OS: "linux", OSID: "debian", OSVersionID: "12"})
	setHeartbeat(t, st, "arch", proto.Heartbeat{OS: "linux", OSID: "arch", OSVersionID: "1"})
	setHeartbeat(t, st, "velho", proto.Heartbeat{OS: "linux"})
	var nb, nd atomic.Int32
	srv := osvFalso(t, &nb, &nd) // só acha vuln em Debian:12
	defer srv.Close()
	e := &Engine{St: st, Base: srv.URL, Espera: func(time.Duration) {}} // sem EcossistemaLinux

	r, err := e.Scan(context.Background(), "deb12")
	if err != nil || len(r.Achados) != 1 || r.Resumo.Avaliados != 2 || r.Resumo.NaoAvaliados != 0 {
		t.Fatalf("deb12: %v %+v", err, r)
	}
	for _, id := range []string{"arch", "velho"} {
		r, err = e.Scan(context.Background(), id)
		if err != nil || r.Resumo.Avaliados != 0 || r.Resumo.NaoAvaliados != 2 || len(r.Achados) != 0 {
			t.Fatalf("%s deveria ficar não avaliado: %v %+v", id, err, r)
		}
	}
	// fallback manual continua valendo p/ quem não reporta
	e.EcossistemaLinux = "Debian:12"
	r, _ = e.Scan(context.Background(), "velho")
	if r.Resumo.Avaliados != 2 || len(r.Achados) != 1 {
		t.Fatalf("fallback manual: %+v", r)
	}
	// derivado vence o manual (arch segue não-mapeado => cai no manual, ok);
	// ubuntu reportado NÃO deve ser consultado como Debian:12
	agenteComInventario(t, st, "ubu", "linux", inv)
	setHeartbeat(t, st, "ubu", proto.Heartbeat{OS: "linux", OSID: "ubuntu", OSVersionID: "22.04"})
	r, _ = e.Scan(context.Background(), "ubu")
	if r.Resumo.Avaliados != 2 || len(r.Achados) != 0 {
		t.Fatalf("ubuntu deveria consultar Ubuntu:22.04 (sem vuln no mock): %+v", r)
	}
}
