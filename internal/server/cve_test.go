package server

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/eduardohenriquemoretti0-ops/fm-rmm/internal/proto"
)

// agenteComInventario cria agente (so informado) e um job `software` finalizado.
func agenteComInventario(t *testing.T, st *Store, id, goos, saida string) {
	t.Helper()
	if _, err := st.db.Exec(`INSERT INTO agents(id, hostname, os, status, csr_pem, poll_hash, token_id, remote_addr, enrolled_at)
		VALUES (?,?,?,?,?,?,?,?,?)`, id, "h-"+id, goos, "approved", "csr", "p", "tk", "127.0.0.1", 1); err != nil {
		t.Fatal(err)
	}
	if saida == "" {
		return
	}
	res, _ := json.Marshal(proto.Result{JobID: "j-" + id, Status: "ok", Output: saida})
	if _, err := st.db.Exec(`INSERT INTO jobs(id, agent_id, action, params, signed, issuer, status, created_at, expires_at, finished_at, result)
		VALUES (?,?,?,?,?,?,?,?,?,?,?)`, "j-"+id, id, "software", "{}", "{}", "adm", "ok", 1, 2, time.Now().Unix(), string(res)); err != nil {
		t.Fatal(err)
	}
}

func novoStoreCVE(t *testing.T) *Store {
	t.Helper()
	st, err := OpenStore(filepath.Join(t.TempDir(), "t.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })
	return st
}

// osvFalso simula o OSV: openssl em Debian:12 tem vuln; o resto não.
func osvFalso(t *testing.T, batch, detalhe *atomic.Int32) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodPost && r.URL.Path == "/v1/querybatch":
			batch.Add(1)
			var q struct {
				Queries []struct {
					Package struct {
						Name      string `json:"name"`
						Ecosystem string `json:"ecosystem"`
					} `json:"package"`
					Version string `json:"version"`
				} `json:"queries"`
			}
			if err := json.NewDecoder(r.Body).Decode(&q); err != nil {
				http.Error(w, "x", 400)
				return
			}
			type v struct {
				ID string `json:"id"`
			}
			var res []map[string]any
			for _, c := range q.Queries {
				if c.Package.Name == "openssl" && c.Package.Ecosystem == "Debian:12" {
					res = append(res, map[string]any{"vulns": []v{{"DSA-0001-1"}}})
				} else {
					res = append(res, map[string]any{})
				}
			}
			_ = json.NewEncoder(w).Encode(map[string]any{"results": res})
		case r.Method == http.MethodGet && r.URL.Path == "/v1/vulns/DSA-0001-1":
			detalhe.Add(1)
			_, _ = w.Write([]byte(`{"id":"DSA-0001-1","aliases":["CVE-2099-1234"],
			 "severity":[{"type":"CVSS_V3","score":"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"}],
			 "affected":[{"package":{"name":"openssl","ecosystem":"Debian:12"},"ranges":[{"type":"ECOSYSTEM","events":[{"introduced":"0"},{"fixed":"3.0.11-1"}]}]}]}`))
		default:
			http.NotFound(w, r)
		}
	}))
}

func TestCVEVulnEncontradaECache(t *testing.T) {
	st := novoStoreCVE(t)
	agenteComInventario(t, st, "ag1", "linux", "openssl\t3.0.1-1\nbash\t5.2-1\n")
	var nb, nd atomic.Int32
	srv := osvFalso(t, &nb, &nd)
	defer srv.Close()
	e := &Engine{St: st, Base: srv.URL, EcossistemaLinux: "Debian:12", Espera: func(time.Duration) {}}

	for i := 0; i < 2; i++ { // 2ª rodada: idempotente e servida do cache
		r, err := e.Scan(context.Background(), "ag1")
		if err != nil {
			t.Fatal(err)
		}
		if len(r.Achados) != 1 || r.Resumo.Avaliados != 2 || r.Resumo.NaoAvaliados != 0 {
			t.Fatalf("rodada %d: %+v", i, r)
		}
	}
	if nb.Load() != 1 || nd.Load() != 1 {
		t.Errorf("cache não evitou chamadas: querybatch=%d detalhe=%d (quer 1/1)", nb.Load(), nd.Load())
	}
	res, err := st.ResumoVulns("ag1")
	if err != nil {
		t.Fatal(err)
	}
	if res.Total != 1 || !res.Escaneado {
		t.Fatalf("resumo: %+v", res)
	}
	a := res.Vulnerabilidades[0]
	if a.CVEID != "CVE-2099-1234" || a.Severidade != "CRITICAL" || a.Pontuacao != 9.8 ||
		a.FixedVersion != "3.0.11-1" || a.Pacote != "openssl" || a.Fonte != FonteOSV {
		t.Errorf("achado: %+v", a)
	}
	if res.PorSeveridade["CRITICAL"] != 1 {
		t.Errorf("por_severidade: %v", res.PorSeveridade)
	}
	var n int
	_ = st.db.QueryRow(`SELECT COUNT(*) FROM vulnerabilidades`).Scan(&n)
	if n != 1 {
		t.Errorf("linhas = %d, quer 1 (idempotente)", n)
	}
}

func TestCVESemVuln(t *testing.T) {
	st := novoStoreCVE(t)
	agenteComInventario(t, st, "ag1", "linux", "bash\t5.2-1\n")
	var nb, nd atomic.Int32
	srv := osvFalso(t, &nb, &nd)
	defer srv.Close()
	e := &Engine{St: st, Base: srv.URL, EcossistemaLinux: "Debian:12"}
	r, err := e.Scan(context.Background(), "ag1")
	if err != nil || len(r.Achados) != 0 || r.Resumo.Avaliados != 1 {
		t.Fatalf("%+v %v", r, err)
	}
	res, _ := st.ResumoVulns("ag1")
	if res.Total != 0 || res.Vulnerabilidades == nil || !res.Escaneado {
		t.Errorf("resumo vazio deve ter lista [] e escaneado: %+v", res)
	}
}

func TestCVENaoAvaliavelWindows(t *testing.T) {
	st := novoStoreCVE(t)
	saida := `[{"nome":"Google Chrome","versao":"120.0.1","fabricante":"Google"},{"nome":"Notepad++","versao":"8.6","fabricante":"x"},{"nome":"SemVersao","versao":null,"fabricante":null}]`
	agenteComInventario(t, st, "w1", "windows", saida)
	chamou := false
	srv := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { chamou = true }))
	defer srv.Close()
	e := &Engine{St: st, Base: srv.URL}
	r, err := e.Scan(context.Background(), "w1")
	if err != nil {
		t.Fatal(err)
	}
	if chamou {
		t.Error("não deveria consultar o OSV para app Windows (sem match inventado)")
	}
	if r.Resumo.ItensTotal != 3 || r.Resumo.Avaliados != 0 || r.Resumo.NaoAvaliados != 3 || len(r.Achados) != 0 {
		t.Errorf("%+v", r.Resumo)
	}
	if len(r.Resumo.NaoAvaliadosRisco) != 1 || r.Resumo.NaoAvaliadosRisco[0].Pacote != "Google Chrome" {
		t.Errorf("alto risco: %+v", r.Resumo.NaoAvaliadosRisco)
	}
	// Linux sem ecossistema configurado também não avalia
	agenteComInventario(t, st, "l1", "linux", "openssl\t1\n")
	r, _ = (&Engine{St: st, Base: srv.URL}).Scan(context.Background(), "l1")
	if r.Resumo.Avaliados != 0 || r.Resumo.NaoAvaliados != 1 || chamou {
		t.Errorf("linux sem ecossistema: %+v", r.Resumo)
	}
}

func TestCVEErroDeRedeFailSoft(t *testing.T) {
	st := novoStoreCVE(t)
	agenteComInventario(t, st, "ag1", "linux", "openssl\t3.0.1-1\n")
	var nb, nd atomic.Int32
	ok := osvFalso(t, &nb, &nd)
	e := &Engine{St: st, Base: ok.URL, EcossistemaLinux: "Debian:12", Espera: func(time.Duration) {}}
	if _, err := e.Scan(context.Background(), "ag1"); err != nil {
		t.Fatal(err)
	}
	ok.Close() // agora a conexão é recusada

	tentativas := 0
	ruim := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		tentativas++
		http.Error(w, "indisponível", 503)
	}))
	defer ruim.Close()
	// expira o cache para forçar a rede
	if _, err := st.db.Exec(`UPDATE osv_cache SET em=0`); err != nil {
		t.Fatal(err)
	}
	for _, base := range []string{ok.URL, ruim.URL} {
		e2 := &Engine{St: st, Base: base, EcossistemaLinux: "Debian:12", Espera: func(time.Duration) {}}
		r, err := e2.Scan(context.Background(), "ag1")
		if err != nil {
			t.Fatalf("erro de rede derrubou o scan (%s): %v", base, err)
		}
		if r.Resumo.Erro == "" || !strings.Contains(r.Resumo.Erro, "osv") {
			t.Errorf("erro não registrado: %+v", r.Resumo)
		}
	}
	if tentativas != osvTentativas {
		t.Errorf("tentativas = %d, quer %d", tentativas, osvTentativas)
	}
	res, err := st.ResumoVulns("ag1")
	if err != nil {
		t.Fatal(err)
	}
	if res.Total != 1 || res.Erro == "" {
		t.Errorf("achados antigos devem ser preservados com erro visível: %+v", res)
	}
}

func TestCVESemInventario(t *testing.T) {
	st := novoStoreCVE(t)
	agenteComInventario(t, st, "ag1", "linux", "")
	if _, err := (&Engine{St: st}).Scan(context.Background(), "ag1"); err != ErrSemInventario {
		t.Errorf("err = %v", err)
	}
	if r, _ := st.ResumoVulns("ag1"); r.Escaneado {
		t.Error("nunca escaneado deve vir escaneado=false")
	}
}

func TestCVECorrecaoRemoveAchado(t *testing.T) {
	st := novoStoreCVE(t)
	agenteComInventario(t, st, "ag1", "linux", "openssl\t3.0.1-1\n")
	var nb, nd atomic.Int32
	srv := osvFalso(t, &nb, &nd)
	defer srv.Close()
	e := &Engine{St: st, Base: srv.URL, EcossistemaLinux: "Debian:12"}
	_, _ = e.Scan(context.Background(), "ag1")
	// inventário novo (mais recente) sem o pacote vulnerável
	res, _ := json.Marshal(proto.Result{JobID: "j2", Status: "ok", Output: "bash\t5.2\n"})
	if _, err := st.db.Exec(`INSERT INTO jobs(id, agent_id, action, params, signed, issuer, status, created_at, expires_at, finished_at, result)
		VALUES ('j2','ag1','software','{}','{}','adm','ok',1,2,?,?)`, time.Now().Unix()+10, string(res)); err != nil {
		t.Fatal(err)
	}
	if _, err := e.Scan(context.Background(), "ag1"); err != nil {
		t.Fatal(err)
	}
	if r, _ := st.ResumoVulns("ag1"); r.Total != 0 {
		t.Errorf("achado corrigido deveria sumir: %+v", r)
	}
}

func TestCVSS3(t *testing.T) {
	for v, quer := range map[string]float64{
		"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H": 9.8,
		"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H": 10.0,
		"CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N": 5.5,
		"CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N": 6.1,
	} {
		if got, ok := cvss3Base(v); !ok || got != quer {
			t.Errorf("%s = %v (ok=%v), quer %v", v, got, ok, quer)
		}
	}
	if _, ok := cvss3Base("lixo"); ok {
		t.Error("vetor inválido aceito")
	}
}

func TestParseInventario(t *testing.T) {
	if got := ParseInventario("windows", `{"nome":"A","versao":"1","fabricante":"F"}`); len(got) != 1 || got[0].Nome != "A" {
		t.Errorf("objeto único: %+v", got)
	}
	if got := ParseInventario("linux", "a\t1\r\nlinha-sem-tab\nb\t2"); len(got) != 2 || got[1].Versao != "2" {
		t.Errorf("tsv: %+v", got)
	}
	if got := ParseInventario("windows", "[não é json"); len(got) != 0 {
		t.Errorf("json quebrado: %+v", got)
	}
}
