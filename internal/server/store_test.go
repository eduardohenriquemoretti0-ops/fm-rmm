package server

import (
	"context"
	"path/filepath"
	"testing"
	"time"

	"github.com/eduardohenriquemoretti0-ops/fm-rmm/internal/audit"
	"github.com/eduardohenriquemoretti0-ops/fm-rmm/internal/proto"
)

func TestAuditChain(t *testing.T) {
	st, err := OpenStore(filepath.Join(t.TempDir(), "t.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	for i := 0; i < 5; i++ {
		if err := st.Audit("teste", "eu", map[string]any{"i": i, "texto": "ação <com> acento é"}); err != nil {
			t.Fatal(err)
		}
	}
	e, err := st.AuditEntries()
	if err != nil {
		t.Fatal(err)
	}
	if err := audit.Verify(e); err != nil {
		t.Fatalf("cadeia íntegra recusada: %v", err)
	}
	if _, err := st.db.Exec(`UPDATE audit SET actor='hacker' WHERE seq=3`); err == nil {
		t.Fatal("UPDATE na auditoria deveria ser bloqueado")
	}
	if _, err := st.db.Exec(`DELETE FROM audit WHERE seq=5`); err == nil {
		t.Fatal("DELETE na auditoria deveria ser bloqueado")
	}
	// atacante com acesso ao arquivo derruba o gatilho e altera: a cadeia acusa
	if _, err := st.db.Exec(`DROP TRIGGER audit_sem_update`); err != nil {
		t.Fatal(err)
	}
	if _, err := st.db.Exec(`UPDATE audit SET actor='hacker' WHERE seq=3`); err != nil {
		t.Fatal(err)
	}
	e, _ = st.AuditEntries()
	if err := audit.Verify(e); err == nil {
		t.Fatal("adulteração não detectada")
	}
}

func TestTokenUsoUnico(t *testing.T) {
	st, err := OpenStore(filepath.Join(t.TempDir(), "t.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	_, tok, err := st.NewToken("lote", 1, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := st.Enroll(tok, "pc1", "windows", "csr", "1.2.3.4"); err != nil {
		t.Fatal(err)
	}
	if _, _, err := st.Enroll(tok, "pc2", "windows", "csr", "1.2.3.4"); err != ErrToken {
		t.Fatalf("token de uso único aceito duas vezes: %v", err)
	}
	_, old, _ := st.NewToken("vencido", 5, -time.Second)
	if _, _, err := st.Enroll(old, "pc3", "windows", "csr", "1.2.3.4"); err != ErrToken {
		t.Fatalf("token vencido aceito: %v", err)
	}
	if _, _, err := st.Enroll("fmr_inventado", "pc4", "windows", "csr", "1.2.3.4"); err != ErrToken {
		t.Fatalf("token inventado aceito: %v", err)
	}
}

func TestAgentOnline(t *testing.T) {
	now := time.Unix(1_000_000, 0)
	cases := []struct {
		name     string
		lastSeen int64
		want     bool
	}{
		{"nunca viu", 0, false},
		{"agora", now.Unix(), true},
		{"1 intervalo atrás", now.Add(-60 * time.Second).Unix(), true},
		{"2x intervalo (limite)", now.Add(-120 * time.Second).Unix(), true},
		{"velho demais", now.Add(-121 * time.Second).Unix(), false},
	}
	for _, c := range cases {
		a := Agent{LastSeen: c.lastSeen}
		if got := a.Online(60*time.Second, now); got != c.want {
			t.Errorf("%s: Online=%v, quer %v", c.name, got, c.want)
		}
	}
}

// N1: job 'delivered' sem resultado, vencido (expires_at + ClockSkew), vira
// 'stale'; o ainda dentro do prazo e o já finalizado ficam como estão.
func TestJobDeliveredVencidoViraStale(t *testing.T) {
	st, err := OpenStore(filepath.Join(t.TempDir(), "t.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	agora := time.Now()
	_, tok, err := st.NewToken("lote", 1, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	agID, _, err := st.Enroll(tok, "pc1", "windows", "csr", "1.2.3.4")
	if err != nil {
		t.Fatal(err)
	}
	add := func(id string, expira time.Time, status string) {
		t.Helper()
		if err := st.AddJob(Job{ID: id, AgentID: agID, Action: "info", Params: "{}", Signed: "{}", Issuer: "x", ExpiresAt: expira.Unix()}); err != nil {
			t.Fatal(err)
		}
		if _, err := st.db.Exec(`UPDATE jobs SET status=? WHERE id=?`, status, id); err != nil {
			t.Fatal(err)
		}
	}
	add("vencido", agora.Add(-proto.ClockSkew-time.Minute), "delivered")
	add("na-tolerancia", agora.Add(-time.Minute), "delivered")
	add("no-prazo", agora.Add(time.Hour), "delivered")
	add("ja-ok", agora.Add(-time.Hour), "ok")

	j, err := st.Job("vencido") // a consulta varre
	if err != nil {
		t.Fatal(err)
	}
	if j.Status != "stale" {
		t.Fatalf("vencido: status = %q, quer stale", j.Status)
	}
	for id, quer := range map[string]string{"na-tolerancia": "delivered", "no-prazo": "delivered", "ja-ok": "ok"} {
		g, _ := st.Job(id)
		if g.Status != quer {
			t.Errorf("%s: status = %q, quer %q", id, g.Status, quer)
		}
	}
	// resultado tardio de job stale não é aceito (FinishJob exige 'delivered')
	if err := st.FinishJob(agID, "vencido", "ok", "r"); err == nil {
		t.Error("FinishJob em job stale deveria falhar")
	}
	// a entrega (TakeQueued) também varre
	add("vencido2", agora.Add(-proto.ClockSkew-time.Minute), "delivered")
	if _, err := st.TakeQueued(context.Background(), agID); err != nil {
		t.Fatal(err)
	}
	if _, err := st.db.Exec(`SELECT 1`); err != nil {
		t.Fatal(err)
	}
	var s2 string
	_ = st.db.QueryRow(`SELECT status FROM jobs WHERE id='vencido2'`).Scan(&s2)
	if s2 != "stale" {
		t.Errorf("TakeQueued não varreu: %q", s2)
	}
}
