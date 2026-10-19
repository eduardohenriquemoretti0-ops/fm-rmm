package server

import (
	"path/filepath"
	"testing"
	"time"

	"github.com/eduardohenriquemoretti0-ops/fm-rmm/internal/audit"
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
