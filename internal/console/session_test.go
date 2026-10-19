package console

import (
	"testing"
	"time"
)

func newFixedManager(abs, idle time.Duration, t0 *time.Time) *SessionManager {
	m := NewSessionManager(abs, idle)
	m.now = func() time.Time { return *t0 }
	return m
}

func TestSessaoValidaComMesmoCliente(t *testing.T) {
	now := time.Unix(1_000_000, 0)
	m := newFixedManager(15*time.Minute, 10*time.Minute, &now)
	tok, csrf, err := m.New("op-1", "thumb-A")
	if err != nil {
		t.Fatal(err)
	}
	s, err := m.Validate(tok, "thumb-A")
	if err != nil {
		t.Fatalf("validate: %v", err)
	}
	if s.OperatorID != "op-1" {
		t.Errorf("operator = %q", s.OperatorID)
	}
	if err := s.CheckCSRF(csrf); err != nil {
		t.Errorf("CSRF correto recusado: %v", err)
	}
	if s.CheckCSRF("errado") == nil {
		t.Error("CSRF errado aceito")
	}
}

func TestSessaoRecusaOutroCliente(t *testing.T) {
	now := time.Unix(1_000_000, 0)
	m := newFixedManager(15*time.Minute, 10*time.Minute, &now)
	tok, _, _ := m.New("op-1", "thumb-A")
	// token roubado, apresentado de outra maquina (thumbprint diferente)
	if _, err := m.Validate(tok, "thumb-B"); err != ErrClienteDiferente {
		t.Fatalf("esperava ErrClienteDiferente, veio %v", err)
	}
}

func TestSessaoExpiraAbsoluto(t *testing.T) {
	now := time.Unix(1_000_000, 0)
	m := newFixedManager(15*time.Minute, 10*time.Minute, &now)
	tok, _, _ := m.New("op-1", "thumb-A")
	now = now.Add(16 * time.Minute)
	if _, err := m.Validate(tok, "thumb-A"); err != ErrSessaoInvalida {
		t.Fatalf("esperava ErrSessaoInvalida (absoluto), veio %v", err)
	}
}

func TestSessaoExpiraInatividade(t *testing.T) {
	now := time.Unix(1_000_000, 0)
	m := newFixedManager(60*time.Minute, 10*time.Minute, &now)
	tok, _, _ := m.New("op-1", "thumb-A")
	// usa dentro da janela, renova lastSeen
	now = now.Add(9 * time.Minute)
	if _, err := m.Validate(tok, "thumb-A"); err != nil {
		t.Fatalf("deveria valer aos 9min: %v", err)
	}
	// agora passa da inatividade desde o ultimo uso
	now = now.Add(11 * time.Minute)
	if _, err := m.Validate(tok, "thumb-A"); err != ErrSessaoInvalida {
		t.Fatalf("esperava expirar por inatividade, veio %v", err)
	}
}

func TestSessaoRevoke(t *testing.T) {
	now := time.Unix(1_000_000, 0)
	m := newFixedManager(15*time.Minute, 10*time.Minute, &now)
	tok, _, _ := m.New("op-1", "thumb-A")
	m.Revoke(tok)
	if _, err := m.Validate(tok, "thumb-A"); err != ErrSessaoInvalida {
		t.Fatalf("sessão revogada ainda valida: %v", err)
	}
}

func TestTokenNaoFicaEmTexto(t *testing.T) {
	now := time.Unix(1_000_000, 0)
	m := newFixedManager(15*time.Minute, 10*time.Minute, &now)
	tok, _, _ := m.New("op-1", "thumb-A")
	m.mu.Lock()
	defer m.mu.Unlock()
	if _, existe := m.byHash[tok]; existe {
		t.Fatal("token guardado em claro como chave do mapa")
	}
	if _, existe := m.byHash[tokenHash(tok)]; !existe {
		t.Fatal("sessão deveria estar indexada pelo hash do token")
	}
}
