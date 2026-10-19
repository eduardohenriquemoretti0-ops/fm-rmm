package agent

import (
	"bufio"
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"time"

	"github.com/eduardohenriquemoretti0-ops/fm-rmm/internal/proto"
	"github.com/eduardohenriquemoretti0-ops/fm-rmm/internal/sign"
)

// Lado do agente do acesso remoto autorizado.
//
// Regras que o código garante, não só a política:
//   - a sessão só abre com concessão ASSINADA pelo admin, para ESTE agente;
//   - o indicador visível SEMPRE acende antes de qualquer mídia; se não acender,
//     a sessão é recusada (sem indicador não há sessão);
//   - não existe caminho para captura sem indicador (não há "modo oculto").

// SessionMedia é o plano de mídia da sessão (tela/input). O transporte já está
// autenticado e cifrado (relay TLS); aqui entra a integração com o motor de
// mídia endurecido (ex.: RustDesk). Mantido atrás de interface de propósito:
// a captura de tela é platform-specific e não deve ser reescrita do zero.
type SessionMedia interface {
	// Serve roda a sessão sobre conn até o fim. mode é "view" ou "control";
	// secret é a senha de uso único da sessão (usada pelo motor rustdesk;
	// os motores que não precisam a ignoram).
	Serve(ctx context.Context, conn net.Conn, mode, secret string) error
}

// Indicator é o indicador de sessão visível no endpoint. Show deve tornar a
// sessão perceptível ao usuário; se falhar, a sessão NÃO começa. Só retorna sem
// erro depois de CONFIRMAR que o aviso está visível (ack). O canal `lost`
// emite/fecha quando o aviso deixa de estar comprovadamente visível (helper
// morreu, sem heartbeat): o chamador DEVE encerrar a sessão na hora.
type Indicator interface {
	Show(sessionID, technician, mode string) (stop func(), lost <-chan struct{}, err error)
}

func (ag *Agent) handleGrant(ctx context.Context, sg proto.SignedGrant) proto.SessionEvent {
	now := ag.now()
	refuse := func(id, why string) proto.SessionEvent {
		ag.Log.Warn("sessão recusada", "sessao", id, "motivo", why)
		return proto.SessionEvent{SessionID: id, Event: "recusada", Detail: why, At: now}
	}
	g, err := sign.VerifyGrant(ag.signer, sg, ag.state.AgentID, now)
	if err != nil {
		if errors.Is(err, sign.ErrSignature) || errors.Is(err, sign.ErrMalformed) {
			ag.Log.Warn("concessão de sessão descartada: " + err.Error())
			return proto.SessionEvent{}
		}
		return refuse(g.SessionID, err.Error())
	}
	media := ag.mediaFor(g.Engine)
	if ag.indicator == nil || media == nil {
		return refuse(g.SessionID, "mídia/indicador não configurados neste agente")
	}
	// indicador ANTES da mídia; sem ele, não há sessão
	stop, lost, err := ag.indicator.Show(g.SessionID, g.Technician, g.Mode)
	if err != nil {
		return refuse(g.SessionID, "indicador de sessão não pôde ser exibido: "+err.Error())
	}
	defer stop()
	ag.reportSession(ctx, proto.SessionEvent{SessionID: g.SessionID, Event: "indicador_on", At: ag.now()})
	ag.reportSession(ctx, proto.SessionEvent{SessionID: g.SessionID, Event: "iniciada", Detail: "técnico " + g.Technician + " · " + g.Mode, At: ag.now()})
	ag.Log.Info("sessão remota iniciada", "sessao", g.SessionID, "tecnico", g.Technician, "modo", g.Mode)

	conn, err := ag.dialRelay(ctx, g)
	if err != nil {
		return proto.SessionEvent{SessionID: g.SessionID, Event: "encerrada", Detail: "falha no relay: " + err.Error(), At: ag.now()}
	}
	defer conn.Close()
	sctx, cancel := context.WithDeadline(ctx, g.ExpiresAt)
	defer cancel()
	// amarra a vida da sessão à do indicador: se o aviso cair, encerra a mídia
	// na hora (sem janela de visualização sem aviso).
	go func() {
		select {
		case <-sctx.Done():
		case <-lost:
			ag.Log.Warn("indicador de sessão caiu — encerrando sessão", "sessao", g.SessionID)
			cancel()
		}
	}()
	if err := media.Serve(sctx, conn, g.Mode, g.MediaSecret); err != nil && !errors.Is(err, context.Canceled) && !errors.Is(err, context.DeadlineExceeded) {
		ag.Log.Warn("sessão encerrou com erro", "sessao", g.SessionID, "erro", err)
	}
	select {
	case <-lost:
		return proto.SessionEvent{SessionID: g.SessionID, Event: "encerrada", Detail: "indicador de sessão caiu (fail-closed)", At: ag.now()}
	default:
		return proto.SessionEvent{SessionID: g.SessionID, Event: "encerrada", At: ag.now()}
	}
}

// dialRelay conecta ao relay (wss/https), usando o pinning da nossa CA, e faz
// o upgrade "fm-relay". O token pareia esta ponta com a do console.
func (ag *Agent) dialRelay(ctx context.Context, g proto.RemoteGrant) (net.Conn, error) {
	u, err := url.Parse(g.RelayURL)
	if err != nil {
		return nil, err
	}
	host := u.Host
	if u.Port() == "" {
		host = net.JoinHostPort(u.Hostname(), "443")
	}
	d := &tls.Dialer{Config: &tls.Config{MinVersion: tls.VersionTLS12, RootCAs: ag.caPool, ServerName: u.Hostname()}}
	c, err := d.DialContext(ctx, "tcp", host)
	if err != nil {
		return nil, err
	}
	req := fmt.Sprintf("POST /relay HTTP/1.1\r\nHost: %s\r\nUpgrade: fm-relay\r\nConnection: Upgrade\r\nX-Session-ID: %s\r\nX-Relay-Token: %s\r\n\r\n",
		u.Hostname(), g.SessionID, g.RelayToken)
	if err := c.SetDeadline(time.Now().Add(15 * time.Second)); err != nil {
		c.Close()
		return nil, err
	}
	if _, err := c.Write([]byte(req)); err != nil {
		c.Close()
		return nil, err
	}
	br := bufio.NewReader(c)
	resp, err := http.ReadResponse(br, nil)
	if err != nil {
		c.Close()
		return nil, err
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusSwitchingProtocols {
		c.Close()
		return nil, fmt.Errorf("relay respondeu %s", resp.Status)
	}
	_ = c.SetDeadline(time.Time{})
	if br.Buffered() > 0 {
		return &bufConn{Conn: c, r: br}, nil
	}
	return c, nil
}

// bufConn preserva bytes que o bufio já leu após o upgrade.
type bufConn struct {
	net.Conn
	r *bufio.Reader
}

func (b *bufConn) Read(p []byte) (int, error) { return b.r.Read(p) }

func (ag *Agent) reportSession(ctx context.Context, ev proto.SessionEvent) {
	c, err := ag.client()
	if err != nil {
		return
	}
	if err := ag.post(ctx, c, "/v1/session/event", ev, nil); err != nil {
		ag.Log.Warn("falha ao reportar evento de sessão", "sessao", ev.SessionID, "erro", err)
	}
}
