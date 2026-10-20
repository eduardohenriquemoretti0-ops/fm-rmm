package agent

import (
	"context"
	"fmt"
	"strings"
	"testing"
)

// winget vai para o executor do contexto do usuário; apt (root) não.
func TestWingetVaiParaContextoDoUsuario_AptNao(t *testing.T) {
	ctx := context.Background()

	ag, sys, raiz, rel := agenteSoft(t, "windows")
	usr := &softFake{}
	ag.wingetUserRun = usr.run
	res := ag.handleJob(ctx, assina(t, raiz, jobSW(ag, rel, "instalar_pacote", map[string]string{"item_id": "firefox"})))
	if res.Status != "ok" {
		t.Fatalf("%+v", res)
	}
	if len(usr.registrado) != 1 || !strings.Contains(usr.registrado[0], "install --id Mozilla.Firefox") {
		t.Fatalf("winget não foi ao contexto do usuário: %v", usr.registrado)
	}
	if len(sys.registrado) != 0 {
		t.Fatalf("winget vazou para o executor SYSTEM: %v", sys.registrado)
	}

	agL, sysL, raizL, relL := agenteSoft(t, "linux")
	usrL := &softFake{}
	agL.wingetUserRun = usrL.run
	res = agL.handleJob(ctx, assina(t, raizL, jobSW(agL, relL, "instalar_pacote", map[string]string{"item_id": "htop"})))
	if res.Status != "ok" {
		t.Fatalf("%+v", res)
	}
	if len(usrL.registrado) != 0 || len(sysL.registrado) != 1 {
		t.Fatalf("apt deve rodar no executor normal: user=%v sys=%v", usrL.registrado, sysL.registrado)
	}
}

// Sem usuário logado: recusa clara, sem fallback para o executor SYSTEM.
func TestWingetSemUsuarioLogadoRecusa(t *testing.T) {
	ag, sys, raiz, rel := agenteSoft(t, "windows")
	ag.wingetUserRun = func(context.Context, string, ...string) (string, error) {
		return "", fmt.Errorf("%w (WTSQueryUserToken: x)", errSemUsuarioLogado)
	}
	res := ag.handleJob(context.Background(), assina(t, raiz, jobSW(ag, rel, "instalar_pacote", map[string]string{"item_id": "firefox"})))
	if res.Status == "ok" || !strings.Contains(fmt.Sprint(res), "winget exige um usuário logado") {
		t.Fatalf("esperava recusa clara: %+v", res)
	}
	if len(sys.registrado) != 0 {
		t.Fatalf("caiu para SYSTEM: %v", sys.registrado)
	}
}
