package agent

// Ação NATIVA wipe_remoto: CRIPTO-ERASE. DESTRUTIVA E IRREVERSÍVEL.
//
// Resposta a Perda/Roubo autorizada. Destrói os protetores de chave do disco
// cifrado (BitLocker/LUKS): sem eles o volume nunca mais é desbloqueado e os
// dados ficam ilegíveis. Não sobrescreve o disco. Disco não cifrado => RECUSA
// (nada a cripto-apagar; cifre antes com forcar_criptografia). macOS: sem suporte.
//
// GATE (tudo precisa valer; qualquer falha = recusa auditada, nada executado):
//
//	a) concessão assinada válida no trust-set (handleJob/VerifyJobAny, ANTES de chegar aqui),
//	   job não repetido (seen) e ação no catálogo com params validados;
//	b) a ação do catálogo é Destructive (e Changes, Native);
//	c) job é para ESTE agente, motivo ∈ {perda, roubo} e confirmacao == "WIPE-"+agentID;
//	d) step-up: o JobPayload assinado NÃO carrega flag de step-up, então ele é
//	   imposto no CONSOLE (sem step-up válido o job nem é enfileirado) — ver
//	   internal/console/acoes.go. Aqui não há como reverificá-lo.
//
// O caminho destrutivo passa por WipeExecutor (injetável): produção usa
// realWipe; os testes usam um fake que só registra. Nenhum teste apaga nada.

import (
	"context"
	"errors"
	"fmt"
	"regexp"
	"strings"

	"github.com/eduardohenriquemoretti0-ops/fm-rmm/internal/catalog"
	"github.com/eduardohenriquemoretti0-ops/fm-rmm/internal/proto"
)

// WipeCmd é um comando do plano de wipe (sem shell: nome + argumentos).
type WipeCmd struct {
	Name string
	Args []string
}

func (c WipeCmd) String() string { return strings.TrimSpace(c.Name + " " + strings.Join(c.Args, " ")) }

// WipeExecutor separa o que é só leitura (Alvos) do que destrói (Executar).
type WipeExecutor interface {
	// Alvos descobre, SEM alterar nada, os volumes/dispositivos cifrados que
	// serão cripto-apagados. Erro se o volume do sistema não estiver cifrado.
	Alvos(ctx context.Context, goos string) ([]string, error)
	// Executar roda o plano destrutivo, na ordem, parando no primeiro erro.
	Executar(ctx context.Context, cmds []WipeCmd) (string, error)
}

var (
	motivosWipe = map[string]bool{"perda": true, "roubo": true}
	alvoWinRe   = regexp.MustCompile(`^[A-Z]:$`)
	alvoLinuxRe = regexp.MustCompile(`^/dev/[A-Za-z0-9._/-]{1,60}$`)
)

// ConfirmacaoWipe é o texto que o operador digita para o agente dado.
func ConfirmacaoWipe(agentID string) string { return "WIPE-" + agentID }

// gateWipe: itens (b) e (c) do gate. (a) já foi feito em handleJob; (d) no console.
func gateWipe(a catalog.Action, p proto.JobPayload, agentID string) error {
	switch {
	case !a.Destructive || !a.Changes || !a.Native:
		return errors.New("ação não está marcada como Destructive no catálogo")
	case agentID == "" || p.AgentID != agentID:
		return errors.New("job não é para este agente")
	case !motivosWipe[p.Params["motivo"]]:
		return errors.New("motivo ausente ou fora de perda|roubo")
	case p.Params["confirmacao"] != ConfirmacaoWipe(agentID):
		return errors.New("confirmação explícita ausente ou não confere com o agente")
	}
	return nil
}

// MontarWipe monta o plano de cripto-erase (PURA: não executa nada). Valida os
// alvos antes de virarem argumento de comando.
func MontarWipe(goos string, alvos []string) ([]WipeCmd, error) {
	if len(alvos) == 0 {
		return nil, errors.New("nenhum alvo cifrado")
	}
	var cmds []WipeCmd
	switch goos {
	case "windows":
		for _, v := range alvos {
			if !alvoWinRe.MatchString(v) {
				return nil, fmt.Errorf("alvo inválido: %q", v)
			}
			// remove TODOS os protetores (TPM, senha de recuperação, ...): a chave do volume fica irrecuperável
			cmds = append(cmds, WipeCmd{"manage-bde", []string{"-protectors", "-delete", v}})
		}
		// derruba a chave que ainda está em memória (15 s para o resultado voltar ao servidor)
		cmds = append(cmds, WipeCmd{"shutdown", []string{"/s", "/t", "15", "/f"}})
	case "linux":
		for _, d := range alvos {
			if !alvoLinuxRe.MatchString(d) || strings.Contains(d, "..") {
				return nil, fmt.Errorf("alvo inválido: %q", d)
			}
			// destrói todos os keyslots do cabeçalho LUKS
			cmds = append(cmds, WipeCmd{"cryptsetup", []string{"luksErase", "--batch-mode", d}})
		}
		cmds = append(cmds, WipeCmd{"shutdown", []string{"-P", "+1"}})
	default:
		return nil, fmt.Errorf("wipe sem suporte em %s (use MDM)", goos)
	}
	return cmds, nil
}

// wipeRemoto aplica o gate e, só então, descobre alvos e executa o plano.
func (ag *Agent) wipeRemoto(ctx context.Context, a catalog.Action, p proto.JobPayload) (string, error) {
	log := ag.Log.With("job", p.JobID, "agente", ag.state.AgentID, "emissor", p.Issuer, "motivo", p.Params["motivo"])
	if err := gateWipe(a, p, ag.state.AgentID); err != nil {
		log.Warn("wipe RECUSADO (gate)", "razao", err.Error())
		return "", errors.New("wipe recusado: " + err.Error())
	}
	if ag.wipe == nil {
		log.Warn("wipe RECUSADO: sem executor")
		return "", errors.New("wipe recusado: executor indisponível")
	}
	alvos, err := ag.wipe.Alvos(ctx, ag.goos)
	if err != nil {
		log.Warn("wipe RECUSADO: sem alvo cifrado", "razao", err.Error())
		return "", errors.New("wipe recusado (nada foi apagado): " + resumo(err.Error()))
	}
	cmds, err := MontarWipe(ag.goos, alvos)
	if err != nil {
		log.Warn("wipe RECUSADO: plano inválido", "razao", err.Error())
		return "", errors.New("wipe recusado (nada foi apagado): " + err.Error())
	}
	log.Warn("wipe EXECUTANDO (cripto-erase, irreversível)", "alvos", strings.Join(alvos, ","))
	out, err := ag.wipe.Executar(ctx, cmds)
	if err != nil {
		log.Error("wipe FALHOU no meio", "razao", err.Error())
		return "", fmt.Errorf("wipe falhou (estado parcial possível): %s", resumo(err.Error()))
	}
	log.Warn("wipe CONCLUÍDO")
	return fmt.Sprintf("wipe=cripto-erase motivo=%s alvos=%s comandos=%d %s", p.Params["motivo"], strings.Join(alvos, ","), len(cmds), resumo(out)), nil
}

// ------------------------------------------------------------ executor real

// realWipe é o ÚNICO ponto que destrói dados. Compila em todas as plataformas;
// validar em runtime só na VM.
type realWipe struct{ run cmdRunner }

func (r realWipe) Alvos(ctx context.Context, goos string) ([]string, error) {
	switch goos {
	case "windows":
		sys, _ := r.run(ctx, "powershell", "-NoProfile", "-NonInteractive", "-Command", `$env:SystemDrive`)
		sys = strings.TrimSpace(sys)
		// ConversionStatus 1 = totalmente criptografado
		out, err := r.run(ctx, "powershell", "-NoProfile", "-NonInteractive", "-Command",
			`Get-CimInstance -Namespace 'root\cimv2\Security\MicrosoftVolumeEncryption' -ClassName Win32_EncryptableVolume | Where-Object { $_.ConversionStatus -eq 1 } | ForEach-Object { $_.DriveLetter }`)
		if err != nil {
			return nil, fmt.Errorf("não consegui consultar o BitLocker: %s", resumo(out))
		}
		var alvos []string
		temSys := false
		for _, l := range strings.Fields(out) {
			l = strings.ToUpper(l)
			if alvoWinRe.MatchString(l) {
				alvos = append(alvos, l)
				temSys = temSys || strings.EqualFold(l, sys)
			}
		}
		if !temSys {
			return nil, errors.New("o volume do sistema não está totalmente cifrado: cripto-erase indisponível (nada a fazer; cifre com forcar_criptografia ou faça reset físico/MDM)")
		}
		return alvos, nil
	case "linux":
		src, _ := r.run(ctx, "findmnt", "-no", "SOURCE", "/")
		src = strings.TrimSpace(src)
		if !alvoLinuxRe.MatchString(src) {
			return nil, errors.New("não identifiquei o dispositivo raiz")
		}
		tipos, _ := r.run(ctx, "lsblk", "-rno", "TYPE", "-s", src)
		if !strings.Contains(tipos, "crypt") {
			return nil, errors.New("a raiz não está sobre LUKS: cripto-erase indisponível (nada a fazer; reinstale com LUKS ou faça reset físico)")
		}
		out, err := r.run(ctx, "lsblk", "-rnpo", "NAME,FSTYPE")
		if err != nil {
			return nil, errors.New("lsblk falhou")
		}
		var alvos []string
		for _, l := range strings.Split(out, "\n") {
			f := strings.Fields(l)
			if len(f) == 2 && f[1] == "crypto_LUKS" {
				alvos = append(alvos, f[0])
			}
		}
		if len(alvos) == 0 {
			return nil, errors.New("nenhum dispositivo LUKS encontrado")
		}
		return alvos, nil
	}
	return nil, fmt.Errorf("wipe sem suporte em %s (use MDM)", goos)
}

func (r realWipe) Executar(ctx context.Context, cmds []WipeCmd) (string, error) {
	var out strings.Builder
	for _, c := range cmds {
		o, err := r.run(ctx, c.Name, c.Args...)
		out.WriteString(c.String() + ": " + resumo(o) + "\n")
		if err != nil {
			return out.String(), fmt.Errorf("%s falhou: %s", c.String(), resumo(o))
		}
	}
	return out.String(), nil
}
