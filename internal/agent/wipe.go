package agent

// Ação NATIVA wipe_remoto: CRIPTO-ERASE REAL. DESTRUTIVA E IRREVERSÍVEL.
//
// Resposta a Perda/Roubo autorizada. Torna o volume cifrado irrecuperável
// destruindo TODO acesso à chave do volume (VMK/master key):
//
//   - Windows/BitLocker: `manage-bde -protectors -delete` NÃO é cripto-erase.
//     Quando remove o último protetor, o Windows insere uma CLEAR KEY (chave em
//     claro no metadado) e o volume continua abrindo e bootando (provado em
//     runtime na VM win10, 2026-10). Por isso o plano agora é: (1) acrescentar
//     um protetor de senha numérica ALEATÓRIA, gerada aqui e descartada (nunca
//     logada nem devolvida ao servidor); (2) remover por -id TODOS os protetores
//     que existiam antes (TPM, recovery do escrow, ...). Como sempre sobra um
//     protetor, o Windows NÃO cria clear key; o boot cai na tela de recuperação
//     e ninguém conhece a senha. (3) Verificar() confere por CIM, sem depender
//     de idioma, que sobrou exatamente 1 protetor, do tipo senha numérica; se
//     houver clear key/TPM o wipe é reportado como INEFETIVO.
//   - Linux/LUKS: `cryptsetup luksErase` sobrescreve todos os keyslots do
//     cabeçalho; sem keyslot a master key não é recuperável.
//
// Disco não cifrado => RECUSA (cifre antes com forcar_criptografia). macOS: sem suporte.
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
	"crypto/rand"
	"errors"
	"fmt"
	"math/big"
	"regexp"
	"strings"

	"github.com/eduardohenriquemoretti0-ops/fm-rmm/internal/catalog"
	"github.com/eduardohenriquemoretti0-ops/fm-rmm/internal/proto"
)

// WipeCmd é um comando do plano de wipe (sem shell: nome + argumentos).
type WipeCmd struct {
	Name string
	Args []string
	// Sigiloso: os argumentos contêm segredo (senha aleatória do wipe) e NUNCA
	// podem aparecer em String()/log/resultado.
	Sigiloso bool
}

func (c WipeCmd) String() string {
	if c.Sigiloso {
		return c.Name + " <argumentos ocultos>"
	}
	return strings.TrimSpace(c.Name + " " + strings.Join(c.Args, " "))
}

// WipeExecutor separa o que é só leitura (Alvos) do que destrói (Executar).
type WipeExecutor interface {
	// Alvos descobre, SEM alterar nada, os volumes/dispositivos cifrados que
	// serão cripto-apagados. Erro se o volume do sistema não estiver cifrado.
	Alvos(ctx context.Context, goos string) ([]string, error)
	// Protetores lista (SÓ LEITURA) os IDs dos protetores BitLocker existentes
	// em cada volume (vazio no Linux).
	Protetores(ctx context.Context, goos string, alvos []string) (map[string][]string, error)
	// Executar roda o plano destrutivo, na ordem, parando no primeiro erro.
	Executar(ctx context.Context, cmds []WipeCmd) (string, error)
	// Verificar (SÓ LEITURA) confere, depois de Executar, que o wipe foi
	// efetivo (sem clear key / sem protetor utilizável). Erro = INEFETIVO.
	Verificar(ctx context.Context, goos string, alvos []string) error
}

var (
	motivosWipe = map[string]bool{"perda": true, "roubo": true}
	alvoWinRe   = regexp.MustCompile(`^[A-Z]:$`)
	alvoLinuxRe = regexp.MustCompile(`^/dev/[A-Za-z0-9._/-]{1,60}$`)
	protIDRe    = regexp.MustCompile(`^\{[0-9A-Fa-f]{8}(-[0-9A-Fa-f]{4}){3}-[0-9A-Fa-f]{12}\}$`)

	// novaSenhaWipe gera a senha numérica de 48 dígitos (8 grupos de 6, cada
	// grupo múltiplo de 11 — formato exigido pelo BitLocker). Variável para os
	// testes serem determinísticos.
	novaSenhaWipe = gerarSenhaNumerica
)

// gerarSenhaNumerica: 8 grupos de 6 dígitos, cada um = 11*k, k em [0, 65535] (128 bits no total).
func gerarSenhaNumerica() (string, error) {
	grupos := make([]string, 8)
	for i := range grupos {
		k, err := rand.Int(rand.Reader, big.NewInt(65536))
		if err != nil {
			return "", err
		}
		grupos[i] = fmt.Sprintf("%06d", k.Int64()*11)
	}
	return strings.Join(grupos, "-"), nil
}

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

// MontarWipe monta o plano de cripto-erase (PURA, exceto o sorteio da senha:
// não executa nada). prot = IDs dos protetores BitLocker pré-existentes por
// volume (ignorado no Linux). Valida tudo antes de virar argumento de comando.
func MontarWipe(goos string, alvos []string, prot map[string][]string) ([]WipeCmd, error) {
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
			if len(prot[v]) == 0 {
				return nil, fmt.Errorf("volume %s sem protetores listados: plano recusado", v)
			}
			for _, id := range prot[v] {
				if !protIDRe.MatchString(id) {
					return nil, fmt.Errorf("id de protetor inválido: %q", id)
				}
			}
		}
		for _, v := range alvos {
			senha, err := novaSenhaWipe()
			if err != nil {
				return nil, errors.New("sem entropia para a senha do wipe")
			}
			// 1) protetor aleatório PRIMEIRO: o volume nunca fica sem protetor => sem clear key
			cmds = append(cmds, WipeCmd{"manage-bde", []string{"-protectors", "-add", v, "-RecoveryPassword", senha}, true})
			// 2) remove cada protetor antigo por id (TPM, recovery do escrow, ...)
			for _, id := range prot[v] {
				cmds = append(cmds, WipeCmd{"manage-bde", []string{"-protectors", "-delete", v, "-id", id}, false})
			}
		}
		// derruba a chave que ainda está em memória (15 s para o resultado voltar ao servidor)
		cmds = append(cmds, WipeCmd{"shutdown", []string{"/s", "/t", "15", "/f"}, false})
	case "linux":
		for _, d := range alvos {
			if !alvoLinuxRe.MatchString(d) || strings.Contains(d, "..") {
				return nil, fmt.Errorf("alvo inválido: %q", d)
			}
			// sobrescreve todos os keyslots do cabeçalho LUKS
			cmds = append(cmds, WipeCmd{"cryptsetup", []string{"luksErase", "--batch-mode", d}, false})
		}
		cmds = append(cmds, WipeCmd{"shutdown", []string{"-P", "+1"}, false})
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
	prot, err := ag.wipe.Protetores(ctx, ag.goos, alvos)
	if err != nil {
		log.Warn("wipe RECUSADO: sem lista de protetores", "razao", err.Error())
		return "", errors.New("wipe recusado (nada foi apagado): " + resumo(err.Error()))
	}
	cmds, err := MontarWipe(ag.goos, alvos, prot)
	if err != nil {
		log.Warn("wipe RECUSADO: plano inválido", "razao", err.Error())
		return "", errors.New("wipe recusado (nada foi apagado): " + err.Error())
	}
	log.Warn("wipe EXECUTANDO (cripto-erase, irreversível)", "alvos", strings.Join(alvos, ","))
	// o último comando do plano é o desligamento: só depois de VERIFICAR a efetividade
	corpo, fim := cmds[:len(cmds)-1], cmds[len(cmds)-1:]
	out, err := ag.wipe.Executar(ctx, corpo)
	if err != nil {
		log.Error("wipe FALHOU no meio", "razao", err.Error())
		return "", fmt.Errorf("wipe falhou (estado parcial possível): %s", resumo(err.Error()))
	}
	if err := ag.wipe.Verificar(ctx, ag.goos, alvos); err != nil {
		log.Error("wipe INEFETIVO (verificação falhou)", "razao", err.Error())
		return "", fmt.Errorf("wipe INEFETIVO, dados podem continuar acessíveis: %s", resumo(err.Error()))
	}
	o2, err := ag.wipe.Executar(ctx, fim)
	out += o2
	if err != nil {
		log.Error("wipe: desligamento falhou", "razao", err.Error())
		return "", fmt.Errorf("wipe efetivo mas desligamento falhou (desligue a máquina): %s", resumo(err.Error()))
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

// Protetores lista os IDs ({GUID}) dos protetores BitLocker de cada volume via
// CIM (independe de idioma). Só leitura. No Linux não há o que listar.
func (r realWipe) Protetores(ctx context.Context, goos string, alvos []string) (map[string][]string, error) {
	res := map[string][]string{}
	if goos != "windows" {
		return res, nil
	}
	for _, v := range alvos {
		if !alvoWinRe.MatchString(v) {
			return nil, fmt.Errorf("alvo inválido: %q", v)
		}
		out, err := r.run(ctx, "powershell", "-NoProfile", "-NonInteractive", "-Command",
			fmt.Sprintf(`$v = Get-CimInstance -Namespace 'root\cimv2\Security\MicrosoftVolumeEncryption' -ClassName Win32_EncryptableVolume | Where-Object { $_.DriveLetter -eq '%s' }; (Invoke-CimMethod -InputObject $v -MethodName GetKeyProtectors -Arguments @{KeyProtectorType=0}).VolumeKeyProtectorID`, v))
		if err != nil {
			return nil, fmt.Errorf("não consegui listar protetores de %s: %s", v, resumo(out))
		}
		for _, id := range strings.Fields(out) {
			if !protIDRe.MatchString(id) {
				return nil, fmt.Errorf("id de protetor inesperado: %q", id)
			}
			res[v] = append(res[v], id)
		}
	}
	return res, nil
}

var luksSlotRe = regexp.MustCompile(`(?m)^\s*\d+:\s*luks2\b|ENABLED`)

// Verificar confere a efetividade do wipe (só leitura).
func (r realWipe) Verificar(ctx context.Context, goos string, alvos []string) error {
	switch goos {
	case "windows":
		for _, v := range alvos {
			if !alvoWinRe.MatchString(v) {
				return fmt.Errorf("alvo inválido: %q", v)
			}
			// tipo 3 = senha numérica. Efetivo SÓ se existe exatamente 1 protetor no total e ele é senha numérica
			// (qualquer clear key, TPM ou outro protetor aparece na contagem total e reprova).
			out, err := r.run(ctx, "powershell", "-NoProfile", "-NonInteractive", "-Command",
				fmt.Sprintf(`$v = Get-CimInstance -Namespace 'root\cimv2\Security\MicrosoftVolumeEncryption' -ClassName Win32_EncryptableVolume | Where-Object { $_.DriveLetter -eq '%s' }; $t = @((Invoke-CimMethod -InputObject $v -MethodName GetKeyProtectors -Arguments @{KeyProtectorType=0}).VolumeKeyProtectorID).Count; $n = @((Invoke-CimMethod -InputObject $v -MethodName GetKeyProtectors -Arguments @{KeyProtectorType=3}).VolumeKeyProtectorID).Count; if ($t -eq 1 -and $n -eq 1) { 'WIPE_OK' } else { "WIPE_FALHOU total=$t senha=$n" }`, v))
			if err != nil || !strings.Contains(out, "WIPE_OK") {
				return fmt.Errorf("volume %s: %s", v, resumo(out))
			}
		}
		return nil
	case "linux":
		for _, d := range alvos {
			if !alvoLinuxRe.MatchString(d) || strings.Contains(d, "..") {
				return fmt.Errorf("alvo inválido: %q", d)
			}
			out, _ := r.run(ctx, "cryptsetup", "luksDump", d)
			if luksSlotRe.MatchString(out) {
				return fmt.Errorf("%s ainda tem keyslot ativo", d)
			}
		}
		return nil
	}
	return fmt.Errorf("wipe sem suporte em %s", goos)
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
