package agent

// Ação NATIVA forcar_criptografia: liga/garante a criptografia de disco e
// SELA a chave de recuperação para a EscrowPub do admin (nacl SealAnonymous).
//
// Invariantes (testadas):
//   - a chave em claro existe só em memória deste fluxo: nunca vai ao Output,
//     ao Error, ao log nem ao servidor — só o blob selado e metadados;
//   - sem EscrowPub válida no bundle a ação falha ANTES de mexer no disco;
//   - mensagens de erro passam por escrow.Redigir.

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"

	"github.com/eduardohenriquemoretti0-ops/fm-rmm/internal/catalog"
	"github.com/eduardohenriquemoretti0-ops/fm-rmm/internal/escrow"
	"github.com/eduardohenriquemoretti0-ops/fm-rmm/internal/proto"
)

// cmdRunner executa um comando e devolve stdout+stderr combinados. A saída pode
// conter a chave de recuperação: quem chama NUNCA a repassa ao Output/log.
type cmdRunner func(ctx context.Context, name string, args ...string) (string, error)

func runCmd(ctx context.Context, name string, args ...string) (string, error) {
	out, err := exec.CommandContext(ctx, name, args...).CombinedOutput()
	return string(out), err
}

const (
	arqFileVaultPlist = "filevault-defer.plist"
	metodoBitLocker   = "bitlocker"
	metodoFileVault   = "filevault"
)

// runNative despacha as ações nativas pelo nome.
func (ag *Agent) runNative(ctx context.Context, a catalog.Action, p proto.JobPayload) (string, int, *proto.EscrowRecord, error) {
	switch a.Name {
	case "forcar_criptografia":
		out, rec, err := ag.forcarCriptografia(ctx, p.Params["volume"])
		if err != nil {
			return "", 1, nil, errors.New(escrow.Redigir(err.Error()))
		}
		return out, 0, rec, nil
	case "instalar_pacote", "desinstalar_pacote":
		out, err := ag.softwareAcao(ctx, a, p)
		if err != nil {
			return "", 1, nil, err
		}
		return out, 0, nil, nil
	case "rodar_script":
		out, err := ag.scriptAcao(ctx, a, p)
		if err != nil {
			return "", 1, nil, err
		}
		return out, 0, nil, nil
	case "wipe_remoto":
		out, err := ag.wipeRemoto(ctx, a, p)
		if err != nil {
			return "", 1, nil, err
		}
		return out, 0, nil, nil
	}
	return "", -1, nil, errors.New("ação nativa sem implementação: " + a.Name)
}

// chaveColhida é o resultado de um fluxo de SO: a chave existe só aqui.
type chaveColhida struct {
	volume, metodo, chave, nota string
}

func (ag *Agent) forcarCriptografia(ctx context.Context, volParam string) (string, *proto.EscrowRecord, error) {
	// 1. falha cedo, ANTES de tocar no disco, se não há para quem selar
	if ag.bundle.EscrowPub == "" {
		return "", nil, errors.New("o bundle deste agente não tem EscrowPub: reemita o bundle com a chave de escrow do admin")
	}
	if _, err := escrow.DecodePub(ag.bundle.EscrowPub); err != nil {
		return "", nil, err
	}
	// 2. fluxo específico do SO
	var c chaveColhida
	var err error
	switch ag.goos {
	case "windows":
		c, err = ag.bitlocker(ctx, volParam)
	case "darwin":
		c, err = ag.filevault(ctx)
	case "linux":
		return "", nil, ag.linuxRelato(ctx)
	default:
		return "", nil, fmt.Errorf("criptografia de disco não suportada em %s", ag.goos)
	}
	if err != nil {
		return "", nil, err
	}
	if c.chave == "" { // habilitação agendada, chave ainda não existe
		return c.nota, nil, nil
	}
	// 3. sela e descarta a chave em claro
	blob, err := escrow.Seal(ag.bundle.EscrowPub, escrow.Segredo{AgentID: ag.state.AgentID, Volume: c.volume, Metodo: c.metodo, Chave: c.chave})
	c.chave = ""
	if err != nil {
		return "", nil, fmt.Errorf("falha ao selar a chave de recuperação: %w", err)
	}
	out := fmt.Sprintf("volume=%s metodo=%s escrow=selado chave_de_recuperacao=entregue_somente_selada %s", c.volume, c.metodo, c.nota)
	return strings.TrimSpace(out), &proto.EscrowRecord{Volume: c.volume, Metodo: c.metodo, Blob: blob}, nil
}

// ------------------------------------------------------------------ Windows

var driveRe = regexp.MustCompile(`^[A-Z]$`)

// bitlocker: garante protetor de senha de recuperação + TPM e liga a proteção.
// Idempotente: se já existe senha de recuperação, reaproveita (e sela a mesma).
func (ag *Agent) bitlocker(ctx context.Context, volParam string) (chaveColhida, error) {
	letra := strings.ToUpper(volParam)
	if letra == "" {
		letra = "C"
	}
	if !driveRe.MatchString(letra) {
		return chaveColhida{}, errors.New("volume inválido")
	}
	vol := letra + ":"
	c := chaveColhida{volume: vol, metodo: metodoBitLocker}

	// senha de recuperação existente?
	out, _ := ag.run(ctx, "manage-bde", "-protectors", "-get", vol, "-Type", "RecoveryPassword")
	c.chave = escrow.ExtrairChaveBitLocker(out)
	if c.chave == "" {
		out, err := ag.run(ctx, "manage-bde", "-protectors", "-add", vol, "-RecoveryPassword")
		if err != nil {
			return chaveColhida{}, fmt.Errorf("manage-bde -protectors -add falhou: %s", resumo(out))
		}
		if c.chave = escrow.ExtrairChaveBitLocker(out); c.chave == "" {
			out, _ = ag.run(ctx, "manage-bde", "-protectors", "-get", vol, "-Type", "RecoveryPassword")
			c.chave = escrow.ExtrairChaveBitLocker(out)
		}
		if c.chave == "" {
			return chaveColhida{}, errors.New("não consegui obter a senha de recuperação do BitLocker")
		}
	}
	// protetor TPM (melhor esforço: pode já existir ou a máquina não ter TPM)
	_, _ = ag.run(ctx, "manage-bde", "-protectors", "-add", vol, "-TPM")

	// liga a proteção só se ainda não estiver ligada
	prot, conv, okWMI := ag.estadoBitLocker(ctx, vol)
	if okWMI && prot == 1 && conv == 1 {
		c.nota = "protecao=ja_ativa"
		return c, nil
	}
	onOut, err := ag.run(ctx, "manage-bde", "-on", vol, "-UsedSpaceOnly")
	if err != nil {
		// pode estar criptografado e apenas suspenso: tenta retomar
		if out2, err2 := ag.run(ctx, "manage-bde", "-protectors", "-enable", vol); err2 != nil {
			return chaveColhida{}, fmt.Errorf("manage-bde -on falhou: %s | -protectors -enable: %s", resumo(onOut), resumo(out2))
		}
		onOut = ""
	}
	// NÃO presume sucesso: relê o estado real (WMI) depois do comando.
	prot, conv, okWMI = ag.estadoBitLocker(ctx, vol)
	if !okWMI {
		c.nota = "protecao=desconhecida (estado WMI ilegível após manage-bde -on)"
		return c, nil
	}
	c.nota = EstadoBitLocker(prot, conv, pedeReboot(onOut))
	return c, nil
}

// estadoBitLocker lê ProtectionStatus e ConversionStatus (WMI). ok=false se
// a leitura ou o parse falhar.
func (ag *Agent) estadoBitLocker(ctx context.Context, vol string) (prot, conv int, ok bool) {
	out, err := ag.run(ctx, "powershell", "-NoProfile", "-NonInteractive", "-Command",
		fmt.Sprintf(`$v = Get-CimInstance -Namespace 'root\cimv2\Security\MicrosoftVolumeEncryption' -ClassName Win32_EncryptableVolume -Filter "DriveLetter='%s'"; "$($v.ProtectionStatus);$($v.ConversionStatus)"`, vol))
	if err != nil {
		return 0, 0, false
	}
	return parseEstadoBitLocker(out)
}

func parseEstadoBitLocker(out string) (prot, conv int, ok bool) {
	f := strings.Split(strings.TrimSpace(out), ";")
	if len(f) != 2 {
		return 0, 0, false
	}
	var err1, err2 error
	prot, err1 = strconv.Atoi(strings.TrimSpace(f[0]))
	conv, err2 = strconv.Atoi(strings.TrimSpace(f[1]))
	return prot, conv, err1 == nil && err2 == nil
}

// pedeReboot: a saída do manage-bde -on indica reinício necessário (teste de
// hardware do TPM), em inglês ou português.
func pedeReboot(out string) bool {
	t := strings.ToLower(out)
	return strings.Contains(t, "restart") || strings.Contains(t, "reinici") || strings.Contains(t, "reboot")
}

// EstadoBitLocker mapeia Win32_EncryptableVolume (ProtectionStatus:
// 0 off, 1 on, 2 desconhecido; ConversionStatus: 0 decifrado, 1 cifrado,
// 2 cifrando, 3 decifrando, 4 cifra pausada, 5 decifra pausada) para a nota.
// "ligada" SÓ com ProtectionStatus=1 e a conversão realmente iniciada/concluída.
func EstadoBitLocker(prot, conv int, rebootPedido bool) string {
	switch {
	case prot == 1 && conv == 1:
		return "protecao=ligada conversao=concluida"
	case prot == 1 && (conv == 2 || conv == 4):
		return "protecao=ligada conversao=em_andamento"
	case prot == 1 && conv == 0:
		// proteção "on" sem nada cifrado: ainda não começou
		return "protecao=pendente_reboot conversao=aguardando_reboot"
	case prot == 0 && conv == 0 && rebootPedido:
		return "protecao=pendente_reboot conversao=aguardando_reboot"
	case prot == 0 && conv == 0:
		return "protecao=desligada conversao=nao_iniciada"
	case prot == 0 && (conv == 1 || conv == 2 || conv == 4):
		return "protecao=suspensa conversao=" + map[int]string{1: "concluida", 2: "em_andamento", 4: "pausada"}[conv]
	case conv == 3 || conv == 5:
		return "protecao=desligada conversao=decifrando"
	}
	return fmt.Sprintf("protecao=desconhecida protection_status=%d conversion_status=%d", prot, conv)
}

// resumo limita e higieniza saída de ferramenta para mensagens de erro.
func resumo(s string) string {
	s = strings.Join(strings.Fields(escrow.Redigir(s)), " ")
	if len(s) > 300 {
		s = s[:300] + "..."
	}
	return s
}

// ------------------------------------------------------------------- macOS

var fvKeyRe = regexp.MustCompile(`(?s)<key>RecoveryKey</key>\s*<string>([^<]+)</string>`)

// filevault: sem credencial de usuário não há como obter a chave de um
// FileVault já ligado. Se desligado, agenda a habilitação (-defer) e a chave
// (gravada pelo fdesetup em plist 0600 do agente) é selada quando existir.
func (ag *Agent) filevault(ctx context.Context) (chaveColhida, error) {
	c := chaveColhida{volume: "/", metodo: metodoFileVault}
	plist := filepath.Join(ag.Dir, arqFileVaultPlist)
	if b, err := os.ReadFile(plist); err == nil {
		if m := fvKeyRe.FindSubmatch(b); m != nil {
			c.chave = strings.TrimSpace(string(m[1]))
			_ = os.WriteFile(plist, make([]byte, len(b)), 0o600) // sobrescreve antes de apagar
			_ = os.Remove(plist)
			c.nota = "protecao=filevault_ligado"
			return c, nil
		}
	}
	st, _ := ag.run(ctx, "fdesetup", "status")
	if strings.Contains(st, "FileVault is On") {
		return c, errors.New("FileVault já está ligado e a chave de recuperação não é recuperável sem credencial de usuário; " +
			"para fazer escrow, o admin deve rotacionar localmente com `fdesetup changerecovery -personal` (decisão manual)")
	}
	if out, err := ag.run(ctx, "fdesetup", "enable", "-defer", plist, "-forceatlogin", "0"); err != nil {
		return c, fmt.Errorf("fdesetup enable -defer falhou: %s", resumo(out))
	}
	_ = os.Chmod(plist, 0o600)
	if b, err := os.ReadFile(plist); err == nil {
		if m := fvKeyRe.FindSubmatch(b); m != nil {
			c.chave = strings.TrimSpace(string(m[1]))
			_ = os.WriteFile(plist, make([]byte, len(b)), 0o600)
			_ = os.Remove(plist)
			c.nota = "protecao=filevault_agendado"
			return c, nil
		}
	}
	c.nota = "FileVault agendado para o próximo login do usuário; rode forcar_criptografia de novo depois para selar a chave"
	return c, nil
}

// -------------------------------------------------------------------- Linux

// linuxRelato: habilitar LUKS em disco em uso é reparticionar/recriptografar
// (destrutivo, decisão de arquitetura), então o agente só RELATA e instrui.
func (ag *Agent) linuxRelato(ctx context.Context) error {
	out, _ := ag.run(ctx, "lsblk", "-o", "NAME,TYPE,FSTYPE,MOUNTPOINT")
	luks := strings.Contains(out, "crypt") || strings.Contains(out, "crypto_LUKS")
	estado := "nenhum volume LUKS encontrado"
	if luks {
		estado = "LUKS presente"
	}
	return fmt.Errorf("linux: o agente não habilita LUKS (operação destrutiva/manual) nem extrai chave. Estado: %s. "+
		"Instrução: criptografe na instalação ou use `cryptsetup reencrypt` com janela de manutenção e faça o escrow da passphrase "+
		"(`cryptsetup luksAddKey`) manualmente; use cripto_status para acompanhar", estado)
}
