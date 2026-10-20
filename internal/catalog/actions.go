package catalog

import "time"

// Cabeçalho comum dos scripts PowerShell: para no primeiro erro e sai em UTF-8.
const psHead = "$ErrorActionPreference = 'Stop'\n" +
	"$ProgressPreference = 'SilentlyContinue'\n" +
	"[Console]::OutputEncoding = [Text.Encoding]::UTF8\n"

// Cabeçalho comum dos scripts sh (Linux e macOS).
const shHead = "set -u\nexport LC_ALL=C\nPATH=/usr/sbin:/usr/bin:/sbin:/bin\n"

func init() {
	register(Action{
		Name: "info",
		Desc: "Identificação: nome, sistema, versão, uptime, domínio e usuário logado",
		Scripts: map[string]string{
			"windows": psHead + `
$os = Get-CimInstance Win32_OperatingSystem
$cs = Get-CimInstance Win32_ComputerSystem
[pscustomobject]@{
  hostname         = $env:COMPUTERNAME
  sistema          = $os.Caption
  versao           = $os.Version
  build            = $os.BuildNumber
  arquitetura      = $os.OSArchitecture
  ultimo_boot      = $os.LastBootUpTime.ToString('s')
  uptime_horas     = [math]::Round(((Get-Date) - $os.LastBootUpTime).TotalHours, 1)
  dominio          = $cs.Domain
  parte_de_dominio = $cs.PartOfDomain
  usuario_logado   = $cs.UserName
  fabricante       = $cs.Manufacturer
  modelo           = $cs.Model
} | ConvertTo-Json -Depth 3
`,
			"linux": shHead + `
. /etc/os-release 2>/dev/null
echo "hostname: $(hostname)"
echo "sistema: ${PRETTY_NAME:-desconhecido}"
echo "kernel: $(uname -r)"
echo "arquitetura: $(uname -m)"
echo "uptime: $(uptime -p 2>/dev/null || uptime)"
echo "usuarios_logados:"; who
`,
			"darwin": shHead + `
echo "hostname: $(scutil --get ComputerName 2>/dev/null || hostname)"
sw_vers
echo "kernel: $(uname -r)"
echo "arquitetura: $(uname -m)"
echo "uptime: $(uptime)"
echo "usuario_console: $(stat -f %Su /dev/console)"
`,
		},
	})

	register(Action{
		Name: "inventario",
		Desc: "Hardware e rede: CPU, memória, discos, placas de rede, número de série",
		Scripts: map[string]string{
			"windows": psHead + `
$cs   = Get-CimInstance Win32_ComputerSystem
$bios = Get-CimInstance Win32_BIOS
[pscustomobject]@{
  cpu = @(Get-CimInstance Win32_Processor | ForEach-Object {
    [pscustomobject]@{ nome = $_.Name.Trim(); nucleos = $_.NumberOfCores; threads = $_.NumberOfLogicalProcessors }
  })
  memoria_gb = [math]::Round($cs.TotalPhysicalMemory / 1GB, 1)
  discos = @(Get-CimInstance Win32_LogicalDisk -Filter 'DriveType=3' | ForEach-Object {
    [pscustomobject]@{ unidade = $_.DeviceID; total_gb = [math]::Round($_.Size / 1GB, 1); livre_gb = [math]::Round($_.FreeSpace / 1GB, 1) }
  })
  rede = @(Get-CimInstance Win32_NetworkAdapterConfiguration -Filter 'IPEnabled=True' | ForEach-Object {
    [pscustomobject]@{ placa = $_.Description; mac = $_.MACAddress; ip = @($_.IPAddress); gateway = @($_.DefaultIPGateway); dns = @($_.DNSServerSearchOrder) }
  })
  fabricante  = $cs.Manufacturer
  modelo      = $cs.Model
  serie       = $bios.SerialNumber
  bios_versao = $bios.SMBIOSBIOSVersion
} | ConvertTo-Json -Depth 4
`,
			"linux": shHead + `
echo "== CPU"; lscpu 2>/dev/null | grep -E '^(Model name|CPU\(s\)|Thread|Core)' || grep -m1 'model name' /proc/cpuinfo
echo "== Memoria"; free -h
echo "== Discos"; df -hT -x tmpfs -x devtmpfs -x squashfs -x overlay 2>/dev/null || df -h
echo "== Rede"; ip -brief address 2>/dev/null || ifconfig
echo "== Equipamento"
for f in sys_vendor product_name product_serial bios_version; do
  [ -r /sys/class/dmi/id/$f ] && echo "$f: $(cat /sys/class/dmi/id/$f)"
done
exit 0
`,
			"darwin": shHead + `
echo "== CPU"; sysctl -n machdep.cpu.brand_string 2>/dev/null; echo "nucleos: $(sysctl -n hw.ncpu)"
echo "== Memoria"; echo "bytes: $(sysctl -n hw.memsize)"
echo "== Discos"; df -h
echo "== Rede"; ifconfig | grep -E '^[a-z]|inet '
echo "== Equipamento"; system_profiler SPHardwareDataType | grep -E 'Model Name|Model Identifier|Serial Number|Chip|Processor'
`,
		},
	})

	register(Action{
		Name:    "hardware",
		Desc:    "Fingerprint de hardware: UUID do sistema, placa-mãe, RAM por pente (serial/part), discos (serial/WWN quando houver/tipo/saúde) e status de ativação (nunca a chave)",
		Timeout: 120 * time.Second,
		Scripts: map[string]string{
			"windows": psHead + `
$csp = Get-CimInstance Win32_ComputerSystemProduct
$bb  = Get-CimInstance Win32_BaseBoard
# ApplicationID do Windows; trazemos só o STATUS de licença, nunca a chave.
$winApp = '55c92734-d682-4d71-983e-d6ec3f16059f'
[pscustomobject]@{
  system_uuid = $csp.UUID
  placa_mae = [pscustomobject]@{ fabricante = $bb.Manufacturer; produto = $bb.Product; serie = $bb.SerialNumber }
  memoria = @(Get-CimInstance Win32_PhysicalMemory | ForEach-Object {
    [pscustomobject]@{ slot = $_.DeviceLocator; fabricante = $_.Manufacturer; part = ($_.PartNumber -replace '\s+$',''); serial = $_.SerialNumber; gb = [math]::Round($_.Capacity / 1GB, 0) } })
  discos = @(Get-CimInstance Win32_DiskDrive | ForEach-Object {
    [pscustomobject]@{ modelo = $_.Model; serial = ($_.SerialNumber -replace '\s+$',''); interface = $_.InterfaceType; tamanho_gb = [math]::Round($_.Size / 1GB, 0) } })
  discos_fisicos = @(Get-CimInstance -Namespace 'root\Microsoft\Windows\Storage' -ClassName MSFT_PhysicalDisk -ErrorAction SilentlyContinue | ForEach-Object {
    $mt = switch ([int]$_.MediaType) { 3 {'HDD'} 4 {'SSD'} 5 {'SCM'} 0 {'Unspecified'} default {"Desconhecido($($_.MediaType))"} }
    $hs = switch ([int]$_.HealthStatus) { 0 {'Healthy'} 1 {'Warning'} 2 {'Unhealthy'} 5 {'Unknown'} default {"Desconhecido($($_.HealthStatus))"} }
    # WWN: só existe quando o UniqueId é um identificador NAA/EUI (hex); senão fica nulo.
    $uid = "$($_.UniqueId)".Trim()
    $wwn = $null
    if ($uid -match '^(?:naa\.|eui\.)?([0-9A-Fa-f]{16,32})$') { $wwn = $Matches[1].ToUpperInvariant() }
    [pscustomobject]@{ nome = $_.FriendlyName; serial = ($_.SerialNumber -replace '\s+$',''); unique_id = $uid; wwn = $wwn; tipo = $mt; saude = $hs } })
  ativacao = @(Get-CimInstance SoftwareLicensingProduct -Filter "ApplicationID='$winApp' AND PartialProductKey IS NOT NULL" -ErrorAction SilentlyContinue | ForEach-Object {
    [pscustomobject]@{ nome = $_.Name; licenciado = ($_.LicenseStatus -eq 1); status_codigo = $_.LicenseStatus } })
} | ConvertTo-Json -Depth 5
`,
			"linux": shHead + `
echo "== system_uuid"; cat /sys/class/dmi/id/product_uuid 2>/dev/null || echo "indisponivel (precisa root)"
echo "== placa_mae"; for f in board_vendor board_name board_serial; do [ -r /sys/class/dmi/id/$f ] && echo "$f: $(cat /sys/class/dmi/id/$f)"; done
echo "== memoria (dmidecode -t 17)"
dmidecode -t 17 2>/dev/null | grep -E '^[[:space:]]*(Size|Locator|Serial Number|Part Number):' | grep -v 'Bank Locator' || echo "dmidecode indisponivel (precisa root)"
echo "== discos (serial/WWN)"; lsblk -d -o NAME,MODEL,SIZE,SERIAL,WWN,TYPE 2>/dev/null | grep -vi loop || echo "lsblk indisponivel"
echo "== SMART"
for d in $(lsblk -dn -o NAME,TYPE 2>/dev/null | awk '$2=="disk"{print $1}'); do
  r=$(smartctl -H /dev/$d 2>/dev/null | grep -iE 'overall-health|SMART Health' | head -1)
  echo "/dev/$d: ${r:-smartctl indisponivel}"
done
echo "== ativacao"; echo "n/a (Linux)"
exit 0
`,
			"darwin": shHead + `
echo "== system_uuid"; ioreg -rd1 -c IOPlatformExpertDevice 2>/dev/null | awk -F'"' '/IOPlatformUUID/{print $4}'
echo "== placa_mae/serie"; system_profiler SPHardwareDataType 2>/dev/null | grep -E 'Serial Number|Model Identifier'
echo "== memoria"; system_profiler SPMemoryDataType 2>/dev/null | grep -E '^ *(Size|Serial Number|Part Number|Location|Bank):'
echo "== discos"; system_profiler SPNVMeDataType SPSerialATADataType 2>/dev/null | grep -E 'Model|Serial Number|Capacity|S.M.A.R.T|TRIM'
echo "== ativacao"; echo "n/a (macOS)"
exit 0
`,
		},
	})

	register(Action{
		Name:    "software",
		Desc:    "Programas instalados (nome, versão, fabricante)",
		Timeout: 120 * time.Second,
		Scripts: map[string]string{
			"windows": psHead + `
$chaves = 'HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\*',
          'HKLM:\Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*'
@(Get-ItemProperty -Path $chaves -ErrorAction SilentlyContinue |
  Where-Object { $_.DisplayName -and -not $_.SystemComponent } |
  Sort-Object DisplayName -Unique |
  ForEach-Object { [pscustomobject]@{ nome = $_.DisplayName; versao = $_.DisplayVersion; fabricante = $_.Publisher; instalado_em = $_.InstallDate } }
) | ConvertTo-Json -Depth 3
`,
			"linux": shHead + `
if command -v dpkg-query >/dev/null 2>&1; then
  dpkg-query -W -f='${Package}\t${Version}\n'
elif command -v rpm >/dev/null 2>&1; then
  rpm -qa --qf '%{NAME}\t%{VERSION}-%{RELEASE}\n' | sort
else
  echo "gerenciador de pacotes não reconhecido"; exit 1
fi
`,
			"darwin": shHead + `
find /Applications -maxdepth 2 -name '*.app' -prune -print 2>/dev/null | sort | while IFS= read -r app; do
  v=$(defaults read "$app/Contents/Info" CFBundleShortVersionString 2>/dev/null || echo "?")
  printf '%s\t%s\n' "$(basename "$app" .app)" "$v"
done
`,
		},
	})

	register(Action{
		Name:    "saude",
		Desc:    "Saúde/estabilidade: desligamentos inesperados, BSOD/panic nos últimos 7 dias",
		Timeout: 120 * time.Second,
		Scripts: map[string]string{
			"windows": psHead + `
$desde = (Get-Date).AddDays(-7)
# 41 = desligamento inesperado; 1001 = BugCheck (BSOD); 6008 = shutdown sujo
$ev = @(Get-WinEvent -FilterHashtable @{LogName='System'; Id=41,1001,6008; StartTime=$desde} -ErrorAction SilentlyContinue |
  ForEach-Object { [pscustomobject]@{ id = $_.Id; em = $_.TimeCreated.ToString('s'); msg = (($_.Message -split "` + "`n" + `")[0]).Trim() } })
[pscustomobject]@{
  janela_dias           = 7
  eventos_instabilidade = $ev.Count
  estavel               = ($ev.Count -eq 0)
  eventos               = $ev
} | ConvertTo-Json -Depth 4
`,
			"linux": shHead + `
n=$(journalctl -k --since "7 days ago" -p warning 2>/dev/null | grep -icE 'panic|oops|BUG:|out of memory|segfault|hung task') || n=0
echo "janela_dias: 7"
echo "eventos_instabilidade: $n"
if [ "$n" -eq 0 ]; then echo "estavel: sim"; else echo "estavel: nao"; fi
echo "boots_registrados: $(journalctl --list-boots 2>/dev/null | wc -l | tr -d ' ')"
exit 0
`,
			"darwin": shHead + `
n=$(ls -1 /Library/Logs/DiagnosticReports/*.panic 2>/dev/null | wc -l | tr -d ' ')
echo "janela_dias: aprox (conta panics retidos)"
echo "panics: $n"
if [ "$n" -eq 0 ]; then echo "estavel: sim"; else echo "estavel: nao"; fi
exit 0
`,
		},
	})

	register(Action{
		Name: "servicos",
		Desc: "Serviços do sistema com estado e tipo de inicialização",
		Scripts: map[string]string{
			"windows": psHead + `
@(Get-CimInstance Win32_Service | Sort-Object Name | ForEach-Object {
  [pscustomobject]@{ nome = $_.Name; exibicao = $_.DisplayName; estado = $_.State; inicio = $_.StartMode; conta = $_.StartName }
}) | ConvertTo-Json -Depth 3
`,
			"linux":  shHead + "systemctl list-units --type=service --all --no-pager --no-legend --plain\n",
			"darwin": shHead + "launchctl list\n",
		},
	})

	register(Action{
		Name:    "atualizacoes",
		Desc:    "Atualizações instaladas recentemente e se há reinício pendente",
		Timeout: 180 * time.Second,
		Scripts: map[string]string{
			"windows": psHead + `
$pend = (Test-Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Component Based Servicing\RebootPending') -or
        (Test-Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\RebootRequired')
[pscustomobject]@{
  reinicio_pendente = $pend
  instaladas = @(Get-HotFix | Sort-Object { $_.InstalledOn } -Descending | Select-Object -First 30 | ForEach-Object {
    [pscustomobject]@{ kb = $_.HotFixID; tipo = $_.Description; em = $(if ($_.InstalledOn) { $_.InstalledOn.ToString('yyyy-MM-dd') } else { $null }) }
  })
} | ConvertTo-Json -Depth 4
`,
			"linux": shHead + `
if [ -f /var/run/reboot-required ]; then echo "reinicio_pendente: sim"; else echo "reinicio_pendente: nao"; fi
if command -v apt >/dev/null 2>&1; then
  echo "== Pendentes (apt, sem atualizar a lista)"; apt list --upgradable 2>/dev/null
  echo "== Historico recente"; grep -h ' install \| upgrade ' /var/log/dpkg.log 2>/dev/null | tail -n 30
elif command -v dnf >/dev/null 2>&1; then
  echo "== Pendentes (dnf)"; dnf -q check-update; true
fi
exit 0
`,
			"darwin": shHead + `
echo "== Pendentes"; softwareupdate -l 2>&1
echo "== Historico"; softwareupdate --history 2>/dev/null | tail -n 30
exit 0
`,
		},
	})

	register(Action{
		Name: "seguranca",
		Desc: "Postura de segurança: antivírus, firewall, criptografia de disco, administradores",
		Scripts: map[string]string{
			"windows": psHead + `
function Tenta([scriptblock]$b) { try { & $b } catch { "indisponivel: $($_.Exception.Message)" } }
[pscustomobject]@{
  defender = Tenta { $m = Get-MpComputerStatus; [pscustomobject]@{
    ativo = $m.AntivirusEnabled; tempo_real = $m.RealTimeProtectionEnabled
    assinatura = $m.AntivirusSignatureLastUpdated.ToString('s'); dias_desde_varredura_rapida = $m.QuickScanAge } }
  firewall = Tenta { @(Get-NetFirewallProfile | ForEach-Object { [pscustomobject]@{
    perfil = $_.Name; ativo = [bool]$_.Enabled; entrada = $_.DefaultInboundAction.ToString(); saida = $_.DefaultOutboundAction.ToString() } }) }
  bitlocker = Tenta { @(Get-CimInstance -Namespace 'root\cimv2\Security\MicrosoftVolumeEncryption' -ClassName Win32_EncryptableVolume |
    ForEach-Object { [pscustomobject]@{ unidade = $_.DriveLetter; protegido = ($_.ProtectionStatus -eq 1) } }) }
  secure_boot = Tenta { Confirm-SecureBootUEFI }
  uac_ativo   = Tenta { (Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System').EnableLUA -eq 1 }
  smb1_ativo  = Tenta { (Get-SmbServerConfiguration).EnableSMB1Protocol }
  rdp_ativo   = Tenta { (Get-ItemProperty 'HKLM:\System\CurrentControlSet\Control\Terminal Server').fDenyTSConnections -eq 0 }
  administradores = Tenta { @(Get-CimInstance Win32_Group -Filter "SID='S-1-5-32-544'" |
    Get-CimAssociatedInstance -ResultClassName Win32_Account | ForEach-Object { "$($_.Domain)\$($_.Name)" }) }
} | ConvertTo-Json -Depth 4
`,
			"linux": shHead + `
echo "== Firewall"; (ufw status verbose 2>/dev/null || firewall-cmd --state 2>/dev/null || echo "nenhum firewall reconhecido")
echo "== SSH"; (sshd -T 2>/dev/null | grep -E '^(port|permitrootlogin|passwordauthentication|pubkeyauthentication) ' || echo "sshd ausente")
echo "== Servicos de seguranca"
for s in fail2ban auditd apparmor unattended-upgrades; do echo "$s: $(systemctl is-active $s 2>/dev/null)"; done
echo "== Administradores (sudo/wheel)"; getent group sudo wheel 2>/dev/null
echo "== Disco criptografado"; lsblk -o NAME,TYPE,FSTYPE 2>/dev/null | grep -i crypt || echo "nenhum volume LUKS encontrado"
exit 0
`,
			"darwin": shHead + `
echo "firewall: $(/usr/libexec/ApplicationFirewall/socketfilterfw --getglobalstate 2>&1)"
echo "filevault: $(fdesetup status 2>&1)"
echo "sip: $(csrutil status 2>&1)"
echo "gatekeeper: $(spctl --status 2>&1)"
echo "administradores: $(dscl . -read /Groups/admin GroupMembership 2>&1)"
`,
		},
	})

	register(Action{
		Name: "impressoras",
		Desc: "Impressoras instaladas, portas e estado do spooler",
		Scripts: map[string]string{
			"windows": psHead + `
[pscustomobject]@{
  spooler = (Get-Service Spooler).Status.ToString()
  impressoras = @(Get-Printer | ForEach-Object { [pscustomobject]@{
    nome = $_.Name; driver = $_.DriverName; porta = $_.PortName; compartilhada = $_.Shared; estado = $_.PrinterStatus.ToString() } })
} | ConvertTo-Json -Depth 4
`,
			"linux":  shHead + "lpstat -t 2>&1 || echo \"CUPS indisponível\"\nexit 0\n",
			"darwin": shHead + "lpstat -t 2>&1\nexit 0\n",
		},
	})

	register(Action{
		Name:    "reiniciar_servico",
		Desc:    "Reinicia UM serviço de uma lista fechada (ex.: spooler de impressão)",
		Changes: true,
		Params: map[string]Param{
			"nome": {
				Desc: "serviço a reiniciar",
				Allowed: map[string][]string{
					"windows": {"Spooler", "wuauserv", "BITS", "W32Time"},
					"linux":   {"cups", "systemd-timesyncd", "chrony"},
					"darwin":  {"org.cups.cupsd"},
				},
			},
		},
		Scripts: map[string]string{
			// $P_nome é injetado pelo agente depois da validação (lista fechada).
			"windows": psHead + `
Restart-Service -Name $P_nome -Force
Start-Sleep -Seconds 2
$s = Get-Service -Name $P_nome
[pscustomobject]@{ servico = $s.Name; estado = $s.Status.ToString() } | ConvertTo-Json
`,
			"linux":  shHead + "systemctl restart \"$P_NOME\" && echo \"$P_NOME: $(systemctl is-active \"$P_NOME\")\"\n",
			"darwin": shHead + "launchctl kickstart -k \"system/$P_NOME\" && echo \"$P_NOME reiniciado\"\n",
		},
	})
}

// wake_on_lan: liga uma máquina desligada na LAN do agente-relay.
//
// Como usar: o magic packet é camada 2 e não roteia pela internet; o servidor
// não alcança o alvo. O operador escolhe um agente-relay ONLINE na MESMA LAN
// do alvo e informa o MAC do alvo (vem do inventário 3.1). O relay dispara o
// pacote (6x 0xFF + 16x MAC = 102 bytes) por UDP broadcast nas portas 9 e 7.
// WoL NÃO usa senha do endpoint: o pacote só liga a máquina (sobe até o
// login). Requer WoL habilitado na BIOS/NIC do alvo. Changes=true, então exige
// concessão assinada. Parâmetros: mac (obrigatório, AA:BB:CC:DD:EE:FF ou
// AA-BB-...) e broadcast (opcional, IPv4; default 255.255.255.255). Ambos
// validados por Pattern antes de entrar como P_MAC / P_BROADCAST.
func init() {
	const (
		macPattern = `[0-9A-Fa-f]{2}(?::[0-9A-Fa-f]{2}){5}|[0-9A-Fa-f]{2}(?:-[0-9A-Fa-f]{2}){5}`
		octeto     = `(?:25[0-5]|2[0-4][0-9]|1[0-9]{2}|[1-9]?[0-9])`
		ipPattern  = octeto + `(?:\.` + octeto + `){3}`
	)
	register(Action{
		Name:    "wake_on_lan",
		Desc:    "Wake-on-LAN: este agente (relay) envia o magic packet na LAN dele para o MAC informado (não usa senha do endpoint)",
		Changes: true,
		Timeout: 30 * time.Second,
		Params: map[string]Param{
			"mac":       {Desc: "MAC do alvo (AA:BB:CC:DD:EE:FF ou AA-BB-CC-DD-EE-FF)", Pattern: macPattern},
			"broadcast": {Desc: "IPv4 de broadcast da LAN (default 255.255.255.255)", Pattern: ipPattern, Optional: true},
		},
		Scripts: map[string]string{
			"windows": psHead + `
$mac = ($P_mac -replace '[:-]', '').ToUpper()
if ($mac -notmatch '^[0-9A-F]{12}$') { throw 'MAC invalido' }
$bc = '255.255.255.255'
if (Get-Variable -Name P_broadcast -ErrorAction SilentlyContinue) { $bc = $P_broadcast }
$m = [byte[]](0..5 | ForEach-Object { [Convert]::ToByte($mac.Substring($_ * 2, 2), 16) })
$pkt = [byte[]](@(0xFF) * 6) + [byte[]]($m * 16)
if ($pkt.Length -ne 102) { throw 'pacote com tamanho inesperado' }
$udp = New-Object System.Net.Sockets.UdpClient
try {
  $udp.EnableBroadcast = $true
  foreach ($port in 9, 7) { [void]$udp.Send($pkt, $pkt.Length, $bc, $port) }
} finally { $udp.Close() }
[pscustomobject]@{ magic_packet = $pkt.Length; mac = $mac; broadcast = $bc; portas = '9,7' } | ConvertTo-Json
`,
			"linux":  shHead + wolShell,
			"darwin": shHead + wolShell,
		},
	})
}

// wolShell serve Linux e macOS. Prefere python3 (monta o pacote de forma
// idêntica em qualquer lugar); senão wakeonlan; senão etherwake (só Linux,
// precisa de root e usa a interface padrão). Sem nenhum, falha com mensagem clara.
const wolShell = `
BC="${P_BROADCAST:-255.255.255.255}"
MAC=$(printf '%s' "$P_MAC" | tr -d ':-' | tr 'a-f' 'A-F')
case "$MAC" in
  [0-9A-F][0-9A-F][0-9A-F][0-9A-F][0-9A-F][0-9A-F][0-9A-F][0-9A-F][0-9A-F][0-9A-F][0-9A-F][0-9A-F]) ;;
  *) echo "MAC invalido" >&2; exit 2 ;;
esac
if command -v python3 >/dev/null 2>&1; then
  P_MAC_N="$MAC" P_BC_N="$BC" python3 - <<'PYEOF'
import os, socket, sys
mac = bytes.fromhex(os.environ["P_MAC_N"])
bc = os.environ["P_BC_N"]
pkt = b"\xff" * 6 + mac * 16
assert len(pkt) == 102
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
s.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
try:
    for port in (9, 7):
        s.sendto(pkt, (bc, port))
finally:
    s.close()
print("magic packet: %d bytes mac=%s broadcast=%s portas=9,7" % (len(pkt), os.environ["P_MAC_N"], bc))
PYEOF
elif command -v wakeonlan >/dev/null 2>&1; then
  wakeonlan -i "$BC" -p 9 "$MAC" && wakeonlan -i "$BC" -p 7 "$MAC" && echo "magic packet enviado (wakeonlan) mac=$MAC broadcast=$BC portas=9,7"
elif command -v etherwake >/dev/null 2>&1; then
  etherwake "$MAC" && echo "magic packet enviado (etherwake, interface padrao) mac=$MAC"
else
  echo "nenhuma ferramenta disponivel para Wake-on-LAN: instale python3, wakeonlan ou etherwake neste agente" >&2
  exit 3
fi
`

// forcar_criptografia: ação NATIVA (sem script). O agente liga/garante a
// criptografia de disco e SELA a chave de recuperação para a EscrowPub do admin;
// só o ciphertext chega ao servidor. Por isso não pode ser script genérico
// (a saída em claro viajaria e seria logada). Changes=true: exige job assinado.
// Windows: BitLocker (manage-bde). macOS: FileVault (fdesetup). Linux: apenas
// relata o estado LUKS e instrui (habilitar LUKS em disco em uso é decisão de arquitetura).
func init() {
	register(Action{
		Name:    "forcar_criptografia",
		Desc:    "Liga a criptografia de disco e entrega a chave de recuperação SELADA ao admin (escrow); a chave em claro nunca sai do agente",
		Changes: true,
		Native:  true,
		Timeout: 10 * time.Minute,
		Params: map[string]Param{
			"volume": {
				Desc:     "volume a proteger (default: volume do sistema)",
				Optional: true,
				Allowed: map[string][]string{
					"windows": {"C", "D", "E", "F"},
					"linux":   {"root"},
					"darwin":  {"root"},
				},
			},
		},
		Scripts: map[string]string{"windows": "", "linux": "", "darwin": ""},
	})

	register(Action{
		Name: "cripto_status",
		Desc: "Estado da criptografia de disco por volume (somente leitura; nunca lê chaves)",
		Scripts: map[string]string{
			"windows": psHead + `
@(Get-CimInstance -Namespace 'root\cimv2\Security\MicrosoftVolumeEncryption' -ClassName Win32_EncryptableVolume |
  ForEach-Object { [pscustomobject]@{ volume = $_.DriveLetter; protegido = ($_.ProtectionStatus -eq 1); criptografia = if ($_.ProtectionStatus -eq 1) { 'on' } else { 'off' } } }) |
  ConvertTo-Json -Depth 3
`,
			"linux": shHead + `
echo "volume,tipo,criptografia"
lsblk -rno NAME,TYPE,FSTYPE 2>/dev/null | awk '{ if ($2=="crypt" || $3=="crypto_LUKS") print $1",luks,on" }'
if ! lsblk -rno TYPE,FSTYPE 2>/dev/null | grep -Eq 'crypt|crypto_LUKS'; then echo "(nenhum),luks,off"; fi
exit 0
`,
			"darwin": shHead + `
echo "volume,tipo,criptografia"
case "$(fdesetup status 2>&1)" in
  *"FileVault is On"*) echo "/,filevault,on" ;;
  *) echo "/,filevault,off" ;;
esac
exit 0
`,
		},
	})
}

// ------------------------------------------------------- anti-furto (3d-2)
//
// Resposta a Perda/Roubo AUTORIZADA. Ambas são ações assinadas (Changes).
//
// lock_remoto: trava o dispositivo. REVERSÍVEL (o usuário volta com a senha;
// com exigir_recuperacao=sim no Windows, pede a chave de recuperação do
// BitLocker no próximo boot — a chave está no escrow do 3d-1).
//
// wipe_remoto: IRREVERSÍVEL. Cripto-erase: destrói os protetores de chave do
// disco cifrado (BitLocker/LUKS), tornando os dados ilegíveis de imediato. NÃO
// sobrescreve o disco. Disco não cifrado => o agente RECUSA (não há cripto-erase
// possível; cifre antes com forcar_criptografia ou faça reset físico/MDM).
// macOS: sem suporte (use MDM EraseDevice). Gate completo em
// internal/agent/wipe.go; aqui ficam só os parâmetros validados.

// confirmacaoWipe: "WIPE-" + agent_id (que é "ag-<hex>"). O agente confere a
// igualdade exata com o PRÓPRIO id.
const confirmacaoWipe = `WIPE-[a-z0-9-]+`

func init() {
	register(Action{
		Name:    "lock_remoto",
		Desc:    "Trava o dispositivo (sessão/tela). Reversível. No Windows, opcionalmente força a chave de recuperação do BitLocker no próximo boot",
		Changes: true,
		Params: map[string]Param{
			"exigir_recuperacao": {
				Desc:     "sim: força modo de recuperação BitLocker no próximo boot (Windows)",
				Optional: true,
				Allowed:  map[string][]string{"windows": {"sim"}},
			},
		},
		Scripts: map[string]string{
			"windows": psHead + `
# O agente roda como SYSTEM (sessão 0): LockWorkStation não alcança a sessão do
# usuário. tsdiscon desconecta a sessão interativa e a tela de bloqueio exige a senha.
$ids = @()
foreach ($l in @(quser 2>$null | Select-Object -Skip 1)) {
  $t = ($l -replace '^[>\s]+', '') -split '\s+'
  foreach ($x in $t | Select-Object -Skip 1) { if ($x -match '^\d+$') { $ids += $x; break } }
}
foreach ($i in $ids) { tsdiscon $i }
Write-Output ("sessoes_travadas=" + $ids.Count)
if ($P_exigir_recuperacao -eq 'sim') {
  $v = $env:SystemDrive
  manage-bde -forcerecovery $v
  if ($LASTEXITCODE -ne 0) { throw "manage-bde -forcerecovery falhou ($LASTEXITCODE)" }
  Write-Output "recuperacao_bitlocker=exigida_no_proximo_boot volume=$v"
}
`,
			"linux": shHead + `
if command -v loginctl >/dev/null 2>&1; then
  loginctl lock-sessions && echo "sessoes=travadas (loginctl lock-sessions)" && exit 0
fi
echo "loginctl indisponivel: nao foi possivel travar a sessao" >&2
exit 3
`,
			"darwin": shHead + `
CGS="/System/Library/CoreServices/Menu Extras/User.menu/Contents/Resources/CGSession"
if [ -x "$CGS" ]; then "$CGS" -suspend && echo "sessao=travada (CGSession -suspend)" && exit 0; fi
pmset displaysleepnow && echo "tela=apagada (exige senha se 'pedir senha imediatamente' estiver ativo)" && exit 0
echo "nao foi possivel travar" >&2
exit 3
`,
		},
	})

	register(Action{
		Name:        "wipe_remoto",
		Desc:        "DESTRUTIVO E IRREVERSÍVEL: cripto-erase do disco cifrado (remove os protetores BitLocker/LUKS). Exige confirmação WIPE-<agent_id> e motivo perda|roubo",
		Changes:     true,
		Destructive: true,
		Native:      true,
		Timeout:     10 * time.Minute,
		Params: map[string]Param{
			"motivo": {
				Desc: "caso de uso autorizado",
				Allowed: map[string][]string{
					"windows": {"perda", "roubo"},
					"linux":   {"perda", "roubo"},
				},
			},
			"confirmacao": {Desc: "WIPE-<agent_id>, digitado pelo operador", Pattern: confirmacaoWipe},
		},
		Scripts: map[string]string{"windows": "", "linux": ""}, // darwin: sem suporte (MDM)
	})
}

// instalar_pacote / desinstalar_pacote: ações NATIVAS do catálogo de software.
//
// O ÚNICO parâmetro é item_id: o id de um item da allow-list assinada pela raiz
// (sign.SoftwareCatalog). Não existe parâmetro pkg_id, nome de pacote nem
// comando: o agente resolve o item no catálogo confiável local e RECUSA se ele
// não existir. O Pattern de item_id reflete sign.ItemIDValido (minúsculas,
// dígitos, '.', '-'; nunca começa com '-') e ainda passa pelo alfabeto
// anti-injeção de Validate.
const itemIDPattern = `[a-z0-9][a-z0-9.-]{0,47}`

func init() {
	for _, n := range []struct{ nome, desc string }{
		{"instalar_pacote", "Instala um item da lista de software aprovada (catálogo assinado pelo admin); o operador escolhe o item, nunca o pacote"},
		{"desinstalar_pacote", "Remove um item da lista de software aprovada (catálogo assinado pelo admin); o operador escolhe o item, nunca o pacote"},
	} {
		register(Action{
			Name:    n.nome,
			Desc:    n.desc,
			Changes: true,
			Native:  true,
			Timeout: 30 * time.Minute,
			Params: map[string]Param{
				"item_id": {Desc: "id do item no catálogo de software aprovado", Pattern: itemIDPattern},
			},
			Scripts: map[string]string{"windows": "", "linux": ""},
		})
	}
}
