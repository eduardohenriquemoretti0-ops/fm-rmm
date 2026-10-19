#Requires -Version 5.1
<#
.SYNOPSIS
    Instalador do agente FM-RMM em Windows. Instala (ou atualiza) o agente como
    servico do Windows. Pensado para rodar por canal autorizado (GPO, Intune,
    ferramenta de RMM, ou execucao manual elevada). NAO e instalacao encoberta:
    cria servico nomeado (FMRMMAgent), com logs, e o agente mostra indicador em
    toda sessao remota.

.DESCRIPTION
    Baixa (ou copia) o kit, confere o SHA-256, e chama "fmrmm-agent.exe install".
    O token de inscricao so e usado na primeira instalacao; depois a maquina
    ainda precisa ser APROVADA no servidor.

.PARAMETER Kit
    URL https do kit .zip, ou caminho local do .zip.
.PARAMETER Sha256
    SHA-256 do kit (obrigatorio quando o kit vem por URL).
.PARAMETER Token
    Token de inscricao de uso unico (so na 1a instalacao).

.EXAMPLE
    .\Instalar-FMRMM.ps1 -Kit https://rmm/kit-windows-amd64.zip -Sha256 ABC... -Token fmr_...

.NOTES
    Texto sem acento de proposito (compatibilidade de codificacao em editores de RMM).
#>
param(
    [Parameter(Mandatory = $true)][string]$Kit,
    [string]$Sha256 = "",
    [string]$Token  = ""
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'                 # para no primeiro erro
$ProgressPreference    = 'SilentlyContinue'     # sem barra de progresso (mais rapido)

# ---- precisa ser Administrador (instala servico e grava em Program Files) ----
$ident = [Security.Principal.WindowsIdentity]::GetCurrent()
$princ = New-Object Security.Principal.WindowsPrincipal($ident)
if (-not $princ.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    throw "Rode como Administrador."
}

# ---- pasta de trabalho temporaria, apagada no fim ---------------------------
$work = Join-Path $env:TEMP ("fmrmm-" + [guid]::NewGuid().ToString('N'))
New-Item -ItemType Directory -Path $work -Force | Out-Null
try {
    $zip = Join-Path $work 'kit.zip'

    # ---- obtem o kit: URL https (com hash) ou arquivo local -----------------
    if ($Kit -match '^https://') {
        [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
        Invoke-WebRequest -Uri $Kit -OutFile $zip -UseBasicParsing -TimeoutSec 300
        if ($Sha256 -notmatch '^[0-9A-Fa-f]{64}$') { throw "SHA-256 obrigatorio para kit por URL." }
    }
    elseif ($Kit -match '^http://') {
        throw "HTTP sem TLS recusado; use HTTPS."
    }
    else {
        Copy-Item -LiteralPath $Kit -Destination $zip -Force     # kit local
    }

    # ---- confere a integridade antes de executar qualquer coisa -------------
    if ($Sha256 -match '^[0-9A-Fa-f]{64}$') {
        $h = (Get-FileHash -LiteralPath $zip -Algorithm SHA256).Hash
        if ($h -ne $Sha256.ToUpperInvariant()) {
            throw "SHA-256 nao confere (esperado $Sha256, veio $h)."
        }
    }

    # ---- extrai e localiza o binario ----------------------------------------
    $kitDir = Join-Path $work 'kit'
    Expand-Archive -LiteralPath $zip -DestinationPath $kitDir -Force
    $agent  = Get-ChildItem -Path $kitDir -Recurse -Filter 'fmrmm-agent.exe' | Select-Object -First 1
    $bundle = Get-ChildItem -Path $kitDir -Recurse -Filter 'bundle.json'     | Select-Object -First 1
    if (-not $agent)  { throw "fmrmm-agent.exe nao encontrado no kit." }
    if (-not $bundle) { throw "bundle.json nao encontrado no kit." }
    if (-not (Test-Path -LiteralPath (Join-Path $agent.DirectoryName 'fmrmm-indicator.exe'))) {
        throw "fmrmm-indicator.exe nao encontrado no kit (precisa ficar junto do agente)."
    }

    # ---- instala/atualiza o servico -----------------------------------------
    # O binario cria o servico FMRMMAgent (LocalSystem), a pasta de dados com
    # ACL restrita (so SYSTEM e Administradores) e inicia o servico. O token so
    # vale na 1a instalacao; em atualizacao ele e ignorado.
    $argv = @('install', '--bundle', $bundle.FullName)
    if ($Token) { $argv += @('--token', $Token) }
    & $agent.FullName @argv
    if ($LASTEXITCODE -ne 0) { throw "fmrmm-agent install saiu com codigo $LASTEXITCODE." }

    # ---- resumo --------------------------------------------------------------
    $svc = Get-Service FMRMMAgent -ErrorAction SilentlyContinue
    Write-Output ("FM-RMM instalado. Servico FMRMMAgent: {0}" -f ($svc.Status))
    Write-Output "Proximo passo: aprovar no servidor -> fmrmm-server agents approve <ID>"
}
finally {
    # ---- limpa a pasta temporaria sempre ------------------------------------
    Remove-Item -LiteralPath $work -Recurse -Force -ErrorAction SilentlyContinue
}
