//go:build windows

package agent

import (
	"errors"
	"os"
	"os/exec"
	"path/filepath"

	"golang.org/x/sys/windows"
)

// captureScreen no Windows: usa .NET (System.Drawing) via PowerShell para
// fotografar a tela. ATENÇÃO: um serviço em Session 0 (SYSTEM) NÃO enxerga a
// área de trabalho interativa do usuário — a captura sai preta ou falha. A
// captura real da sessão do usuário exige um helper rodando na sessão dela
// (é o que motores como o RustDesk fazem). Aqui detectamos Session 0 e
// falhamos com motivo claro, em vez de enviar uma tela preta.
func captureScreen() ([]byte, error) {
	if inSession0() {
		return nil, errors.New("agente em Session 0 (SYSTEM): captura da área de trabalho do usuário exige helper na sessão interativa (integrar motor de mídia)")
	}
	tmp := filepath.Join(os.TempDir(), "fmrmm-frame.png")
	defer os.Remove(tmp)
	ps := `
$ErrorActionPreference='Stop'
Add-Type -AssemblyName System.Windows.Forms,System.Drawing
$b = [System.Windows.Forms.SystemInformation]::VirtualScreen
$bmp = New-Object System.Drawing.Bitmap $b.Width, $b.Height
$g = [System.Drawing.Graphics]::FromImage($bmp)
$g.CopyFromScreen($b.Left, $b.Top, 0, 0, $bmp.Size)
$bmp.Save('` + tmp + `', [System.Drawing.Imaging.ImageFormat]::Png)
`
	root := os.Getenv("SystemRoot")
	if root == "" {
		root = `C:\Windows`
	}
	exe := filepath.Join(root, "System32", "WindowsPowerShell", "v1.0", "powershell.exe")
	if err := exec.Command(exe, "-NoProfile", "-NonInteractive", "-Command", ps).Run(); err != nil {
		return nil, err
	}
	b, err := os.ReadFile(tmp)
	if err != nil || len(b) == 0 {
		return nil, errors.New("captura vazia")
	}
	return b, nil
}

// inSession0 diz se o processo está na sessão de serviços (sem desktop do usuário).
func inSession0() bool {
	var sid uint32
	if err := windows.ProcessIdToSessionId(windows.GetCurrentProcessId(), &sid); err != nil {
		return false
	}
	return sid == 0
}
