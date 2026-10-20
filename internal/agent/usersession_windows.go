//go:build windows

package agent

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"unsafe"

	"golang.org/x/sys/windows"
)

// Helpers comuns de "executar na sessão do usuário logado" (agente = SYSTEM,
// Session 0). Usados pelo indicador (launchInUserSession) e pelo winget
// (runInUserSession, ver software.go).

// VALIDAÇÃO NA VM (Windows, o CreateProcessAsUser real não roda em CI):
//  1. Com usuário logado no console: disparar instalar_pacote de um item winget
//     (ex.: 7zip.7zip) pelo agente SYSTEM; esperar sucesso e
//     "C:\Program Files\7-Zip\7z.exe" presente; o log do job mostra a saída do
//     winget. desinstalar_pacote idem.
//  2. Sem login (tela de logon / usuário deslogado): o mesmo job deve voltar
//     "recusado ... winget exige um usuário logado; agende quando houver sessão,
//     ou use MSI/machine-scope" e NADA instalado.
//  3. Pacote inexistente: erro do winget com código de saída 0x... no resultado.

// withUserSession obtém o token primário do usuário da sessão de console ativa
// e o bloco de ambiente dele, chama fn e libera tudo. Sem usuário logado
// devolve um erro que satisfaz errors.Is(err, errSemUsuarioLogado).
func withUserSession(fn func(primary windows.Token, envBlock *uint16) error) error {
	sess := windows.WTSGetActiveConsoleSessionId()
	if sess == 0xFFFFFFFF {
		return fmt.Errorf("%w (nenhuma sessão de console ativa)", errSemUsuarioLogado)
	}

	var userTok windows.Token
	if err := windows.WTSQueryUserToken(sess, &userTok); err != nil {
		return fmt.Errorf("%w (WTSQueryUserToken: %v)", errSemUsuarioLogado, err)
	}
	defer userTok.Close()

	var primary windows.Token
	if err := windows.DuplicateTokenEx(userTok, windows.TOKEN_ALL_ACCESS, nil,
		windows.SecurityImpersonation, windows.TokenPrimary, &primary); err != nil {
		return fmt.Errorf("DuplicateTokenEx: %w", err)
	}
	defer primary.Close()

	var envBlock *uint16
	if err := windows.CreateEnvironmentBlock(&envBlock, primary, false); err != nil {
		return fmt.Errorf("CreateEnvironmentBlock: %w", err)
	}
	defer windows.DestroyEnvironmentBlock(envBlock)

	return fn(primary, envBlock)
}

// createProcessInSession cria o processo com o token do usuário em
// winsta0\default. Se stdio != 0, é usado como stdout+stderr (handle
// inheritable) e a janela de console é suprimida. Devolve o handle do processo
// (o chamador fecha).
func createProcessInSession(primary windows.Token, envBlock *uint16, exe, cmdline string,
	stdio windows.Handle, semJanela bool) (windows.Handle, error) {
	desktop, _ := windows.UTF16PtrFromString(`winsta0\default`)
	appName, err := windows.UTF16PtrFromString(exe)
	if err != nil {
		return 0, err
	}
	cmdlinePtr, err := windows.UTF16PtrFromString(cmdline)
	if err != nil {
		return 0, err
	}
	si := windows.StartupInfo{Desktop: desktop}
	si.Cb = uint32(unsafe.Sizeof(si))
	flags := uint32(windows.CREATE_UNICODE_ENVIRONMENT)
	inherit := false
	if stdio != 0 {
		si.Flags = windows.STARTF_USESTDHANDLES
		si.StdOutput, si.StdErr = stdio, stdio
		inherit = true
	}
	if semJanela {
		flags |= windows.CREATE_NO_WINDOW
	}
	var pi windows.ProcessInformation
	if err := windows.CreateProcessAsUser(primary, appName, cmdlinePtr, nil, nil, inherit,
		flags, envBlock, nil, &si, &pi); err != nil {
		return 0, fmt.Errorf("CreateProcessAsUser: %w", err)
	}
	_ = windows.CloseHandle(pi.Thread)
	return pi.Process, nil
}

// runInUserSession é o cmdRunner do winget: roda name+args na sessão do usuário
// logado, captura stdout+stderr num arquivo temporário (diretório 0700 do
// SYSTEM; o handle é herdado pelo filho, que não precisa de ACL no arquivo),
// respeita o timeout do ctx (derruba o processo) e devolve erro com o exit code
// se != 0. Sem usuário logado: errSemUsuarioLogado (nunca cai para SYSTEM).
func runInUserSession(ctx context.Context, name string, args ...string) (string, error) {
	dir, err := os.MkdirTemp("", "fmrmm-wg-")
	if err != nil {
		return "", err
	}
	defer os.RemoveAll(dir)
	outPath := filepath.Join(dir, "saida.txt")
	p16, _ := windows.UTF16PtrFromString(outPath)
	sa := windows.SecurityAttributes{InheritHandle: 1}
	sa.Length = uint32(unsafe.Sizeof(sa))
	h, err := windows.CreateFile(p16, windows.GENERIC_WRITE, windows.FILE_SHARE_READ, &sa,
		windows.CREATE_ALWAYS, windows.FILE_ATTRIBUTE_NORMAL, 0)
	if err != nil {
		return "", fmt.Errorf("arquivo de saída: %w", err)
	}

	cmdline := windows.ComposeCommandLine(append([]string{name}, args...))
	var code uint32
	var timedOut bool
	err = withUserSession(func(primary windows.Token, env *uint16) error {
		proc, err := createProcessInSession(primary, env, name, cmdline, h, true)
		if err != nil {
			return err
		}
		defer windows.CloseHandle(proc)
		for {
			ev, err := windows.WaitForSingleObject(proc, 200)
			if err != nil {
				return fmt.Errorf("WaitForSingleObject: %w", err)
			}
			if ev == windows.WAIT_OBJECT_0 {
				return windows.GetExitCodeProcess(proc, &code)
			}
			if ctx.Err() != nil {
				_ = windows.TerminateProcess(proc, 1)
				_, _ = windows.WaitForSingleObject(proc, 3000)
				timedOut = true
				return nil
			}
		}
	})
	_ = windows.CloseHandle(h) // fecha (uma só vez) antes de ler
	b, _ := os.ReadFile(outPath)
	out := string(b)
	switch {
	case err != nil:
		return out, err
	case timedOut:
		return out, fmt.Errorf("winget (sessão do usuário) excedeu o tempo limite: %w", ctx.Err())
	case code != 0:
		return out, fmt.Errorf("winget (sessão do usuário) terminou com código 0x%x (%d)", code, code)
	}
	return out, nil
}
