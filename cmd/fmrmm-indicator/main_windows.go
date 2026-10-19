//go:build windows

// fmrmm-indicator é o helper de indicador de sessão do Windows. O serviço
// FM-RMM (SYSTEM) o lança na sessão interativa do usuário com CreateProcessAsUser.
// Aqui ele:
//   - conecta no canal de liveness do serviço (loopback) e manda "HELLO <token>"
//     (prova de que subiu na sessão do usuário = ack);
//   - mostra um ícone de bandeja + balão persistente avisando da sessão remota;
//   - manda "HB" periodicamente; se o serviço mandar "QUIT" (ou a conexão cair),
//     retira o ícone e sai.
//
// Sem este helper visível, o serviço recusa a sessão (fail-closed).
package main

import (
	"bufio"
	"encoding/base64"
	"net"
	"os"
	"runtime"
	"syscall"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
)

// --- Win32 mínimo via lazy DLL ---
var (
	user32              = windows.NewLazySystemDLL("user32.dll")
	shell32             = windows.NewLazySystemDLL("shell32.dll")
	pRegisterClassEx    = user32.NewProc("RegisterClassExW")
	pCreateWindowEx     = user32.NewProc("CreateWindowExW")
	pDefWindowProc      = user32.NewProc("DefWindowProcW")
	pGetMessage         = user32.NewProc("GetMessageW")
	pTranslateMessage   = user32.NewProc("TranslateMessage")
	pDispatchMessage    = user32.NewProc("DispatchMessageW")
	pDestroyWindow      = user32.NewProc("DestroyWindow")
	pPostQuitMessage    = user32.NewProc("PostQuitMessage")
	pPostMessage        = user32.NewProc("PostMessageW")
	pSetTimer           = user32.NewProc("SetTimer")
	pLoadIcon           = user32.NewProc("LoadIconW")
	pShellNotifyIcon    = shell32.NewProc("Shell_NotifyIconW")
)

const (
	wmDestroy = 0x0002
	wmClose   = 0x0010
	wmTimer   = 0x0113

	nimAdd    = 0x0000
	nimModify = 0x0001
	nimDelete = 0x0002

	nifMessage = 0x0001
	nifIcon    = 0x0002
	nifTip     = 0x0004
	nifInfo    = 0x0010

	niifInfo = 0x0001

	cwUseDefault = ^uintptr(0x7fffffff) // 0x80000000 (CW_USEDEFAULT)
	idiInfo      = 32516                // IDI_INFORMATION
	timerID      = 1
	timerMs      = 3000 // heartbeat a cada 3s
	reballoonN   = 10   // reballoon a cada 10 ticks (~30s)
)

type wndClassEx struct {
	cbSize        uint32
	style         uint32
	lpfnWndProc   uintptr
	cbClsExtra    int32
	cbWndExtra    int32
	hInstance     windows.Handle
	hIcon         windows.Handle
	hCursor       windows.Handle
	hbrBackground windows.Handle
	lpszMenuName  *uint16
	lpszClassName *uint16
	hIconSm       windows.Handle
}

type notifyIconData struct {
	cbSize           uint32
	hWnd             windows.Handle
	uID              uint32
	uFlags           uint32
	uCallbackMessage uint32
	hIcon            windows.Handle
	szTip            [128]uint16
	dwState          uint32
	dwStateMask      uint32
	szInfo           [256]uint16
	uTimeout         uint32
	szInfoTitle      [64]uint16
	dwInfoFlags      uint32
	guidItem         [16]byte
	hBalloonIcon     windows.Handle
}

type msgStruct struct {
	hwnd    windows.Handle
	message uint32
	wParam  uintptr
	lParam  uintptr
	time    uint32
	pt      struct{ x, y int32 }
}

// estado global (WndProc é callback do SO)
var (
	gConn   net.Conn
	gIcon   windows.Handle
	gMsg    string
	gTick   int
	gNidPtr *notifyIconData
)

func copyUTF16(dst []uint16, s string) {
	src := windows.StringToUTF16(s)
	n := len(src)
	if n > len(dst) {
		n = len(dst)
		src[n-1] = 0
	}
	copy(dst[:n], src[:n])
}

func shellNotify(action uintptr, nid *notifyIconData) {
	pShellNotifyIcon.Call(action, uintptr(unsafe.Pointer(nid)))
}

func baseNid(hwnd windows.Handle) *notifyIconData {
	nid := &notifyIconData{
		cbSize:           uint32(unsafe.Sizeof(notifyIconData{})),
		hWnd:             hwnd,
		uID:              1,
		uFlags:           nifIcon | nifTip | nifMessage,
		uCallbackMessage: 0x8000, // WM_APP
		hIcon:            gIcon,
	}
	copyUTF16(nid.szTip[:], "FM-RMM — sessão de suporte remoto ATIVA")
	return nid
}

func showBalloon(nid *notifyIconData) {
	nid.uFlags |= nifInfo
	copyUTF16(nid.szInfoTitle[:], "FM-RMM — sessão remota ATIVA")
	copyUTF16(nid.szInfo[:], gMsg)
	nid.dwInfoFlags = niifInfo
	shellNotify(nimModify, nid)
}

func wndProc(hwnd windows.Handle, msg uint32, wParam, lParam uintptr) uintptr {
	switch msg {
	case wmTimer:
		if gConn != nil {
			_, _ = gConn.Write([]byte("HB\n"))
		}
		gTick++
		if gTick%reballoonN == 0 && gNidPtr != nil {
			showBalloon(gNidPtr)
		}
		return 0
	case wmClose:
		pDestroyWindow.Call(uintptr(hwnd))
		return 0
	case wmDestroy:
		if gNidPtr != nil {
			shellNotify(nimDelete, gNidPtr)
		}
		pPostQuitMessage.Call(0)
		return 0
	}
	r, _, _ := pDefWindowProc.Call(uintptr(hwnd), uintptr(msg), wParam, lParam)
	return r
}

func main() {
	runtime.LockOSThread() // o loop de mensagens tem de ficar numa thread só

	if len(os.Args) < 4 {
		os.Exit(2)
	}
	addr, token, msgB64 := os.Args[1], os.Args[2], os.Args[3]
	if b, err := base64.StdEncoding.DecodeString(msgB64); err == nil {
		gMsg = string(b)
	} else {
		gMsg = "Sessão de suporte remoto ATIVA."
	}

	conn, err := net.Dial("tcp", addr)
	if err != nil {
		os.Exit(1) // sem canal com o serviço: serviço não recebe ack -> recusa
	}
	gConn = conn
	if _, err := conn.Write([]byte("HELLO " + token + "\n")); err != nil {
		os.Exit(1)
	}

	className, _ := windows.UTF16PtrFromString("FMRMMIndicatorWnd")
	var hInst windows.Handle // 0: instância do próprio processo
	ic, _, _ := pLoadIcon.Call(0, uintptr(idiInfo))
	gIcon = windows.Handle(ic)

	wc := wndClassEx{
		lpfnWndProc:   syscall.NewCallback(wndProc),
		hInstance:     hInst,
		lpszClassName: className,
	}
	wc.cbSize = uint32(unsafe.Sizeof(wc))
	pRegisterClassEx.Call(uintptr(unsafe.Pointer(&wc)))

	title, _ := windows.UTF16PtrFromString("FM-RMM")
	hwndR, _, _ := pCreateWindowEx.Call(
		0,
		uintptr(unsafe.Pointer(className)),
		uintptr(unsafe.Pointer(title)),
		0, // sem WS_VISIBLE: janela oculta, só dona do ícone de bandeja
		cwUseDefault, cwUseDefault, cwUseDefault, cwUseDefault,
		0, 0, uintptr(hInst), 0,
	)
	hwnd := windows.Handle(hwndR)

	nid := baseNid(hwnd)
	gNidPtr = nid
	shellNotify(nimAdd, nid)
	showBalloon(nid) // balão inicial já avisa

	pSetTimer.Call(uintptr(hwnd), timerID, timerMs, 0)

	// lê o canal do serviço; QUIT ou EOF -> fecha a janela (retira a bandeja)
	go func() {
		br := bufio.NewReader(conn)
		for {
			line, err := br.ReadString('\n')
			if err != nil {
				pPostMessage.Call(uintptr(hwnd), wmClose, 0, 0)
				return
			}
			if line == "QUIT\n" {
				pPostMessage.Call(uintptr(hwnd), wmClose, 0, 0)
				return
			}
		}
	}()

	// backstop: se nada mais encerrar, expira sozinho em 12h (sessão nunca dura tanto)
	go func() {
		time.Sleep(12 * time.Hour)
		pPostMessage.Call(uintptr(hwnd), wmClose, 0, 0)
	}()

	var m msgStruct
	for {
		r, _, _ := pGetMessage.Call(uintptr(unsafe.Pointer(&m)), 0, 0, 0)
		if int32(r) <= 0 { // WM_QUIT (0) ou erro (-1)
			break
		}
		pTranslateMessage.Call(uintptr(unsafe.Pointer(&m)))
		pDispatchMessage.Call(uintptr(unsafe.Pointer(&m)))
	}
}
