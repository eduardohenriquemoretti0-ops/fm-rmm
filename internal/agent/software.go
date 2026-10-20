package agent

// Catálogo de software (allow-list) no agente + ações nativas instalar_pacote /
// desinstalar_pacote.
//
// MODELO DE CONFIANÇA
//
//   - O catálogo é assinado OFFLINE pela chave RAIZ e chega no check-in. O
//     agente só o aceita se a assinatura conferir com a raiz do bundle e a
//     versão for MAIOR que a já aceita (anti-downgrade, persistida em
//     software.json). O catálogo guardado é re-verificado ao abrir.
//   - O job só carrega item_id. O pkg_id NUNCA vem do job: é resolvido aqui,
//     no catálogo confiável local. Item inexistente => recusa. Parâmetro extra
//     (pkg_id, comando) já é recusado por catalog.Validate (parâmetro desconhecido).
//   - O comando é montado por MontarSoftware (PURA, sem shell: nome + argv),
//     com pkg_id/versão validados por alfabeto estrito e sem '-' inicial.
//   - Quem verifica o pacote em si é o gerenciador: winget valida o hash do
//     instalador contra o manifesto do repositório (e a fonte "winget" usa
//     TLS + índice assinado pela Microsoft); apt valida a assinatura do
//     repositório (InRelease/GPG) e os hashes dos .deb. Os campos publisher e
//     sha256 do item são informativos/auditoria: o agente NÃO os usa para
//     autorizar nada.
//   - winget sob SYSTEM (LIMITAÇÃO CONHECIDA DA MICROSOFT): o agente roda como
//     SYSTEM/Session 0, e o winget é o App Installer (MSIX, instalado por
//     usuário): não está no PATH do SYSTEM. Por isso resolverWinget procura
//     %ProgramFiles%\WindowsApps\Microsoft.DesktopAppInstaller_*_8wekyb3d8bbwe\winget.exe
//     (maior versão) e o exec usa o caminho ABSOLUTO. Mesmo assim, o winget.exe do
//     MSIX pode morrer sob SYSTEM com 0xc0000135 (STATUS_DLL_NOT_FOUND, falta o
//     contexto de pacote do usuário); nesse caso o erro devolvido é explícito
//     (dicaWinget). Alternativas, se isso ocorrer em produção (mudança de
//     arquitetura, NÃO implementada aqui): (a) executar o winget no contexto do
//     usuário logado (token da sessão via WTSQueryUserToken+CreateProcessAsUser,
//     helper em Session 1); (b) API COM/PowerShell Microsoft.WinGet.Client
//     (módulo Repair-WinGetPackageManager / -Scope machine); (c) instalar via
//     MSI/EXE do fornecedor com hash. O gancho é ag.wingetResolve/ag.softRun:
//     troque o executor sem mexer na trava de catálogo.
//   - Executor injetável (ag.softRun): os testes usam fake; nenhum teste instala.

import (
	"context"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"

	"github.com/eduardohenriquemoretti0-ops/fm-rmm/internal/catalog"
	"github.com/eduardohenriquemoretti0-ops/fm-rmm/internal/proto"
	"github.com/eduardohenriquemoretti0-ops/fm-rmm/internal/sign"
)

// errCatalogoRepetido: mesma versão já aceita (caso normal: o servidor serve
// o catálogo corrente em todo check-in).
var errCatalogoRepetido = errors.New("catálogo repetido (mesma versão já aceita)")

// fileSoftware é o arquivo, no diretório de dados, com o catálogo aceito.
const fileSoftware = "software.json"

type softFile struct {
	MaxVersion int             `json:"max_version"`
	Catalogo   json.RawMessage `json:"catalogo,omitempty"`
	Assinatura []byte          `json:"assinatura,omitempty"`
}

type softStore struct {
	mu         sync.RWMutex
	path       string
	raiz       ed25519.PublicKey
	maxVersion int
	cat        sign.SoftwareCatalog
	log        *slog.Logger
}

// openSoft carrega o catálogo persistido. Arquivo corrompido: falha fechada.
// Catálogo que não confere com a raiz atual: descartado (sem herdar versão).
func openSoft(path string, raiz ed25519.PublicKey, log *slog.Logger) (*softStore, error) {
	s := &softStore{path: path, raiz: raiz, log: log}
	var f softFile
	err := readJSONFile(path, &f)
	if errors.Is(err, os.ErrNotExist) {
		return s, nil
	}
	if err != nil {
		return nil, fmt.Errorf("catálogo de software: %w", err)
	}
	if len(f.Catalogo) == 0 {
		return s, nil
	}
	c, err := sign.ParseSoftwareCatalog(raiz, f.Catalogo, f.Assinatura)
	if err != nil {
		log.Warn("catálogo de software guardado não confere com a raiz atual; descartado", "erro", err)
		return s, nil
	}
	s.maxVersion, s.cat = max(f.MaxVersion, c.Version), c
	return s, nil
}

// resolver devolve o item do catálogo confiável (ok=false se não existe).
func (s *softStore) resolver(id string) (sign.SoftwareItem, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.cat.Item(id)
}

// ingerir verifica contra a raiz, recusa downgrade/replay, persiste e só então
// troca o catálogo em memória.
func (s *softStore) ingerir(raw, assinatura []byte) error {
	c, err := sign.ParseSoftwareCatalog(s.raiz, raw, assinatura)
	if err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if c.Version == s.maxVersion {
		return fmt.Errorf("%w: %w: v%d", sign.ErrCatalogoVersao, errCatalogoRepetido, c.Version)
	}
	if c.Version < s.maxVersion {
		return fmt.Errorf("%w: recebida v%d, já aceita v%d", sign.ErrCatalogoVersao, c.Version, s.maxVersion)
	}
	b, err := json.Marshal(softFile{MaxVersion: c.Version,
		Catalogo: append([]byte(nil), raw...), Assinatura: append([]byte(nil), assinatura...)})
	if err != nil {
		return err
	}
	if err := writeFileAtomic(s.path, b); err != nil {
		return fmt.Errorf("gravar catálogo de software: %w", err)
	}
	s.maxVersion, s.cat = c.Version, c
	s.log.Info("catálogo de software aceito", "versao", c.Version, "itens", len(c.Items))
	return nil
}

// IngerirCatalogoSoftware aceita um catálogo assinado pela raiz.
func (ag *Agent) IngerirCatalogoSoftware(raw, assinatura []byte) error {
	if ag.soft == nil {
		return errors.New("catálogo de software não inicializado")
	}
	return ag.soft.ingerir(raw, assinatura)
}

// aplicarSoftwareDoCheckin ingere o catálogo do check-in; repetido é silencioso,
// qualquer outra recusa vai ao log. Não interrompe o check-in.
func (ag *Agent) aplicarSoftwareDoCheckin(c *proto.SignedSoftwareCatalog) {
	err := ag.IngerirCatalogoSoftware(c.Raw, c.Sig)
	if err == nil || errors.Is(err, errCatalogoRepetido) {
		return
	}
	ag.Log.Warn("catálogo de software recusado", "erro", err)
}

// SoftCmd é um comando de gerenciador de pacotes (sem shell: nome + argv).
type SoftCmd struct {
	Name string
	Args []string
}

func (c SoftCmd) String() string { return strings.TrimSpace(c.Name + " " + strings.Join(c.Args, " ")) }

// MontarSoftware monta a receita do item para o SO. PURA: não executa nada.
// Revalida o item (defesa em profundidade) e exige gerenciador compatível com o
// SO (winget só em windows, apt só em linux). op é "instalar" ou "desinstalar".
func MontarSoftware(goos, op string, it sign.SoftwareItem) (SoftCmd, error) {
	if err := it.Validar(); err != nil {
		return SoftCmd{}, err
	}
	switch {
	case goos == "windows" && it.Gerenciador == sign.GerenciadorWinget:
		switch op {
		case "instalar":
			args := []string{"install", "--id", it.PkgID, "--exact", "--silent",
				"--accept-package-agreements", "--accept-source-agreements"}
			if it.Versao != "" {
				args = append(args, "--version", it.Versao)
			}
			return SoftCmd{Name: "winget", Args: args}, nil
		case "desinstalar":
			return SoftCmd{Name: "winget", Args: []string{"uninstall", "--id", it.PkgID, "--exact", "--silent",
				"--accept-source-agreements"}}, nil
		}
	case goos == "linux" && it.Gerenciador == sign.GerenciadorApt:
		switch op {
		case "instalar":
			pkg := it.PkgID
			if it.Versao != "" {
				pkg += "=" + it.Versao
			}
			return SoftCmd{Name: "apt-get", Args: []string{"install", "-y", pkg}}, nil
		case "desinstalar":
			return SoftCmd{Name: "apt-get", Args: []string{"remove", "-y", it.PkgID}}, nil
		}
	default:
		return SoftCmd{}, fmt.Errorf("gerenciador %q do item não se aplica a %s", it.Gerenciador, goos)
	}
	return SoftCmd{}, fmt.Errorf("operação desconhecida: %q", op)
}

// softwareAcao é o fluxo de instalar_pacote/desinstalar_pacote: resolve o item
// no catálogo confiável, monta a receita e roda no executor injetável.
func (ag *Agent) softwareAcao(ctx context.Context, a catalog.Action, p proto.JobPayload) (string, error) {
	op := "instalar"
	if a.Name == "desinstalar_pacote" {
		op = "desinstalar"
	}
	log := ag.Log.With("job", p.JobID, "acao", a.Name, "emissor", p.Issuer, "item", p.Params["item_id"])
	if !a.Changes || !a.Native {
		return "", errors.New(a.Name + " recusado: ação mal definida no catálogo")
	}
	if ag.soft == nil {
		return "", errors.New(a.Name + " recusado: catálogo de software indisponível")
	}
	it, ok := ag.soft.resolver(p.Params["item_id"])
	if !ok {
		log.Warn("software RECUSADO: item fora do catálogo confiável")
		return "", fmt.Errorf("%s recusado: item %q não existe no catálogo de software aprovado", a.Name, p.Params["item_id"])
	}
	cmd, err := MontarSoftware(ag.goos, op, it)
	if err != nil {
		log.Warn("software RECUSADO", "razao", err.Error())
		return "", fmt.Errorf("%s recusado: %v", a.Name, err)
	}
	run := ag.softRun
	if run == nil {
		return "", errors.New(a.Name + " recusado: executor indisponível")
	}
	ctx, cancel := context.WithTimeout(ctx, a.Timeout)
	defer cancel()
	if cmd.Name == "winget" && ag.wingetResolve != nil {
		exe, err := ag.wingetResolve()
		if err != nil {
			log.Error("software FALHOU", "erro", err.Error())
			return "", fmt.Errorf("%s falhou (%s): %v", a.Name, it.ID, err)
		}
		cmd.Name = exe
	}
	log.Info("software EXECUTANDO", "comando", cmd.String())
	out, err := run(ctx, cmd.Name, cmd.Args...)
	if err != nil {
		log.Error("software FALHOU", "erro", err.Error())
		return "", fmt.Errorf("%s falhou (%s): %v: %s%s", a.Name, it.ID, err, resumo(out), dicaWinget(cmd.Name, err, out))
	}
	log.Info("software CONCLUÍDO")
	return fmt.Sprintf("%s item=%s pkg=%s gerenciador=%s %s", op, it.ID, it.PkgID, it.Gerenciador, resumo(out)), nil
}

// dicaWinget acrescenta uma explicação quando o winget morre com 0xc0000135
// (STATUS_DLL_NOT_FOUND = 3221225781), sintoma de MSIX rodando sob SYSTEM.
func dicaWinget(nome string, err error, out string) string {
	if !strings.Contains(strings.ToLower(filepath.Base(nome)), "winget") {
		return ""
	}
	t := strings.ToLower(err.Error() + " " + out)
	if strings.Contains(t, "0xc0000135") || strings.Contains(t, "3221225781") {
		return " [winget (MSIX) não executa sob SYSTEM/Session 0: limitação da Microsoft; ver cabeçalho de software.go para as alternativas]"
	}
	return ""
}

// resolverWingetEm acha o winget.exe: primeiro o App Installer em
// <windowsApps>\Microsoft.DesktopAppInstaller_<versão>_*\winget.exe (maior
// versão), depois lookPath("winget"). Devolve caminho ABSOLUTO.
func resolverWingetEm(windowsApps string, lookPath func(string) (string, error)) (string, error) {
	dirs, _ := filepath.Glob(filepath.Join(windowsApps, "Microsoft.DesktopAppInstaller_*"))
	best, bestV := "", []int(nil)
	for _, d := range dirs {
		exe := filepath.Join(d, "winget.exe")
		if st, err := os.Stat(exe); err != nil || st.IsDir() {
			continue
		}
		v := versaoPacoteMSIX(filepath.Base(d))
		if v == nil {
			continue
		}
		if best == "" || cmpVersao(v, bestV) > 0 {
			best, bestV = exe, v
		}
	}
	if best != "" {
		return best, nil
	}
	if p, err := lookPath("winget"); err == nil && filepath.IsAbs(p) {
		return p, nil
	}
	return "", errors.New("winget não encontrado (nem em WindowsApps\\Microsoft.DesktopAppInstaller_*, nem no PATH): instale/atualize o App Installer; sob SYSTEM o MSIX pode estar inacessível (ver cabeçalho de software.go)")
}

// resolverWinget usa o %ProgramFiles% real do SO.
func resolverWinget() (string, error) {
	pf := os.Getenv("ProgramFiles")
	if pf == "" {
		pf = `C:\Program Files`
	}
	return resolverWingetEm(filepath.Join(pf, "WindowsApps"), exec.LookPath)
}

// versaoPacoteMSIX extrai [1 24 25200 0] de "Microsoft.DesktopAppInstaller_1.24.25200.0_x64__8wekyb3d8bbwe".
func versaoPacoteMSIX(nome string) []int {
	partes := strings.Split(nome, "_")
	if len(partes) < 2 {
		return nil
	}
	var v []int
	for _, n := range strings.Split(partes[1], ".") {
		i, err := strconv.Atoi(n)
		if err != nil {
			return nil
		}
		v = append(v, i)
	}
	return v
}

func cmpVersao(a, b []int) int {
	for i := 0; i < max(len(a), len(b)); i++ {
		var x, y int
		if i < len(a) {
			x = a[i]
		}
		if i < len(b) {
			y = b[i]
		}
		if x != y {
			if x > y {
				return 1
			}
			return -1
		}
	}
	return 0
}
