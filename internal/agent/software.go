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
//   - EXCEÇÃO (defesa em profundidade, sha256 imposto): se o item do catálogo
//     assinado traz sha256, o agente BAIXA o instalador antes de instalar,
//     confere o hash e RECUSA se divergir (verificarSHA256). Item sem sha256 =
//     fluxo acima, inalterado. O sha256 refere-se ao ARQUIVO instalador
//     (winget: o instalador do manifesto; apt: o .deb do próprio pacote, sem
//     contar dependências). Falha ao baixar/localizar o arquivo = recusa
//     (falha fechada). LIMITAÇÕES: (a) winget não permite instalar o arquivo
//     que baixamos com segurança (os switches silenciosos dependem do
//     manifesto), então "winget download" confere o hash e "winget install"
//     baixa de novo; o winget já valida o hash contra o manifesto da fonte,
//     mas há uma janela TOCTOU entre os dois downloads que só o hash do
//     manifesto cobre; (b) apt reaproveita os .deb baixados (Dir::Cache::archives
//     apontando p/ o diretório verificado), sem novo download.
//   - winget roda NO CONTEXTO DO USUÁRIO LOGADO (não sob SYSTEM). O agente é
//     SYSTEM/Session 0, e o winget é o App Installer (MSIX por usuário): sob
//     SYSTEM morre com 0xc0000135 (STATUS_DLL_NOT_FOUND). Por isso, em Windows,
//     todo comando winget (install, uninstall e o "download" do sha256) é
//     executado por ag.wingetUserRun (runInUserSession, usersession_windows.go):
//     WTSGetActiveConsoleSessionId + WTSQueryUserToken + DuplicateTokenEx +
//     CreateProcessAsUser (helper comum withUserSession, o mesmo do indicador),
//     com stdout/stderr capturados em arquivo temporário, timeout do ctx e exit
//     code. SEM USUÁRIO LOGADO a ação é RECUSADA com erro claro ("winget exige um
//     usuário logado; agende quando houver sessão, ou use MSI/machine-scope") e
//     NUNCA cai para SYSTEM. apt NÃO usa contexto de usuário (roda bem como
//     root). Consequência: o winget instala com os privilégios/escopo do usuário
//     (instalador que exige admin pode pedir UAC, que não há sem interação;
//     preferir pacotes com escopo de usuário ou MSI/machine-scope). resolverWinget
//     acha o winget.exe do App Installer em WindowsApps (caminho ABSOLUTO).
//     Testes: wingetUserRun e softRun são injetáveis; o CreateProcessAsUser real
//     só se valida na VM (roteiro em usersession_windows.go).
//   - Executor injetável (ag.softRun): os testes usam fake; nenhum teste instala.

import (
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
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

// errSemUsuarioLogado: não há sessão interativa para rodar o winget.
var errSemUsuarioLogado = errors.New("nenhum usuário logado")

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
	if it.Gerenciador == sign.GerenciadorWinget && ag.wingetUserRun != nil {
		run = ag.wingetUserRun // winget: contexto do usuário logado, nunca SYSTEM
	}
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
	if op == "instalar" && it.SHA256 != "" {
		dir, err := ag.verificarSHA256(ctx, run, &cmd, it)
		if dir != "" {
			defer os.RemoveAll(dir)
		}
		if err != nil {
			log.Warn("software RECUSADO: sha256 do instalador", "erro", err.Error())
			return "", fmt.Errorf("%s recusado (%s): %v", a.Name, it.ID, err)
		}
		log.Info("software: sha256 do instalador conferido", "sha256", it.SHA256)
	}
	log.Info("software EXECUTANDO", "comando", cmd.String())
	out, err := run(ctx, cmd.Name, cmd.Args...)
	if err != nil {
		log.Error("software FALHOU", "erro", err.Error())
		if errors.Is(err, errSemUsuarioLogado) {
			return "", fmt.Errorf("%s recusado (%s): winget exige um usuário logado; agende quando houver sessão, ou use MSI/machine-scope (%v)", a.Name, it.ID, err)
		}
		return "", fmt.Errorf("%s falhou (%s): %v: %s%s", a.Name, it.ID, err, resumo(out), dicaWinget(cmd.Name, err, out))
	}
	log.Info("software CONCLUÍDO")
	return fmt.Sprintf("%s item=%s pkg=%s gerenciador=%s %s", op, it.ID, it.PkgID, it.Gerenciador, resumo(out)), nil
}

// verificarSHA256 baixa o instalador do item (diretório temporário 0700,
// devolvido p/ o chamador remover) e confere o sha256 do catálogo assinado.
// Em apt, ajusta cmd p/ instalar a partir dos .deb verificados.
func (ag *Agent) verificarSHA256(ctx context.Context, run cmdRunner, cmd *SoftCmd, it sign.SoftwareItem) (string, error) {
	dir, err := os.MkdirTemp("", "fmrmm-sw-")
	if err != nil {
		return "", fmt.Errorf("sha256 não verificável (diretório temporário): %v", err)
	}
	switch it.Gerenciador {
	case sign.GerenciadorApt:
		pkg := it.PkgID
		if it.Versao != "" {
			pkg += "=" + it.Versao
		}
		if out, err := run(ctx, "apt-get", "install", "--download-only", "-y",
			"-o", "Dir::Cache::archives="+dir, pkg); err != nil {
			return dir, fmt.Errorf("sha256 não verificável: download falhou: %v: %s", err, resumo(out))
		}
		arqs, _ := filepath.Glob(filepath.Join(dir, it.PkgID+"_*.deb"))
		if err := conferirHashes(arqs, it.SHA256, false); err != nil {
			return dir, err
		}
		// instala a partir dos .deb já verificados (sem novo download do pacote)
		cmd.Args = append([]string{"-o", "Dir::Cache::archives=" + dir}, cmd.Args...)
		return dir, nil
	case sign.GerenciadorWinget:
		args := []string{"download", "--id", it.PkgID, "--exact", "--skip-dependencies",
			"--download-directory", dir, "--accept-package-agreements", "--accept-source-agreements"}
		if it.Versao != "" {
			args = append(args, "--version", it.Versao)
		}
		if out, err := run(ctx, cmd.Name, args...); err != nil {
			return dir, fmt.Errorf("sha256 não verificável: winget download falhou: %v: %s", err, resumo(out))
		}
		ents, _ := os.ReadDir(dir)
		var arqs []string
		for _, e := range ents {
			ext := strings.ToLower(filepath.Ext(e.Name()))
			if e.Type().IsRegular() && ext != ".yaml" && ext != ".yml" {
				arqs = append(arqs, filepath.Join(dir, e.Name()))
			}
		}
		return dir, conferirHashes(arqs, it.SHA256, true)
	}
	return dir, fmt.Errorf("sha256 não verificável: gerenciador %q", it.Gerenciador)
}

// conferirHashes exige ao menos um arquivo e que o hash confira (qualquer um se
// anyOne, p/ pastas com vários instaladores; senão TODOS). Diverge => erro.
func conferirHashes(arqs []string, esperado string, anyOne bool) error {
	if len(arqs) == 0 {
		return errors.New("sha256 não verificável: instalador baixado não encontrado")
	}
	var obtidos []string
	for _, f := range arqs {
		h, err := sha256Arquivo(f)
		if err != nil {
			return fmt.Errorf("sha256 não verificável: %v", err)
		}
		ok := h == esperado
		if ok && anyOne {
			return nil
		}
		if !ok && !anyOne {
			return fmt.Errorf("sha256 DIVERGE: %s esperado=%s obtido=%s", filepath.Base(f), esperado, h)
		}
		obtidos = append(obtidos, h)
	}
	if anyOne {
		return fmt.Errorf("sha256 DIVERGE: esperado=%s obtido(s)=%s", esperado, strings.Join(obtidos, ","))
	}
	return nil
}

func sha256Arquivo(path string) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer f.Close()
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", err
	}
	return hex.EncodeToString(h.Sum(nil)), nil
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
