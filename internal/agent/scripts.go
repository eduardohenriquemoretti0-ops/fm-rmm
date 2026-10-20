package agent

// Biblioteca de scripts assinada no agente + ação nativa rodar_script.
//
// NÃO é terminal remoto. MODELO DE CONFIANÇA
//
//   - A biblioteca é assinada OFFLINE pela chave RAIZ e chega no check-in. O
//     agente só a aceita se a assinatura conferir com a raiz do bundle e a
//     versão for MAIOR que a já aceita (anti-downgrade, persistida em
//     scripts.json). A guardada é re-verificada ao abrir; de outra raiz, descartada.
//   - O job só carrega script_id + versao. O CORPO nunca vem do job: é
//     resolvido aqui, na biblioteca confiável. Fora dela => recusa.
//   - Antes de rodar, o sha256 do corpo é RECONFERIDO (defesa em profundidade);
//     divergência => recusa.
//   - O comando é montado por MontarScript (PURA): interpretador fixo, sem
//     shell intermediário, corpo como único argumento. Executor injetável
//     (ag.scriptRun): os testes usam fake; nenhum teste roda script.

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"os/exec"
	"sync"
	"time"

	"github.com/eduardohenriquemoretti0-ops/fm-rmm/internal/catalog"
	"github.com/eduardohenriquemoretti0-ops/fm-rmm/internal/escrow"
	"github.com/eduardohenriquemoretti0-ops/fm-rmm/internal/proto"
	"github.com/eduardohenriquemoretti0-ops/fm-rmm/internal/sign"
)

// errBibliotecaRepetida: mesma versão já aceita (caso normal no check-in).
var errBibliotecaRepetida = errors.New("biblioteca de scripts repetida (mesma versão já aceita)")

// fileScripts é o arquivo, no diretório de dados, com a biblioteca aceita.
const fileScripts = "scripts.json"

type scriptFile struct {
	MaxVersion int             `json:"max_version"`
	Biblioteca json.RawMessage `json:"biblioteca,omitempty"`
	Assinatura []byte          `json:"assinatura,omitempty"`
}

type scriptStore struct {
	mu         sync.RWMutex
	path       string
	raiz       ed25519.PublicKey
	maxVersion int
	lib        sign.ScriptLibrary
	log        *slog.Logger
}

// openScripts carrega a biblioteca persistida. Arquivo corrompido: falha
// fechada. Biblioteca que não confere com a raiz atual: descartada.
func openScripts(path string, raiz ed25519.PublicKey, log *slog.Logger) (*scriptStore, error) {
	s := &scriptStore{path: path, raiz: raiz, log: log}
	var f scriptFile
	err := readJSONFile(path, &f)
	if errors.Is(err, os.ErrNotExist) {
		return s, nil
	}
	if err != nil {
		return nil, fmt.Errorf("biblioteca de scripts: %w", err)
	}
	if len(f.Biblioteca) == 0 {
		return s, nil
	}
	l, err := sign.ParseScriptLibrary(raiz, f.Biblioteca, f.Assinatura)
	if err != nil {
		log.Warn("biblioteca de scripts guardada não confere com a raiz atual; descartada", "erro", err)
		return s, nil
	}
	s.maxVersion, s.lib = max(f.MaxVersion, l.Version), l
	return s, nil
}

// resolver devolve a entrada exata (id + versão) da biblioteca confiável.
func (s *scriptStore) resolver(id, versao string) (sign.ScriptEntry, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.lib.Script(id, versao)
}

// ingerir verifica contra a raiz, recusa downgrade/replay, persiste e só então
// troca a biblioteca em memória.
func (s *scriptStore) ingerir(raw, assinatura []byte) error {
	l, err := sign.ParseScriptLibrary(s.raiz, raw, assinatura)
	if err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if l.Version == s.maxVersion {
		return fmt.Errorf("%w: %w: v%d", sign.ErrBibliotecaVersao, errBibliotecaRepetida, l.Version)
	}
	if l.Version < s.maxVersion {
		return fmt.Errorf("%w: recebida v%d, já aceita v%d", sign.ErrBibliotecaVersao, l.Version, s.maxVersion)
	}
	b, err := json.Marshal(scriptFile{MaxVersion: l.Version,
		Biblioteca: append([]byte(nil), raw...), Assinatura: append([]byte(nil), assinatura...)})
	if err != nil {
		return err
	}
	if err := writeFileAtomic(s.path, b); err != nil {
		return fmt.Errorf("gravar biblioteca de scripts: %w", err)
	}
	s.maxVersion, s.lib = l.Version, l
	s.log.Info("biblioteca de scripts aceita", "versao", l.Version, "scripts", len(l.Scripts))
	return nil
}

// IngerirBibliotecaScripts aceita uma biblioteca assinada pela raiz.
func (ag *Agent) IngerirBibliotecaScripts(raw, assinatura []byte) error {
	if ag.scripts == nil {
		return errors.New("biblioteca de scripts não inicializada")
	}
	return ag.scripts.ingerir(raw, assinatura)
}

// aplicarScriptsDoCheckin ingere a biblioteca do check-in; repetida é silencioso.
func (ag *Agent) aplicarScriptsDoCheckin(c *proto.SignedScriptLibrary) {
	err := ag.IngerirBibliotecaScripts(c.Raw, c.Sig)
	if err == nil || errors.Is(err, errBibliotecaRepetida) {
		return
	}
	ag.Log.Warn("biblioteca de scripts recusada", "erro", err)
}

// ScriptCmd é o comando de um script (sem shell intermediário: nome + argv).
type ScriptCmd struct {
	Name string
	Args []string
}

// MontarScript monta a execução do script para o SO. PURA: não executa nada.
// Revalida a entrada (inclusive o sha256 do corpo) e exige interpretador
// compatível com o SO (powershell só em windows, bash só em linux).
func MontarScript(goos string, e sign.ScriptEntry) (ScriptCmd, error) {
	if err := e.Validar(); err != nil {
		return ScriptCmd{}, err
	}
	switch {
	case goos == "windows" && e.Interprete == sign.InterpretePowerShell:
		return ScriptCmd{Name: "powershell", Args: []string{"-NoLogo", "-NoProfile", "-NonInteractive",
			"-ExecutionPolicy", "Bypass", "-Command", e.Corpo}}, nil
	case goos == "linux" && e.Interprete == sign.InterpreteBash:
		return ScriptCmd{Name: "bash", Args: []string{"-c", e.Corpo}}, nil
	}
	return ScriptCmd{}, fmt.Errorf("interpretador %q do script não se aplica a %s", e.Interprete, goos)
}

// runScript é o executor real: caminho fixo do interpretador, ambiente mínimo,
// saída limitada (proto.MaxOutputSize) e encerramento no timeout do contexto.
func runScript(ctx context.Context, name string, args ...string) (string, error) {
	name, args, env := prepararInterpretador(name, args)
	cmd := exec.CommandContext(ctx, name, args...)
	cmd.Env = env
	out := &capWriter{max: proto.MaxOutputSize}
	cmd.Stdout, cmd.Stderr = out, out
	cmd.WaitDelay = 5 * time.Second
	err := cmd.Run()
	s := out.buf.String()
	if out.truncated {
		s += "\n[saída truncada]"
	}
	if errors.Is(ctx.Err(), context.DeadlineExceeded) {
		return s, errors.New("tempo limite excedido")
	}
	return s, err
}

// scriptAcao é o fluxo de rodar_script: resolve (id, versão) na biblioteca
// confiável, reconfere o hash, monta a execução e roda no executor injetável.
func (ag *Agent) scriptAcao(ctx context.Context, a catalog.Action, p proto.JobPayload) (string, error) {
	id, versao := p.Params["script_id"], p.Params["versao"]
	log := ag.Log.With("job", p.JobID, "acao", a.Name, "emissor", p.Issuer, "script", id, "versao", versao)
	if !a.Changes || !a.Native {
		return "", errors.New(a.Name + " recusado: ação mal definida no catálogo")
	}
	if ag.scripts == nil {
		return "", errors.New(a.Name + " recusado: biblioteca de scripts indisponível")
	}
	e, ok := ag.scripts.resolver(id, versao)
	if !ok {
		log.Warn("script RECUSADO: fora da biblioteca confiável")
		return "", fmt.Errorf("%s recusado: %q versão %q não existe na biblioteca de scripts assinada", a.Name, id, versao)
	}
	if sign.HashCorpoScript(e.Corpo) != e.SHA256 {
		log.Error("script RECUSADO: sha256 do corpo diverge do assinado")
		return "", fmt.Errorf("%s recusado: corpo de %q v%s não confere com o sha256 assinado", a.Name, id, versao)
	}
	cmd, err := MontarScript(ag.goos, e)
	if err != nil {
		log.Warn("script RECUSADO", "razao", err.Error())
		return "", fmt.Errorf("%s recusado: %v", a.Name, err)
	}
	run := ag.scriptRun
	if run == nil {
		return "", errors.New(a.Name + " recusado: executor indisponível")
	}
	ctx, cancel := context.WithTimeout(ctx, a.Timeout)
	defer cancel()
	log.Info("script EXECUTANDO", "sha256", e.SHA256, "interprete", e.Interprete)
	out, err := run(ctx, cmd.Name, cmd.Args...)
	out = escrow.Redigir(out)
	if err != nil {
		log.Error("script FALHOU", "erro", err.Error())
		return "", fmt.Errorf("%s falhou (%s v%s): %v: %s", a.Name, e.ID, e.Versao, err, resumo(out))
	}
	log.Info("script CONCLUÍDO")
	return fmt.Sprintf("script=%s versao=%s sha256=%s\n%s", e.ID, e.Versao, e.SHA256, string(bytes.TrimSpace([]byte(out)))), nil
}
