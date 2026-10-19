package agent

import (
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"sync"
	"time"

	"github.com/eduardohenriquemoretti0-ops/fm-rmm/internal/sign"
)

// Trust-set do agente: {chave raiz} ∪ signers da lista assinada mais recente.
//
// A raiz vem do bundle e é a âncora. A lista é assinada pela raiz (offline) e
// chega por ingestão (IngerirListaSigners). Sem lista, o trust-set é só a raiz,
// que é o comportamento de antes.
//
// Anti-downgrade: a maior versão já aceita fica gravada em trust.json. Lista
// com versão menor ou igual é recusada, mesmo que a assinatura esteja correta.
// Isso impede replay de uma lista antiga que reabilitaria um operador revogado.

// fileTrust é o arquivo, dentro do diretório de dados, com a lista aceita.
const fileTrust = "trust.json"

// trustFile é o formato gravado em disco: a versão máxima vista e a lista
// corrente com a sua assinatura (para o trust-set sobreviver a reinícios).
type trustFile struct {
	MaxVersion int             `json:"max_version"`
	Lista      json.RawMessage `json:"lista,omitempty"`
	Assinatura []byte          `json:"assinatura,omitempty"`
}

type trustStore struct {
	mu         sync.RWMutex
	path       string
	raiz       ed25519.PublicKey
	maxVersion int
	ts         sign.TrustSet
	log        *slog.Logger
}

// openTrust carrega o trust-set persistido. Arquivo corrompido: falha fechada
// (sem ele não há anti-downgrade). Lista que não confere com a raiz atual (ex.:
// raiz rotacionada no reprovisionamento): é descartada e o trust-set volta a
// ser só a raiz, sem herdar a versão antiga.
func openTrust(path string, raiz ed25519.PublicKey, now time.Time, log *slog.Logger) (*trustStore, error) {
	t := &trustStore{path: path, raiz: raiz, ts: sign.SingleKey(raiz), log: log}
	var f trustFile
	err := readJSONFile(path, &f)
	if errors.Is(err, os.ErrNotExist) {
		return t, nil
	}
	if err != nil {
		return nil, fmt.Errorf("trust-set: %w", err)
	}
	if len(f.Lista) == 0 {
		return t, nil
	}
	l, err := sign.ParseSignerList(raiz, f.Lista, f.Assinatura)
	if err != nil {
		log.Warn("lista de signers guardada não confere com a raiz atual; descartada", "erro", err)
		return t, nil
	}
	ts, err := sign.TrustFromList(raiz, l, now)
	if err != nil {
		return nil, fmt.Errorf("trust-set: %w", err)
	}
	t.maxVersion, t.ts = max(f.MaxVersion, l.Version), ts
	return t, nil
}

// snapshot devolve o trust-set vigente. As fatias nunca são alteradas depois de
// criadas (a ingestão troca o conjunto inteiro), então o retorno é seguro.
func (t *trustStore) snapshot() sign.TrustSet {
	t.mu.RLock()
	defer t.mu.RUnlock()
	return t.ts
}

// ingerir verifica a lista contra a raiz, recusa downgrade, persiste e só então
// troca o trust-set em memória. Se a gravação falhar, nada muda.
func (t *trustStore) ingerir(raw, assinatura []byte, now time.Time) error {
	l, err := sign.ParseSignerList(t.raiz, raw, assinatura)
	if err != nil {
		return err
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	if l.Version <= t.maxVersion {
		return fmt.Errorf("%w: recebida v%d, já aceita v%d", sign.ErrListaVersao, l.Version, t.maxVersion)
	}
	ts, err := sign.TrustFromList(t.raiz, l, now)
	if err != nil {
		return err
	}
	rawCopia := append([]byte(nil), raw...)
	sigCopia := append([]byte(nil), assinatura...)
	b, err := json.Marshal(trustFile{MaxVersion: l.Version, Lista: rawCopia, Assinatura: sigCopia})
	if err != nil {
		return err
	}
	if err := writeFileAtomic(t.path, b); err != nil {
		return fmt.Errorf("gravar trust-set: %w", err)
	}
	t.maxVersion, t.ts = l.Version, ts
	t.log.Info("lista de signers aceita", "versao", l.Version, "chaves_confiadas", len(ts.Keys))
	return nil
}

// IngerirListaSigners aceita uma lista de signers assinada pela raiz. raw são
// os bytes canônicos da lista e assinatura a assinatura Ed25519 destacada.
// Erros (sem efeito no trust-set): sign.ErrListaAssinatura, sign.ErrListaMalformada,
// sign.ErrListaVersao.
func (ag *Agent) IngerirListaSigners(raw, assinatura []byte) error {
	if ag.trust == nil {
		return errors.New("trust-set não inicializado")
	}
	return ag.trust.ingerir(raw, assinatura, ag.now())
}

// confianca é o trust-set usado para verificar jobs e concessões.
func (ag *Agent) confianca() sign.TrustSet {
	if ag.trust == nil {
		return sign.SingleKey(ag.signer)
	}
	return ag.trust.snapshot()
}
