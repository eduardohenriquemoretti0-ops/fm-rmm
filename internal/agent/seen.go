package agent

import (
	"encoding/json"
	"errors"
	"os"
	"sync"
	"time"
)

// seenStore guarda os job_id já executados até a validade deles acabar.
// Depois disso o próprio VerifyJob recusa o job por expiração.
type seenStore struct {
	mu   sync.Mutex
	path string
	ids  map[string]time.Time
}

func openSeen(path string) (*seenStore, error) {
	s := &seenStore{path: path, ids: map[string]time.Time{}}
	err := readJSONFile(path, &s.ids)
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		// arquivo corrompido: falhar fechado (sem ele não há proteção de replay)
		return nil, err
	}
	return s, nil
}

func (s *seenStore) Has(id string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	_, ok := s.ids[id]
	return ok
}

// Add registra e grava no disco; limpa o que já venceu.
func (s *seenStore) Add(id string, until time.Time) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	now := time.Now()
	for k, t := range s.ids {
		if now.After(t) {
			delete(s.ids, k)
		}
	}
	s.ids[id] = until
	b, err := json.Marshal(s.ids)
	if err != nil {
		return err
	}
	return writeFileAtomic(s.path, b)
}
