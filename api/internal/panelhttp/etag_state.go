package panelhttp

import "sync"

// ETagState owns concurrent access to successfully applied Panel ETags.
// Its zero value is ready for use.
type ETagState struct {
	mu     sync.RWMutex
	values map[string]string
}

func (s *ETagState) Get(key string) string {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.values[key]
}

func (s *ETagState) Publish(key, candidate string) {
	if candidate == "" {
		return
	}

	s.mu.Lock()
	defer s.mu.Unlock()
	if s.values == nil {
		s.values = make(map[string]string)
	}
	s.values[key] = candidate
}
