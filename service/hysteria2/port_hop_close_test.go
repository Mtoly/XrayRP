//go:build !linux

package hysteria2

import (
	"testing"

	log "github.com/sirupsen/logrus"
)

func TestCloseRemovesPortHopRulesOnce(t *testing.T) {
	original := deletePortHopRules
	defer func() { deletePortHopRules = original }()

	calls := 0
	deletePortHopRules = func(rules []portHopRule, _ *log.Entry) {
		calls++
		if len(rules) != 1 {
			t.Fatalf("removed rules = %v, want one rule", rules)
		}
	}
	service := &Hysteria2Service{
		state: stateRunning,
		portHopRules: []portHopRule{{
			FromPortStart: 30001,
			FromPortEnd:   30002,
			ToPort:        30000,
		}},
	}

	if err := service.Close(); err != nil {
		t.Fatalf("first Close() error = %v", err)
	}
	if err := service.Close(); err != nil {
		t.Fatalf("second Close() error = %v", err)
	}
	if calls != 1 {
		t.Fatalf("port-hop remove calls = %d, want 1", calls)
	}
}
