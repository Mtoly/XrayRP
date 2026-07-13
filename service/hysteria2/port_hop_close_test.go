//go:build !linux

package hysteria2

import (
	"errors"
	"reflect"
	"testing"

	log "github.com/sirupsen/logrus"
)

func TestReplacePortHopRulesDoesNotClaimUnsupportedInstallation(t *testing.T) {
	originalApply, originalDelete := applyPortHopRules, deletePortHopRules
	t.Cleanup(func() {
		applyPortHopRules = originalApply
		deletePortHopRules = originalDelete
	})
	applyPortHopRules = applyPortHopIptablesRules
	deletePortHopRules = deletePortHopIptablesRules

	service := &Hysteria2Service{}
	rules := []portHopRule{{FromPortStart: 30001, FromPortEnd: 30002, ToPort: 30000}}
	restored, err := service.replacePortHopRulesLocked(rules)
	if err != nil {
		t.Fatalf("replacePortHopRulesLocked() error = %v", err)
	}
	if !restored {
		t.Fatal("unsupported platform changed the pre-call rule state")
	}
	if len(service.portHopRules) != 0 {
		t.Fatalf("unsupported installation published false ownership: %v", service.portHopRules)
	}
}

func TestCloseRemovesPortHopRulesOnce(t *testing.T) {
	original := deletePortHopRules
	defer func() { deletePortHopRules = original }()

	calls := 0
	deletePortHopRules = func(rules []portHopRule, _ *log.Entry) error {
		calls++
		if len(rules) != 1 {
			t.Fatalf("removed rules = %v, want one rule", rules)
		}
		return nil
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

func TestCloseRetainsRestoredPortHopOwnershipAndRetriesCleanup(t *testing.T) {
	deleteErr := errors.New("delete port-hop rules failed")
	original := deletePortHopRules
	t.Cleanup(func() { deletePortHopRules = original })

	rules := []portHopRule{{FromPortStart: 30001, FromPortEnd: 30002, ToPort: 30000}}
	calls := 0
	deletePortHopRules = func(got []portHopRule, _ *log.Entry) error {
		calls++
		if !reflect.DeepEqual(got, rules) {
			t.Fatalf("removed rules = %v, want %v", got, rules)
		}
		if calls == 1 {
			return deleteErr
		}
		return nil
	}
	service := &Hysteria2Service{
		state:        stateRunning,
		portHopRules: append([]portHopRule(nil), rules...),
	}

	if err := service.Close(); !errors.Is(err, deleteErr) {
		t.Fatalf("first Close() error = %v, want %v", err, deleteErr)
	}
	if !reflect.DeepEqual(service.portHopRules, rules) {
		t.Fatalf("failed delete lost restored rule ownership: %v", service.portHopRules)
	}
	if err := service.Close(); err != nil {
		t.Fatalf("second Close() error = %v", err)
	}
	if calls != 2 || len(service.portHopRules) != 0 {
		t.Fatalf("retry cleanup calls/rules = %d/%v, want 2/empty", calls, service.portHopRules)
	}
}
