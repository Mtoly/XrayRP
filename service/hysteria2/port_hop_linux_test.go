//go:build linux

package hysteria2

import (
	"context"
	"errors"
	"reflect"
	"testing"
)

func TestApplyPortHopIptablesRulesReturnsFailureAndRollsBackAppliedPrefix(t *testing.T) {
	commandErr := errors.New("iptables add failed")
	original := runPortHopCommand
	t.Cleanup(func() { runPortHopCommand = original })

	var calls [][]string
	runPortHopCommand = func(_ context.Context, args ...string) ([]byte, error) {
		calls = append(calls, append([]string(nil), args...))
		if args[2] == "-A" && args[7] == "31002" {
			return []byte("add failed"), commandErr
		}
		return nil, nil
	}
	rules := []portHopRule{
		{FromPortStart: 31001, FromPortEnd: 31001, ToPort: 10443},
		{FromPortStart: 31002, FromPortEnd: 31002, ToPort: 10443},
	}

	err := applyPortHopIptablesRules(context.Background(), rules, nil)
	if !errors.Is(err, commandErr) {
		t.Fatalf("applyPortHopIptablesRules() error = %v, want %v", err, commandErr)
	}
	want := [][]string{
		{"-t", "nat", "-A", "PREROUTING", "-p", "udp", "--dport", "31001", "-j", "REDIRECT", "--to-port", "10443"},
		{"-t", "nat", "-A", "PREROUTING", "-p", "udp", "--dport", "31002", "-j", "REDIRECT", "--to-port", "10443"},
		{"-t", "nat", "-D", "PREROUTING", "-p", "udp", "--dport", "31001", "-j", "REDIRECT", "--to-port", "10443"},
	}
	if !reflect.DeepEqual(calls, want) {
		t.Fatalf("iptables calls = %v, want %v", calls, want)
	}
}

func TestDeletePortHopIptablesRulesReturnsFailureAndRestoresDeletedPrefix(t *testing.T) {
	commandErr := errors.New("iptables delete failed")
	original := runPortHopCommand
	t.Cleanup(func() { runPortHopCommand = original })

	var calls [][]string
	runPortHopCommand = func(_ context.Context, args ...string) ([]byte, error) {
		calls = append(calls, append([]string(nil), args...))
		if args[2] == "-D" && args[7] == "31002" {
			return []byte("delete failed"), commandErr
		}
		return nil, nil
	}
	rules := []portHopRule{
		{FromPortStart: 31001, FromPortEnd: 31001, ToPort: 10443},
		{FromPortStart: 31002, FromPortEnd: 31002, ToPort: 10443},
	}

	err := deletePortHopIptablesRules(context.Background(), rules, nil)
	if !errors.Is(err, commandErr) || !portHopMutationRestored(err) {
		t.Fatalf("deletePortHopIptablesRules() error/restored = %v/%v, want failure with restored rules", err, portHopMutationRestored(err))
	}
	want := [][]string{
		{"-t", "nat", "-D", "PREROUTING", "-p", "udp", "--dport", "31001", "-j", "REDIRECT", "--to-port", "10443"},
		{"-t", "nat", "-D", "PREROUTING", "-p", "udp", "--dport", "31002", "-j", "REDIRECT", "--to-port", "10443"},
		{"-t", "nat", "-A", "PREROUTING", "-p", "udp", "--dport", "31001", "-j", "REDIRECT", "--to-port", "10443"},
	}
	if !reflect.DeepEqual(calls, want) {
		t.Fatalf("iptables calls = %v, want %v", calls, want)
	}
}

func TestDeletePortHopIptablesRulesReportsFailedRollback(t *testing.T) {
	deleteErr := errors.New("iptables delete failed")
	rollbackErr := errors.New("iptables rollback failed")
	original := runPortHopCommand
	t.Cleanup(func() { runPortHopCommand = original })

	runPortHopCommand = func(_ context.Context, args ...string) ([]byte, error) {
		if args[2] == "-D" && args[7] == "31002" {
			return nil, deleteErr
		}
		if args[2] == "-A" && args[7] == "31001" {
			return nil, rollbackErr
		}
		return nil, nil
	}
	rules := []portHopRule{
		{FromPortStart: 31001, FromPortEnd: 31001, ToPort: 10443},
		{FromPortStart: 31002, FromPortEnd: 31002, ToPort: 10443},
	}

	err := deletePortHopIptablesRules(context.Background(), rules, nil)
	if !errors.Is(err, deleteErr) || !errors.Is(err, rollbackErr) {
		t.Fatalf("deletePortHopIptablesRules() error = %v, want delete and rollback failures", err)
	}
	if portHopMutationRestored(err) {
		t.Fatal("deletePortHopIptablesRules() reported restored after rollback failed")
	}
}

func TestPortHopIptablesCommandHonorsCancellation(t *testing.T) {
	original := runPortHopCommand
	t.Cleanup(func() { runPortHopCommand = original })

	entered := make(chan struct{})
	returned := make(chan struct{})
	runPortHopCommand = func(ctx context.Context, _ ...string) ([]byte, error) {
		close(entered)
		<-ctx.Done()
		close(returned)
		return nil, ctx.Err()
	}

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() {
		done <- applyPortHopIptablesRules(ctx, []portHopRule{{FromPortStart: 31001, FromPortEnd: 31001, ToPort: 10443}}, nil)
	}()
	<-entered
	cancel()
	if err := <-done; !errors.Is(err, context.Canceled) {
		t.Fatalf("applyPortHopIptablesRules() error = %v, want context cancellation", err)
	}
	select {
	case <-returned:
	default:
		t.Fatal("canceled iptables command did not return")
	}
}
