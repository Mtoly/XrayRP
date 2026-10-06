//go:build linux

package hysteria2

import (
	"context"
	"errors"
	"reflect"
	"strings"
	"testing"
)

// dportValue returns the value that follows --dport in a generated iptables
// argument list, so tests do not depend on the exact argument index.
func dportValue(t *testing.T, args []string) string {
	t.Helper()
	for i, arg := range args {
		if arg == "--dport" && i+1 < len(args) {
			return args[i+1]
		}
	}
	t.Fatalf("generated iptables args %v contain no --dport value", args)
	return ""
}

func assertLocalDestinationScope(t *testing.T, args []string) {
	t.Helper()
	joined := strings.Join(args, " ")
	for _, required := range []string{
		"PREROUTING",
		"-m addrtype",
		"--dst-type LOCAL",
		"-p udp",
		"--dport",
		"-j REDIRECT",
		"--to-port",
	} {
		if !strings.Contains(joined, required) {
			t.Fatalf("generated iptables args %v are missing %q", args, required)
		}
	}
}

func TestPortHopIptablesArgsScopesSinglePortRedirectToLocalDestinations(t *testing.T) {
	args := portHopIptablesArgs("-A", portHopRule{FromPortStart: 30001, FromPortEnd: 30001, ToPort: 30000})
	assertLocalDestinationScope(t, args)
	want := []string{
		"-t", "nat", "-A", "PREROUTING",
		"-m", "addrtype", "--dst-type", "LOCAL",
		"-p", "udp", "--dport", "30001", "-j", "REDIRECT", "--to-port", "30000",
	}
	if !reflect.DeepEqual(args, want) {
		t.Fatalf("portHopIptablesArgs() = %v, want %v", args, want)
	}
}

func TestPortHopIptablesArgsScopesPortRangeRedirectToLocalDestinations(t *testing.T) {
	args := portHopIptablesArgs("-A", portHopRule{FromPortStart: 30001, FromPortEnd: 50000, ToPort: 30000})
	assertLocalDestinationScope(t, args)
	if got := dportValue(t, args); got != "30001:50000" {
		t.Fatalf("port range --dport = %q, want %q", got, "30001:50000")
	}
}

// add, delete and both rollback directions must build the identical rule
// specification; only the iptables action may differ.
func TestPortHopIptablesArgsDifferOnlyByAction(t *testing.T) {
	rule := portHopRule{FromPortStart: 30001, FromPortEnd: 50000, ToPort: 30000}
	add := portHopIptablesArgs("-A", rule)
	del := portHopIptablesArgs("-D", rule)
	if add[2] != "-A" || del[2] != "-D" {
		t.Fatalf("actions = %q/%q, want -A/-D", add[2], del[2])
	}
	add[2] = "ACTION"
	del[2] = "ACTION"
	if !reflect.DeepEqual(add, del) {
		t.Fatalf("add/delete rule specifications differ beyond the action: %v vs %v", add, del)
	}
	assertLocalDestinationScope(t, add)
}

func TestApplyPortHopIptablesRulesReturnsFailureAndRollsBackAppliedPrefix(t *testing.T) {
	commandErr := errors.New("iptables add failed")
	original := runPortHopCommand
	t.Cleanup(func() { runPortHopCommand = original })

	var calls [][]string
	runPortHopCommand = func(_ context.Context, args ...string) ([]byte, error) {
		calls = append(calls, append([]string(nil), args...))
		if args[2] == "-A" && dportValue(t, args) == "31002" {
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
		{"-t", "nat", "-A", "PREROUTING", "-m", "addrtype", "--dst-type", "LOCAL", "-p", "udp", "--dport", "31001", "-j", "REDIRECT", "--to-port", "10443"},
		{"-t", "nat", "-A", "PREROUTING", "-m", "addrtype", "--dst-type", "LOCAL", "-p", "udp", "--dport", "31002", "-j", "REDIRECT", "--to-port", "10443"},
		{"-t", "nat", "-D", "PREROUTING", "-m", "addrtype", "--dst-type", "LOCAL", "-p", "udp", "--dport", "31001", "-j", "REDIRECT", "--to-port", "10443"},
	}
	if !reflect.DeepEqual(calls, want) {
		t.Fatalf("iptables calls = %v, want %v", calls, want)
	}
	for _, call := range calls {
		assertLocalDestinationScope(t, call)
	}
}

func TestDeletePortHopIptablesRulesReturnsFailureAndRestoresDeletedPrefix(t *testing.T) {
	commandErr := errors.New("iptables delete failed")
	original := runPortHopCommand
	t.Cleanup(func() { runPortHopCommand = original })

	var calls [][]string
	runPortHopCommand = func(_ context.Context, args ...string) ([]byte, error) {
		calls = append(calls, append([]string(nil), args...))
		if args[2] == "-D" && dportValue(t, args) == "31002" {
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
		{"-t", "nat", "-D", "PREROUTING", "-m", "addrtype", "--dst-type", "LOCAL", "-p", "udp", "--dport", "31001", "-j", "REDIRECT", "--to-port", "10443"},
		{"-t", "nat", "-D", "PREROUTING", "-m", "addrtype", "--dst-type", "LOCAL", "-p", "udp", "--dport", "31002", "-j", "REDIRECT", "--to-port", "10443"},
		{"-t", "nat", "-A", "PREROUTING", "-m", "addrtype", "--dst-type", "LOCAL", "-p", "udp", "--dport", "31001", "-j", "REDIRECT", "--to-port", "10443"},
	}
	if !reflect.DeepEqual(calls, want) {
		t.Fatalf("iptables calls = %v, want %v", calls, want)
	}
	for _, call := range calls {
		assertLocalDestinationScope(t, call)
	}
}

func TestDeletePortHopIptablesRulesReportsFailedRollback(t *testing.T) {
	deleteErr := errors.New("iptables delete failed")
	rollbackErr := errors.New("iptables rollback failed")
	original := runPortHopCommand
	t.Cleanup(func() { runPortHopCommand = original })

	runPortHopCommand = func(_ context.Context, args ...string) ([]byte, error) {
		if args[2] == "-D" && dportValue(t, args) == "31002" {
			return nil, deleteErr
		}
		if args[2] == "-A" && dportValue(t, args) == "31001" {
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
