//go:build linux
// +build linux

package hysteria2

import (
	"errors"
	"fmt"
	"os/exec"

	log "github.com/sirupsen/logrus"
)

var runPortHopCommand = func(args ...string) ([]byte, error) {
	return exec.Command("iptables", args...).CombinedOutput()
}

func portHopIptablesArgs(action string, r portHopRule) []string {
	args := []string{"-t", "nat", action, "PREROUTING", "-p", "udp"}
	if r.FromPortStart == r.FromPortEnd {
		args = append(args, "--dport", fmt.Sprintf("%d", r.FromPortStart))
	} else {
		args = append(args, "--dport", fmt.Sprintf("%d:%d", r.FromPortStart, r.FromPortEnd))
	}
	return append(args, "-j", "REDIRECT", "--to-port", fmt.Sprintf("%d", r.ToPort))
}

func mutatePortHopIptablesRule(action, operation string, r portHopRule, logger *log.Entry) error {
	out, err := runPortHopCommand(portHopIptablesArgs(action, r)...)
	if err != nil {
		ruleErr := fmt.Errorf("%s iptables port-hop rule %v: %w (output: %s)", operation, r, err, string(out))
		if logger != nil {
			logger.Error(ruleErr)
		}
		return ruleErr
	}
	if logger != nil {
		logger.Debugf("Hysteria2 port hop: %s iptables rule (%v)", operation, r)
	}
	return nil
}

func rollbackPortHopIptablesRules(action, operation string, rules []portHopRule, logger *log.Entry) error {
	var errs []error
	for i := len(rules) - 1; i >= 0; i-- {
		errs = append(errs, mutatePortHopIptablesRule(action, operation, rules[i], logger))
	}
	return errors.Join(errs...)
}

// applyPortHopIptablesRules installs iptables NAT PREROUTING rules for the
// given port ranges so that traffic to the external ports is redirected to the
// underlying Hysteria2 server port. The generated commands are intentionally
// equivalent to the manual examples provided by the user, e.g.:
//
//	iptables -t nat -A PREROUTING -p udp --dport 30001:50000 -j REDIRECT --to-port 30000
func applyPortHopIptablesRules(rules []portHopRule, logger *log.Entry) error {
	applied := make([]portHopRule, 0, len(rules))
	for _, r := range rules {
		if err := mutatePortHopIptablesRule("-A", "add", r, logger); err != nil {
			rollbackErr := rollbackPortHopIptablesRules("-D", "rollback added", applied, logger)
			return &portHopMutationError{err: errors.Join(err, rollbackErr), restored: rollbackErr == nil}
		}
		applied = append(applied, r)
	}
	return nil
}

// deletePortHopIptablesRules removes previously installed iptables rules. Each
// rule must match exactly the arguments used when it was added.
func deletePortHopIptablesRules(rules []portHopRule, logger *log.Entry) error {
	deleted := make([]portHopRule, 0, len(rules))
	for _, r := range rules {
		if err := mutatePortHopIptablesRule("-D", "delete", r, logger); err != nil {
			rollbackErr := rollbackPortHopIptablesRules("-A", "rollback deleted", deleted, logger)
			return &portHopMutationError{err: errors.Join(err, rollbackErr), restored: rollbackErr == nil}
		}
		deleted = append(deleted, r)
	}
	return nil
}
