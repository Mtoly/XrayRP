//go:build !linux
// +build !linux

package hysteria2

import (
	"context"
	log "github.com/sirupsen/logrus"
)

// On non-Linux platforms there is no iptables binary. We simply log and skip
// installing rules so that the core Hysteria2 service can still run.

func applyPortHopIptablesRules(ctx context.Context, rules []portHopRule, logger *log.Entry) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if len(rules) > 0 {
		if logger != nil {
			logger.Warn("Hysteria2 port hop: iptables is only supported on Linux; skipping port hop rules on this platform")
		}
		return errPortHopUnsupported
	}
	return nil
}

func deletePortHopIptablesRules(ctx context.Context, rules []portHopRule, logger *log.Entry) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	// nothing to do on non-Linux platforms
	return nil
}
