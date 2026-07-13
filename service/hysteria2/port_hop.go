package hysteria2

import (
	"errors"
	"strconv"
	"strings"

	"github.com/Mtoly/XrayRP/api"
)

var (
	applyPortHopRules     portHopRulesFunc = applyPortHopIptablesRules
	deletePortHopRules    portHopRulesFunc = deletePortHopIptablesRules
	errPortHopUnsupported                  = errors.New("port-hop rules are unsupported on this platform")
)

type portHopMutationError struct {
	err      error
	restored bool
}

func (e *portHopMutationError) Error() string { return e.err.Error() }
func (e *portHopMutationError) Unwrap() error { return e.err }

func portHopMutationRestored(err error) bool {
	var mutationErr *portHopMutationError
	if errors.As(err, &mutationErr) {
		return mutationErr.restored
	}
	// Injected adapters must leave the pre-call state intact when returning a
	// plain error. Production Linux mutations report rollback state explicitly.
	return true
}

// replacePortHopRulesLocked replaces installed port-hop rules only after a
// replacement runtime is ready. The caller must hold reloadMu.
func (h *Hysteria2Service) replacePortHopRulesLocked(rules []portHopRule) (bool, error) {
	oldRules := append([]portHopRule(nil), h.portHopRules...)
	if len(oldRules) > 0 {
		if err := deletePortHopRules(oldRules, h.logger); err != nil {
			restored := portHopMutationRestored(err)
			if restored {
				h.portHopRules = oldRules
			} else {
				h.portHopRules = nil
			}
			return restored, err
		}
	}
	if len(rules) > 0 {
		if err := applyPortHopRules(rules, h.logger); err != nil {
			if errors.Is(err, errPortHopUnsupported) {
				h.portHopRules = nil
				return true, nil
			}
			var restoreErr error
			if len(oldRules) > 0 {
				restoreErr = applyPortHopRules(oldRules, h.logger)
			}
			if portHopMutationRestored(err) && restoreErr == nil {
				h.portHopRules = oldRules
				return true, err
			}
			h.portHopRules = nil
			return false, errors.Join(err, restoreErr)
		}
	}
	h.portHopRules = append([]portHopRule(nil), rules...)
	return true, nil
}

func (h *Hysteria2Service) cleanupPortHopRules() error {
	h.reloadMu.Lock()
	defer h.reloadMu.Unlock()
	if len(h.portHopRules) == 0 {
		return nil
	}
	err := deletePortHopRules(h.portHopRules, h.logger)
	if err == nil || !portHopMutationRestored(err) {
		h.portHopRules = nil
	}
	return err
}

// buildPortHopRulesFromNode turns the Hysteria2 port hopping configuration in
// api.NodeInfo into a concrete list of portHopRule structures that can be
// translated to iptables commands.
func buildPortHopRulesFromNode(nodeInfo *api.NodeInfo) []portHopRule {
	if nodeInfo == nil {
		return nil
	}
	if nodeInfo.Hysteria2Config == nil {
		return nil
	}
	hy := nodeInfo.Hysteria2Config
	if !hy.PortHopEnabled || hy.PortHopPorts == "" {
		return nil
	}
	if nodeInfo.Port == 0 || nodeInfo.Port > 65535 {
		return nil
	}

	return buildPortHopRules(uint16(nodeInfo.Port), hy.PortHopPorts)
}

// buildPortHopRules parses a ports expression like "30000-50000,60000" and
// produces the minimal set of REDIRECT rules needed to emulate the behavior
// described in the user's requirement:
//
//   - For each port range listed in portExpr, all ports in that range are
//     redirected to basePort, *except* basePort itself.
//
//   - The final iptables commands are equivalent to manually running, e.g.:
//
//     iptables -t nat -A PREROUTING -p udp --dport 30001:50000 -j REDIRECT --to-port 30000
//
//     when basePort = 30000 and the expression is "30000-50000".
func buildPortHopRules(basePort uint16, portsExpr string) []portHopRule {
	if portsExpr == "" {
		return nil
	}

	split := func(r rune) bool {
		return r == ',' || r == '\uff0c' || r == ' ' || r == '\t' || r == '\n' || r == '\r'
	}
	parts := strings.FieldsFunc(portsExpr, split)
	if len(parts) == 0 {
		return nil
	}

	bp := int(basePort)
	var rules []portHopRule
	for _, part := range parts {
		seg := strings.TrimSpace(part)
		if seg == "" {
			continue
		}

		var start, end int
		if dash := strings.Index(seg, "-"); dash >= 0 {
			left := strings.TrimSpace(seg[:dash])
			right := strings.TrimSpace(seg[dash+1:])
			s, err1 := strconv.Atoi(left)
			e, err2 := strconv.Atoi(right)
			if err1 != nil || err2 != nil {
				continue
			}
			start, end = s, e
		} else {
			p, err := strconv.Atoi(seg)
			if err != nil {
				continue
			}
			start, end = p, p
		}

		// Validate and normalize range.
		if start < 1 || start > 65535 || end < 1 || end > 65535 {
			continue
		}
		if start > end {
			start, end = end, start
		}

		// If basePort lies within the configured segment, split into at most two
		// ranges so that we do NOT create a rule that explicitly mentions
		// --dport basePort, matching the user's example 30001-50000 -> 30000.
		if bp >= start && bp <= end {
			if bp > start {
				rules = append(rules, portHopRule{
					FromPortStart: uint16(start),
					FromPortEnd:   uint16(bp - 1),
					ToPort:        basePort,
				})
			}
			if bp < end {
				rules = append(rules, portHopRule{
					FromPortStart: uint16(bp + 1),
					FromPortEnd:   uint16(end),
					ToPort:        basePort,
				})
			}
			continue
		}

		// Segment does not contain basePort; redirect the whole segment.
		rules = append(rules, portHopRule{
			FromPortStart: uint16(start),
			FromPortEnd:   uint16(end),
			ToPort:        basePort,
		})
	}

	return rules
}
