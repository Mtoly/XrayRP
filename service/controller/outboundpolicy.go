package controller

import (
	"context"
	"fmt"
	"strings"

	"github.com/xtls/xray-core/features/outbound"

	"github.com/Mtoly/XrayRP/api"
)

type runtimeRoutingSelector struct {
	baseTag     string
	baseHandler outbound.Handler
	routePolicy *api.PanelRoutePolicy
	obm         outbound.Manager
}

func (s runtimeRoutingSelector) resolveTagToHandler(tag string) (outbound.Handler, bool) {
	if tag == "" {
		return nil, false
	}
	if tag == s.baseTag {
		return s.baseHandler, true
	}
	if isXrayRManagedTag(tag) && tag != s.baseTag {
		return nil, false
	}
	if s.obm != nil {
		if handler := s.obm.GetHandler(tag); handler != nil {
			return handler, true
		}
	}
	if strings.EqualFold(tag, "direct") {
		return s.baseHandler, true
	}
	return nil, false
}

func (s runtimeRoutingSelector) selectHandler(_ context.Context) (outbound.Handler, error) {
	candidates := []string{s.baseTag}
	if s.routePolicy != nil && len(s.routePolicy.Outbound.Candidates) > 0 {
		candidates = append([]string(nil), s.routePolicy.Outbound.Candidates...)
	}
	tags, err := selectOutboundCandidates(candidates, s.routePolicy)
	if err != nil {
		return nil, err
	}
	if len(tags) == 0 {
		tags = []string{s.baseTag}
	}
	for _, tag := range tags {
		if handler, ok := s.resolveTagToHandler(tag); ok {
			return handler, nil
		}
	}
	return nil, fmt.Errorf("no outbound handler available for selected tags: %v", tags)
}

func selectOutboundCandidates(candidates []string, policy *api.PanelRoutePolicy) ([]string, error) {
	if len(candidates) == 0 {
		return nil, fmt.Errorf("no outbound candidates configured")
	}
	if policy == nil {
		return candidates, nil
	}

	filtered := applyInclude(candidates, policy.Outbound.Include)
	filtered = applyExclude(filtered, policy.Outbound.Exclude)
	if len(filtered) > 0 {
		return filtered, nil
	}

	fallback := resolveFallback(candidates, policy.Outbound.Fallback)
	if len(fallback) == 0 {
		return nil, fmt.Errorf("no outbound candidates remain after include/exclude and fallback")
	}
	return fallback, nil
}

func applyInclude(candidates []string, include []string) []string {
	if len(include) == 0 {
		return append([]string(nil), candidates...)
	}
	filtered := make([]string, 0, len(candidates))
	for _, candidate := range candidates {
		if matchesAnyPattern(candidate, include) {
			filtered = append(filtered, candidate)
		}
	}
	return filtered
}

func applyExclude(candidates []string, exclude []string) []string {
	if len(exclude) == 0 {
		return append([]string(nil), candidates...)
	}
	filtered := make([]string, 0, len(candidates))
	for _, candidate := range candidates {
		if !matchesAnyPattern(candidate, exclude) {
			filtered = append(filtered, candidate)
		}
	}
	return filtered
}

func resolveFallback(candidates []string, fallback []string) []string {
	if len(fallback) == 0 {
		return nil
	}
	resolved := make([]string, 0, len(fallback))
	for _, rule := range fallback {
		for _, candidate := range candidates {
			if candidate == rule {
				resolved = append(resolved, candidate)
				break
			}
		}
	}
	return dedupePreserveOrder(resolved)
}

func matchesAnyPattern(candidate string, patterns []string) bool {
	for _, pattern := range patterns {
		if pattern == "" {
			continue
		}
		if candidate == pattern || strings.HasPrefix(candidate, pattern) || strings.Contains(candidate, pattern) {
			return true
		}
	}
	return false
}

func dedupePreserveOrder(items []string) []string {
	seen := make(map[string]struct{}, len(items))
	result := make([]string, 0, len(items))
	for _, item := range items {
		if _, ok := seen[item]; ok {
			continue
		}
		seen[item] = struct{}{}
		result = append(result, item)
	}
	return result
}
