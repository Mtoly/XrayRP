// Package rule controls audit-rule matching and result draining.
package rule

import (
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"

	"github.com/Mtoly/XrayRP/api"
)

const maxDetectResultsPerTag = 64 << 10

type Manager struct {
	rulesMu sync.RWMutex
	rules   map[string][]api.DetectRule

	resultsMu sync.Mutex
	results   map[string]map[api.DetectResult]struct{}
}

func New() *Manager {
	return &Manager{
		rules:   make(map[string][]api.DetectRule),
		results: make(map[string]map[api.DetectResult]struct{}),
	}
}

func (r *Manager) UpdateRule(tag string, newRuleList []api.DetectRule) error {
	ownedRules := cloneRules(newRuleList)

	r.rulesMu.Lock()
	if r.rules == nil {
		r.rules = make(map[string][]api.DetectRule)
	}
	if len(ownedRules) == 0 {
		delete(r.rules, tag)
	} else {
		r.rules[tag] = ownedRules
	}
	r.rulesMu.Unlock()
	return nil
}

// GetDetectResult atomically drains one tag's deduplicated results.
func (r *Manager) GetDetectResult(tag string) (*[]api.DetectResult, error) {
	r.resultsMu.Lock()
	resultSet := r.results[tag]
	delete(r.results, tag)
	r.resultsMu.Unlock()

	detectResults := make([]api.DetectResult, 0, len(resultSet))
	for result := range resultSet {
		detectResults = append(detectResults, result)
	}
	sort.Slice(detectResults, func(i, j int) bool { return detectResultLess(detectResults[i], detectResults[j]) })
	return &detectResults, nil
}

// DetectUID matches a destination and records the explicit panel UID.
func (r *Manager) DetectUID(tag, destination string, uid int, srcIP string) bool {
	r.rulesMu.RLock()
	hitRuleID, matched := matchRules(r.rules[tag], destination)
	if !matched {
		r.rulesMu.RUnlock()
		return false
	}
	r.record(tag, api.DetectResult{UID: uid, RuleID: hitRuleID, IP: srcIP})
	r.rulesMu.RUnlock()
	return true
}

// Detect is retained as a compatibility Adapter for legacy callers that still
// carry the UID in a user key. New production paths should call DetectUID.
func (r *Manager) Detect(tag, destination, userKey, srcIP string) bool {
	uid, validIdentity := legacyUID(tag, userKey)

	r.rulesMu.RLock()
	hitRuleID, matched := matchRules(r.rules[tag], destination)
	if !matched {
		r.rulesMu.RUnlock()
		return false
	}
	if validIdentity {
		r.record(tag, api.DetectResult{UID: uid, RuleID: hitRuleID, IP: srcIP})
	}
	r.rulesMu.RUnlock()
	return true
}

func matchRules(ruleList []api.DetectRule, destination string) (int, bool) {
	for _, rule := range ruleList {
		if rule.Pattern != nil && rule.Pattern.MatchString(destination) {
			return rule.ID, true
		}
	}
	return 0, false
}

// RetireTag releases an inactive tag and moves its pending audit results to
// the replacement tag. The lock order is rulesMu then resultsMu.
func (r *Manager) RetireTag(oldTag, replacementTag string) {
	if oldTag == "" || oldTag == replacementTag {
		return
	}

	r.rulesMu.Lock()
	defer r.rulesMu.Unlock()
	r.resultsMu.Lock()
	defer r.resultsMu.Unlock()

	delete(r.rules, oldTag)
	pending := r.results[oldTag]
	delete(r.results, oldTag)
	if len(pending) == 0 || replacementTag == "" {
		return
	}

	combined := make(map[api.DetectResult]struct{}, len(pending)+len(r.results[replacementTag]))
	for result := range r.results[replacementTag] {
		combined[result] = struct{}{}
	}
	for result := range pending {
		combined[result] = struct{}{}
	}
	ordered := make([]api.DetectResult, 0, len(combined))
	for result := range combined {
		ordered = append(ordered, result)
	}
	sort.Slice(ordered, func(i, j int) bool { return detectResultLess(ordered[i], ordered[j]) })
	if len(ordered) > maxDetectResultsPerTag {
		ordered = ordered[:maxDetectResultsPerTag]
	}
	merged := make(map[api.DetectResult]struct{}, len(ordered))
	for _, result := range ordered {
		merged[result] = struct{}{}
	}
	r.results[replacementTag] = merged
}

func (r *Manager) record(tag string, result api.DetectResult) {
	r.resultsMu.Lock()
	defer r.resultsMu.Unlock()

	if r.results == nil {
		r.results = make(map[string]map[api.DetectResult]struct{})
	}
	resultSet := r.results[tag]
	if resultSet == nil {
		resultSet = make(map[api.DetectResult]struct{})
		r.results[tag] = resultSet
	}
	if _, duplicate := resultSet[result]; duplicate {
		return
	}
	if len(resultSet) >= maxDetectResultsPerTag {
		return
	}
	resultSet[result] = struct{}{}
}

func detectResultLess(left, right api.DetectResult) bool {
	if left.UID != right.UID {
		return left.UID < right.UID
	}
	if left.RuleID != right.RuleID {
		return left.RuleID < right.RuleID
	}
	return left.IP < right.IP
}

func cloneRules(rules []api.DetectRule) []api.DetectRule {
	if rules == nil {
		return nil
	}
	cloned := make([]api.DetectRule, len(rules))
	for i, rule := range rules {
		cloned[i] = api.DetectRule{
			ID:      rule.ID,
			Pattern: clonePattern(rule.Pattern),
		}
	}
	return cloned
}

func clonePattern(pattern *regexp.Regexp) *regexp.Regexp {
	if pattern == nil {
		return nil
	}
	return pattern.Copy()
}

func legacyUID(tag, userKey string) (int, bool) {
	if !strings.ContainsRune(userKey, '|') {
		uid, err := strconv.Atoi(userKey)
		return uid, err == nil
	}

	prefix := tag + "|"
	if !strings.HasPrefix(userKey, prefix) {
		return 0, false
	}
	identity := strings.TrimPrefix(userKey, prefix)
	lastSeparator := strings.LastIndexByte(identity, '|')
	if lastSeparator < 0 || lastSeparator == len(identity)-1 {
		return 0, false
	}
	uid, err := strconv.Atoi(identity[lastSeparator+1:])
	return uid, err == nil
}
