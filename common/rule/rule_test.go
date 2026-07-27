package rule

import (
	"errors"
	"reflect"
	"regexp"
	"sort"
	"strconv"
	"sync"
	"testing"

	"github.com/Mtoly/XrayRP/api"
)

func TestManagerOwnsPrivateState(t *testing.T) {
	managerType := reflect.TypeOf(*New())
	for i := 0; i < managerType.NumField(); i++ {
		field := managerType.Field(i)
		if field.IsExported() {
			t.Fatalf("Manager exposes mutable field %s", field.Name)
		}
	}
}

func TestUpdateRuleOwnsCallerSlice(t *testing.T) {
	manager := New()
	rules := []api.DetectRule{{
		ID:      7,
		Pattern: regexp.MustCompile(`blocked\.example`),
	}}
	if err := manager.UpdateRule("node", rules); err != nil {
		t.Fatalf("UpdateRule() error = %v", err)
	}

	rules[0] = api.DetectRule{
		ID:      99,
		Pattern: regexp.MustCompile(`allowed\.example`),
	}

	if !manager.DetectUID("node", "blocked.example:443", 17, "192.0.2.1") {
		t.Fatal("DetectUID() did not use the owned rule snapshot")
	}
	results := drainResults(t, manager, "node")
	if len(results) != 1 || results[0].RuleID != 7 {
		t.Fatalf("drained results = %#v, want owned rule ID 7", results)
	}
}

func TestEmptyRuleSnapshotReleasesTagState(t *testing.T) {
	manager := managerWithMatchAllRule(t)
	if err := manager.UpdateRule("node", nil); err != nil {
		t.Fatalf("UpdateRule(nil) error = %v", err)
	}

	manager.rulesMu.RLock()
	_, retained := manager.rules["node"]
	manager.rulesMu.RUnlock()
	if retained {
		t.Fatal("empty rule snapshot retained private tag state")
	}
}

func TestRetireTagMovesPendingResultsAndReleasesOldState(t *testing.T) {
	manager := managerWithMatchAllRule(t)
	if !manager.DetectUID("node", "blocked.example:443", 17, "192.0.2.1") {
		t.Fatal("DetectUID() returned false before tag retirement")
	}
	if err := manager.UpdateRule("next-node", []api.DetectRule{{
		ID:      3,
		Pattern: regexp.MustCompile(`blocked\.example`),
	}}); err != nil {
		t.Fatalf("UpdateRule(next-node) error = %v", err)
	}

	manager.RetireTag("node", "next-node")

	if manager.DetectUID("node", "blocked.example:443", 18, "192.0.2.2") {
		t.Fatal("DetectUID() matched the retired tag")
	}
	results := drainResults(t, manager, "next-node")
	if len(results) != 1 || results[0].UID != 17 {
		t.Fatalf("migrated results = %#v, want pending UID 17", results)
	}
	if oldResults := drainResults(t, manager, "node"); len(oldResults) != 0 {
		t.Fatalf("retired tag retained results %#v", oldResults)
	}
}

func TestConcurrentRetireTagDoesNotLoseMatchedResults(t *testing.T) {
	manager := managerWithMatchAllRule(t)
	if err := manager.UpdateRule("next-node", []api.DetectRule{{
		ID:      3,
		Pattern: regexp.MustCompile(`blocked\.example`),
	}}); err != nil {
		t.Fatalf("UpdateRule(next-node) error = %v", err)
	}

	const writerCount = 512
	start := make(chan struct{})
	matched := make(chan bool, writerCount)
	var writers sync.WaitGroup
	writers.Add(writerCount)
	for uid := 1; uid <= writerCount; uid++ {
		uid := uid
		go func() {
			defer writers.Done()
			<-start
			matched <- manager.DetectUID("node", "blocked.example:443", uid, "192.0.2.1")
		}()
	}
	retired := make(chan struct{})
	go func() {
		<-start
		manager.RetireTag("node", "next-node")
		close(retired)
	}()

	close(start)
	writers.Wait()
	<-retired
	close(matched)

	wantResults := 0
	for didMatch := range matched {
		if didMatch {
			wantResults++
		}
	}
	results := drainResults(t, manager, "next-node")
	if len(results) != wantResults {
		t.Fatalf("migrated result count = %d, want %d matched detections", len(results), wantResults)
	}
}

func TestInvalidLegacyIdentityDoesNotFabricateUIDZero(t *testing.T) {
	manager := managerWithMatchAllRule(t)

	if !manager.Detect("node", "blocked.example:443", "node|user@example.com|invalid", "192.0.2.1") {
		t.Fatal("Detect() must still reject a matching destination")
	}
	if results := drainResults(t, manager, "node"); len(results) != 0 {
		t.Fatalf("invalid identity produced audit results %#v", results)
	}
}

func TestDetectUIDDoesNotDependOnDelimitedIdentity(t *testing.T) {
	manager := New()
	if err := manager.UpdateRule("node|with|separators", []api.DetectRule{{
		ID:      3,
		Pattern: regexp.MustCompile(`blocked\.example`),
	}}); err != nil {
		t.Fatalf("UpdateRule() error = %v", err)
	}

	if !manager.DetectUID("node|with|separators", "blocked.example:443", 0, "") {
		t.Fatal("DetectUID() returned false for a matching destination")
	}
	results := drainResults(t, manager, "node|with|separators")
	if len(results) != 1 {
		t.Fatalf("result count = %d, want 1", len(results))
	}
	if results[0] != (api.DetectResult{UID: 0, RuleID: 3}) {
		t.Fatalf("result = %#v, want explicit UID 0 with empty IP", results[0])
	}
}

func TestLegacyIdentityAllowsSeparatorsInsideEmail(t *testing.T) {
	manager := managerWithMatchAllRule(t)

	if !manager.Detect("node", "blocked.example:443", "node|mail|alias@example.com|17", "192.0.2.1") {
		t.Fatal("Detect() returned false for a matching destination")
	}
	results := drainResults(t, manager, "node")
	if len(results) != 1 || results[0].UID != 17 {
		t.Fatalf("legacy composite identity results = %#v, want UID 17", results)
	}
}

func TestDetectResultsAreDeduplicatedAndDeterministicallyOrdered(t *testing.T) {
	manager := managerWithMatchAllRule(t)

	const resultCount = 128
	for uid := resultCount; uid >= 1; uid-- {
		ip := "192.0.2." + strconv.Itoa((uid%31)+1)
		if !manager.DetectUID("node", "blocked.example:443", uid, ip) {
			t.Fatalf("DetectUID() uid %d returned false", uid)
		}
		if !manager.DetectUID("node", "blocked.example:443", uid, ip) {
			t.Fatalf("duplicate DetectUID() uid %d returned false", uid)
		}
	}

	results := drainResults(t, manager, "node")
	if len(results) != resultCount {
		t.Fatalf("result count = %d, want %d", len(results), resultCount)
	}
	if !sort.SliceIsSorted(results, func(i, j int) bool {
		if results[i].UID != results[j].UID {
			return results[i].UID < results[j].UID
		}
		if results[i].RuleID != results[j].RuleID {
			return results[i].RuleID < results[j].RuleID
		}
		return results[i].IP < results[j].IP
	}) {
		t.Fatalf("results are not deterministically ordered: %#v", results)
	}
	if remaining := drainResults(t, manager, "node"); len(remaining) != 0 {
		t.Fatalf("second drain returned stale results %#v", remaining)
	}
}

func TestDetectResultsHaveBoundedCardinality(t *testing.T) {
	manager := managerWithMatchAllRule(t)

	const maximumResultsPerTag = 64 << 10
	for uid := 1; uid <= maximumResultsPerTag+1; uid++ {
		if !manager.DetectUID("node", "blocked.example:443", uid, "192.0.2.1") {
			t.Fatalf("DetectUID() uid %d returned false", uid)
		}
	}

	results := drainResults(t, manager, "node")
	if len(results) > maximumResultsPerTag {
		t.Fatalf("result count = %d, want at most %d", len(results), maximumResultsPerTag)
	}
}

func TestConcurrentDetectAndDrainDoesNotLoseCompletedResults(t *testing.T) {
	manager := managerWithMatchAllRule(t)

	const writerCount = 512
	start := make(chan struct{})
	var writers sync.WaitGroup
	writers.Add(writerCount)
	for uid := 1; uid <= writerCount; uid++ {
		uid := uid
		go func() {
			defer writers.Done()
			<-start
			manager.DetectUID("node", "blocked.example:443", uid, "192.0.2.1")
		}()
	}

	firstDrain := make(chan asyncDrainResult, 1)
	go func() {
		<-start
		firstDrain <- drainResultsAsync(manager, "node")
	}()

	close(start)
	writers.Wait()
	first := <-firstDrain
	if first.err != nil {
		t.Fatalf("concurrent GetDetectResult() error = %v", first.err)
	}
	results := append(first.results, drainResults(t, manager, "node")...)

	seen := make(map[int]int, writerCount)
	for _, result := range results {
		seen[result.UID]++
	}
	for uid := 1; uid <= writerCount; uid++ {
		if seen[uid] != 1 {
			t.Fatalf("UID %d appeared %d times across concurrent drains", uid, seen[uid])
		}
	}
}

func TestConcurrentRuleReplacementDetectionAndDrain(t *testing.T) {
	manager := managerWithMatchAllRule(t)
	start := make(chan struct{})
	var workers sync.WaitGroup

	const workerCount = 256
	workers.Add(workerCount)
	for worker := 0; worker < workerCount; worker++ {
		worker := worker
		go func() {
			defer workers.Done()
			<-start
			switch worker % 3 {
			case 0:
				_ = manager.UpdateRule("node", []api.DetectRule{{
					ID:      worker + 1,
					Pattern: regexp.MustCompile(`blocked\.example`),
				}})
			case 1:
				_ = manager.UpdateRule("node", nil)
			default:
				manager.DetectUID("node", "blocked.example:443", worker, "192.0.2.1")
			}
		}()
	}

	drained := make(chan asyncDrainResult, 1)
	go func() {
		<-start
		drained <- drainResultsAsync(manager, "node")
	}()

	close(start)
	workers.Wait()
	if result := <-drained; result.err != nil {
		t.Fatalf("concurrent GetDetectResult() error = %v", result.err)
	}
	if err := manager.UpdateRule("node", nil); err != nil {
		t.Fatalf("UpdateRule(nil) error = %v", err)
	}
	if manager.DetectUID("node", "blocked.example:443", 17, "192.0.2.1") {
		t.Fatal("DetectUID() matched after the final empty rule snapshot")
	}
	_ = drainResults(t, manager, "node")
	if remaining := drainResults(t, manager, "node"); len(remaining) != 0 {
		t.Fatalf("second drain returned stale results %#v", remaining)
	}
}

func managerWithMatchAllRule(t *testing.T) *Manager {
	t.Helper()
	manager := New()
	if err := manager.UpdateRule("node", []api.DetectRule{{
		ID:      3,
		Pattern: regexp.MustCompile(`blocked\.example`),
	}}); err != nil {
		t.Fatalf("UpdateRule() error = %v", err)
	}
	return manager
}

func drainResults(t *testing.T, manager *Manager, tag string) []api.DetectResult {
	t.Helper()
	results, err := manager.GetDetectResult(tag)
	if err != nil {
		t.Fatalf("GetDetectResult() error = %v", err)
	}
	if results == nil {
		t.Fatal("GetDetectResult() returned nil")
	}
	return *results
}

type asyncDrainResult struct {
	results []api.DetectResult
	err     error
}

func drainResultsAsync(manager *Manager, tag string) asyncDrainResult {
	results, err := manager.GetDetectResult(tag)
	if err != nil {
		return asyncDrainResult{err: err}
	}
	if results == nil {
		return asyncDrainResult{err: errors.New("GetDetectResult returned nil")}
	}
	return asyncDrainResult{results: *results}
}
