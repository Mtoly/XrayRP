package limiter

import (
	"context"
	"errors"
	"fmt"
	"reflect"
	"sync"
	"testing"
	"time"

	"github.com/Mtoly/XrayRP/api"
	"github.com/xtls/xray-core/common/buf"
	"golang.org/x/time/rate"
)

func TestReplaceInboundUsersRemovesStalePolicy(t *testing.T) {
	limiter := New()
	users := []api.UserInfo{
		{UID: 1, Email: "kept@example.test", SpeedLimit: 100},
		{UID: 2, Email: "removed@example.test", SpeedLimit: 200},
	}
	if err := limiter.AddInboundLimiter("inbound", 0, &users, nil); err != nil {
		t.Fatalf("AddInboundLimiter() error = %v", err)
	}

	removedKey := "inbound|removed@example.test|2"
	if bucket, speedLimited, rejected := limiter.getUserBucket("inbound", removedKey, "192.0.2.2"); rejected || !speedLimited || bucket == nil {
		t.Fatalf("initial removed-user policy = bucket:%v speedLimited:%v rejected:%v", bucket, speedLimited, rejected)
	}

	replacement := []api.UserInfo{{UID: 1, Email: "kept@example.test", SpeedLimit: 100}}
	if err := limiter.ReplaceInboundUsers("inbound", &replacement); err != nil {
		t.Fatalf("ReplaceInboundUsers() error = %v", err)
	}

	if bucket, speedLimited, rejected := limiter.getUserBucket("inbound", removedKey, "198.51.100.2"); !rejected || speedLimited || bucket != nil {
		t.Fatalf("stale removed-user policy = bucket:%v speedLimited:%v rejected:%v", bucket, speedLimited, rejected)
	}
}

func TestReplaceInboundUsersRemovesStaleOnlineDevices(t *testing.T) {
	limiter := New()
	users := []api.UserInfo{
		{UID: 1, Email: "kept@example.test"},
		{UID: 2, Email: "removed@example.test"},
	}
	if err := limiter.AddInboundLimiter("inbound", 0, &users, nil); err != nil {
		t.Fatalf("AddInboundLimiter() error = %v", err)
	}
	if _, _, rejected := limiter.getUserBucket("inbound", "inbound|kept@example.test|1", "192.0.2.1"); rejected {
		t.Fatal("kept user was rejected")
	}
	if _, _, rejected := limiter.getUserBucket("inbound", "inbound|removed@example.test|2", "192.0.2.2"); rejected {
		t.Fatal("removed user was rejected")
	}

	replacement := []api.UserInfo{{UID: 1, Email: "kept@example.test"}}
	if err := limiter.ReplaceInboundUsers("inbound", &replacement); err != nil {
		t.Fatalf("ReplaceInboundUsers() error = %v", err)
	}

	online, err := limiter.GetOnlineDevice("inbound")
	if err != nil {
		t.Fatalf("GetOnlineDevice() error = %v", err)
	}
	if len(*online) != 1 || (*online)[0].UID != 1 || (*online)[0].IP != "192.0.2.1" {
		t.Fatalf("online devices after replacement = %#v, want only kept user", *online)
	}
}

func TestLimiterOnlyExportsLegacyCompatibilityState(t *testing.T) {
	typeOfLimiter := reflect.TypeOf(Limiter{})
	for index := 0; index < typeOfLimiter.NumField(); index++ {
		field := typeOfLimiter.Field(index)
		if field.IsExported() && field.Name != "InboundInfo" {
			t.Fatalf("Limiter exposes mutable field %s", field.Name)
		}
	}
}

func TestCloseIsIdempotentAndRejectsConfigurationMutations(t *testing.T) {
	limiter := New()
	users := []api.UserInfo{{UID: 1, Email: "user@example.test"}}
	if err := limiter.AddInboundLimiter("inbound", 0, &users, nil); err != nil {
		t.Fatalf("AddInboundLimiter() error = %v", err)
	}

	if err := limiter.Close(); err != nil {
		t.Fatalf("first Close() error = %v", err)
	}
	if err := limiter.Close(); err != nil {
		t.Fatalf("second Close() error = %v", err)
	}

	mutations := []struct {
		name string
		run  func() error
	}{
		{name: "add", run: func() error { return limiter.AddInboundLimiter("new", 0, &users, nil) }},
		{name: "update", run: func() error { return limiter.UpdateInboundLimiter("inbound", &users) }},
		{name: "replace", run: func() error { return limiter.ReplaceInboundUsers("inbound", &users) }},
		{name: "delete", run: func() error { return limiter.DeleteInboundLimiter("inbound") }},
	}
	for _, mutation := range mutations {
		t.Run(mutation.name, func(t *testing.T) {
			if err := mutation.run(); err == nil {
				t.Fatal("mutation after Close() error = nil")
			}
		})
	}
}

type countingCloser struct {
	calls int
}

func (c *countingCloser) Close() error {
	c.calls++
	return nil
}

type failingCloser struct {
	calls int
	err   error
}

func (c *failingCloser) Close() error {
	c.calls++
	return c.err
}

func TestCommittedReplacementDefersOldBackendCleanupErrorUntilClose(t *testing.T) {
	cleanupErr := errors.New("old backend cleanup failed")
	oldCloser := &failingCloser{err: cleanupErr}
	newCloser := &countingCloser{}
	builds := 0
	limiter := New()
	limiter.buildGlobalLimitBackend = func(*GlobalDeviceLimitConfig) globalLimitBackend {
		builds++
		if builds == 1 {
			return globalLimitBackend{closer: oldCloser}
		}
		return globalLimitBackend{closer: newCloser}
	}
	users := []api.UserInfo{{UID: 1, Email: "user@example.test"}}
	config := &GlobalDeviceLimitConfig{Enable: true}
	if err := limiter.AddInboundLimiter("inbound", 0, &users, config); err != nil {
		t.Fatalf("first AddInboundLimiter() error = %v", err)
	}
	if err := limiter.AddInboundLimiter("inbound", 0, &users, config); err != nil {
		t.Fatalf("committed replacement reported cleanup failure as apply failure: %v", err)
	}
	if oldCloser.calls != 1 {
		t.Fatalf("old backend Close() calls = %d, want 1", oldCloser.calls)
	}
	if _, _, rejected := limiter.Admit("inbound", "inbound|user@example.test|1", "192.0.2.1", nil, nil); rejected {
		t.Fatal("published replacement rejected admission")
	}
	if err := limiter.Close(); !errors.Is(err, cleanupErr) {
		t.Fatalf("Close() error = %v, want deferred cleanup error", err)
	}
	if newCloser.calls != 1 {
		t.Fatalf("replacement backend Close() calls = %d, want 1", newCloser.calls)
	}
}

func TestCommittedDeleteDefersBackendCleanupErrorUntilClose(t *testing.T) {
	cleanupErr := errors.New("deleted backend cleanup failed")
	closer := &failingCloser{err: cleanupErr}
	limiter := New()
	limiter.buildGlobalLimitBackend = func(*GlobalDeviceLimitConfig) globalLimitBackend {
		return globalLimitBackend{closer: closer}
	}
	users := []api.UserInfo{{UID: 1, Email: "user@example.test"}}
	config := &GlobalDeviceLimitConfig{Enable: true}
	if err := limiter.AddInboundLimiter("inbound", 0, &users, config); err != nil {
		t.Fatalf("AddInboundLimiter() error = %v", err)
	}
	if err := limiter.DeleteInboundLimiter("inbound"); err != nil {
		t.Fatalf("committed delete reported cleanup failure as apply failure: %v", err)
	}
	if closer.calls != 1 {
		t.Fatalf("deleted backend Close() calls = %d, want 1", closer.calls)
	}
	if _, _, rejected := limiter.Admit("inbound", "inbound|user@example.test|1", "192.0.2.1", nil, nil); !rejected {
		t.Fatal("deleted inbound still accepted admission")
	}
	if err := limiter.Close(); !errors.Is(err, cleanupErr) {
		t.Fatalf("Close() error = %v, want deferred cleanup error", err)
	}
}
func TestCloseClosesOwnedGlobalLimitBackendOnce(t *testing.T) {
	closer := &countingCloser{}
	limiter := New()
	limiter.buildGlobalLimitBackend = func(*GlobalDeviceLimitConfig) globalLimitBackend {
		return globalLimitBackend{closer: closer}
	}
	users := []api.UserInfo{{UID: 1, Email: "user@example.test"}}
	config := &GlobalDeviceLimitConfig{Enable: true}
	if err := limiter.AddInboundLimiter("inbound", 0, &users, config); err != nil {
		t.Fatalf("AddInboundLimiter() error = %v", err)
	}
	if err := limiter.Close(); err != nil {
		t.Fatalf("first Close() error = %v", err)
	}
	if err := limiter.Close(); err != nil {
		t.Fatalf("second Close() error = %v", err)
	}
	if closer.calls != 1 {
		t.Fatalf("global limit backend Close() calls = %d, want 1", closer.calls)
	}
}

func TestReplacingAndDeletingInboundCloseOwnedBackends(t *testing.T) {
	var closers []*countingCloser
	limiter := New()
	limiter.buildGlobalLimitBackend = func(*GlobalDeviceLimitConfig) globalLimitBackend {
		closer := &countingCloser{}
		closers = append(closers, closer)
		return globalLimitBackend{closer: closer}
	}
	users := []api.UserInfo{{UID: 1, Email: "user@example.test"}}
	config := &GlobalDeviceLimitConfig{Enable: true}
	if err := limiter.AddInboundLimiter("inbound", 0, &users, config); err != nil {
		t.Fatalf("first AddInboundLimiter() error = %v", err)
	}
	if err := limiter.AddInboundLimiter("inbound", 0, &users, config); err != nil {
		t.Fatalf("replacement AddInboundLimiter() error = %v", err)
	}
	if len(closers) != 2 || closers[0].calls != 1 || closers[1].calls != 0 {
		t.Fatalf("backend closes after replacement = %#v", []int{closers[0].calls, closers[1].calls})
	}

	if err := limiter.DeleteInboundLimiter("inbound"); err != nil {
		t.Fatalf("DeleteInboundLimiter() error = %v", err)
	}
	if closers[1].calls != 1 {
		t.Fatalf("replacement backend Close() calls after delete = %d, want 1", closers[1].calls)
	}
	if err := limiter.Close(); err != nil {
		t.Fatalf("Close() error = %v", err)
	}
	if closers[0].calls != 1 || closers[1].calls != 1 {
		t.Fatalf("backend closes after final Close() = %#v, want [1 1]", []int{closers[0].calls, closers[1].calls})
	}
}

func TestGetUserBucketRejectsAdmissionAfterClose(t *testing.T) {
	limiter := New()
	users := []api.UserInfo{{UID: 1, Email: "user@example.test", SpeedLimit: 100, DeviceLimit: 1}}
	if err := limiter.AddInboundLimiter("inbound", 0, &users, nil); err != nil {
		t.Fatalf("AddInboundLimiter() error = %v", err)
	}
	if err := limiter.Close(); err != nil {
		t.Fatalf("Close() error = %v", err)
	}

	if bucket, speedLimited, rejected := limiter.getUserBucket("inbound", "inbound|user@example.test|1", "192.0.2.1"); !rejected || speedLimited || bucket != nil {
		t.Fatalf("admission after Close() = bucket:%v speedLimited:%v rejected:%v", bucket, speedLimited, rejected)
	}
}

func TestRestoreSnapshotAfterCandidateDeletionRebuildsClosedBackend(t *testing.T) {
	var closers []*countingCloser
	limiter := New()
	limiter.buildGlobalLimitBackend = func(*GlobalDeviceLimitConfig) globalLimitBackend {
		closer := &countingCloser{}
		closers = append(closers, closer)
		return globalLimitBackend{closer: closer}
	}
	config := &GlobalDeviceLimitConfig{Enable: true}
	appliedUsers := []api.UserInfo{{UID: 1, Email: "applied@example.test"}}
	if err := limiter.AddInboundLimiter("inbound", 0, &appliedUsers, config); err != nil {
		t.Fatalf("applied AddInboundLimiter() error = %v", err)
	}
	snapshot, err := limiter.SnapshotInboundLimiterState("inbound")
	if err != nil {
		t.Fatalf("SnapshotInboundLimiterState() error = %v", err)
	}

	candidateUsers := []api.UserInfo{{UID: 2, Email: "candidate@example.test"}}
	if err := limiter.AddInboundLimiter("inbound", 0, &candidateUsers, config); err != nil {
		t.Fatalf("candidate AddInboundLimiter() error = %v", err)
	}
	if err := limiter.DeleteInboundLimiter("inbound"); err != nil {
		t.Fatalf("DeleteInboundLimiter() error = %v", err)
	}
	if err := limiter.RestoreInboundLimiterState("inbound", snapshot); err != nil {
		t.Fatalf("RestoreInboundLimiterState() error = %v", err)
	}
	if len(closers) != 3 {
		t.Fatalf("backend builds = %d, want applied, candidate, and restored", len(closers))
	}
	if _, _, rejected := limiter.Admit("inbound", "inbound|applied@example.test|1", "192.0.2.1", nil, nil); rejected {
		t.Fatal("restored applied user was rejected")
	}
	if _, _, rejected := limiter.Admit("inbound", "inbound|candidate@example.test|2", "192.0.2.2", nil, nil); !rejected {
		t.Fatal("deleted candidate user was admitted after restore")
	}
	if err := limiter.Close(); err != nil {
		t.Fatalf("Close() error = %v", err)
	}
	if closers[2].calls != 1 {
		t.Fatalf("restored backend Close() calls = %d, want 1", closers[2].calls)
	}
}

func TestRestoreInboundLimiterStateReturnsCandidateCleanupFailure(t *testing.T) {
	cleanupErr := errors.New("candidate backend cleanup failed")
	appliedCloser := &countingCloser{}
	candidateCloser := &failingCloser{err: cleanupErr}
	restoredCloser := &countingCloser{}
	builds := 0
	limiter := New()
	limiter.buildGlobalLimitBackend = func(*GlobalDeviceLimitConfig) globalLimitBackend {
		builds++
		switch builds {
		case 1:
			return globalLimitBackend{closer: appliedCloser}
		case 2:
			return globalLimitBackend{closer: candidateCloser}
		default:
			return globalLimitBackend{closer: restoredCloser}
		}
	}
	config := &GlobalDeviceLimitConfig{Enable: true}
	appliedUsers := []api.UserInfo{{UID: 1, Email: "applied@example.test"}}
	if err := limiter.AddInboundLimiter("inbound", 0, &appliedUsers, config); err != nil {
		t.Fatalf("applied AddInboundLimiter() error = %v", err)
	}
	snapshot, err := limiter.SnapshotInboundLimiterState("inbound")
	if err != nil {
		t.Fatalf("SnapshotInboundLimiterState() error = %v", err)
	}
	candidateUsers := []api.UserInfo{{UID: 2, Email: "candidate@example.test"}}
	if err := limiter.AddInboundLimiter("inbound", 0, &candidateUsers, config); err != nil {
		t.Fatalf("candidate AddInboundLimiter() error = %v", err)
	}

	err = limiter.RestoreInboundLimiterState("inbound", snapshot)
	if !errors.Is(err, cleanupErr) {
		t.Fatalf("RestoreInboundLimiterState() error = %v, want %v", err, cleanupErr)
	}
	if _, _, rejected := limiter.Admit("inbound", "inbound|applied@example.test|1", "192.0.2.1", nil, nil); rejected {
		t.Fatal("candidate cleanup failure left the applied user unavailable")
	}
	if _, _, rejected := limiter.Admit("inbound", "inbound|candidate@example.test|2", "192.0.2.2", nil, nil); !rejected {
		t.Fatal("candidate cleanup failure left the candidate user published")
	}
	if err := limiter.Close(); !errors.Is(err, cleanupErr) {
		t.Fatalf("Close() error = %v, want deferred cleanup error %v", err, cleanupErr)
	}
	if appliedCloser.calls != 1 || candidateCloser.calls != 1 || restoredCloser.calls != 1 {
		t.Fatalf(
			"backend Close() calls = applied:%d candidate:%d restored:%d, want 1/1/1",
			appliedCloser.calls,
			candidateCloser.calls,
			restoredCloser.calls,
		)
	}
}

func TestInboundLimiterSnapshotOnlyExportsCompatibilityCopies(t *testing.T) {
	typeOfSnapshot := reflect.TypeOf(InboundLimiterStateSnapshot{})
	for index := 0; index < typeOfSnapshot.NumField(); index++ {
		field := typeOfSnapshot.Field(index)
		if field.IsExported() && field.Name != "UserInfo" && field.Name != "Buckets" {
			t.Fatalf("InboundLimiterStateSnapshot exposes mutable field %s", field.Name)
		}
	}
}

func TestRestoreInboundLimiterStateReinstatesExactAppliedState(t *testing.T) {
	limiter := New()
	users := []api.UserInfo{
		{UID: 1, Email: "kept@example.test", SpeedLimit: 100},
		{UID: 2, Email: "removed@example.test", SpeedLimit: 200},
	}
	if err := limiter.AddInboundLimiter("inbound", 0, &users, nil); err != nil {
		t.Fatalf("AddInboundLimiter() error = %v", err)
	}
	removedKey := "inbound|removed@example.test|2"
	originalBucket, speedLimited, rejected := limiter.getUserBucket("inbound", removedKey, "192.0.2.2")
	if rejected || !speedLimited || originalBucket == nil {
		t.Fatalf("initial admission = bucket:%v speedLimited:%v rejected:%v", originalBucket, speedLimited, rejected)
	}
	originalValue, _ := limiter.InboundInfo.Load("inbound")
	originalState := originalValue.(*inboundState)

	snapshot, err := limiter.SnapshotInboundLimiterState("inbound")
	if err != nil {
		t.Fatalf("SnapshotInboundLimiterState() error = %v", err)
	}
	replacement := []api.UserInfo{{UID: 1, Email: "kept@example.test", SpeedLimit: 300}}
	if err := limiter.ReplaceInboundUsers("inbound", &replacement); err != nil {
		t.Fatalf("ReplaceInboundUsers() error = %v", err)
	}
	if err := limiter.RestoreInboundLimiterState("inbound", snapshot); err != nil {
		t.Fatalf("RestoreInboundLimiterState() error = %v", err)
	}

	restoredValue, _ := limiter.InboundInfo.Load("inbound")
	if restoredValue != originalState {
		t.Fatal("restore did not republish the exact applied inbound generation")
	}
	restoredBucket, speedLimited, rejected := limiter.getUserBucket("inbound", removedKey, "192.0.2.2")
	if rejected || !speedLimited || restoredBucket != originalBucket {
		t.Fatalf("restored admission = bucket:%v speedLimited:%v rejected:%v, want original bucket", restoredBucket, speedLimited, rejected)
	}
	online, err := limiter.GetOnlineDevice("inbound")
	if err != nil {
		t.Fatalf("GetOnlineDevice() error = %v", err)
	}
	if len(*online) != 1 || (*online)[0].UID != 2 || (*online)[0].IP != "192.0.2.2" {
		t.Fatalf("restored online devices = %#v, want removed user's applied device", *online)
	}
}

func TestRestoreAfterPartialUpdateRemovesCandidateOnlineState(t *testing.T) {
	limiter := New()
	appliedUsers := []api.UserInfo{{UID: 1, Email: "applied@example.test"}}
	if err := limiter.AddInboundLimiter("inbound", 0, &appliedUsers, nil); err != nil {
		t.Fatalf("AddInboundLimiter() error = %v", err)
	}
	snapshot, err := limiter.SnapshotInboundLimiterState("inbound")
	if err != nil {
		t.Fatalf("SnapshotInboundLimiterState() error = %v", err)
	}

	candidateUsers := []api.UserInfo{{UID: 2, Email: "candidate@example.test"}}
	if err := limiter.UpdateInboundLimiter("inbound", &candidateUsers); err != nil {
		t.Fatalf("UpdateInboundLimiter() error = %v", err)
	}
	candidateKey := "inbound|candidate@example.test|2"
	if _, _, rejected := limiter.Admit("inbound", candidateKey, "192.0.2.2", nil, nil); rejected {
		t.Fatal("candidate user was not admitted before restore")
	}

	if err := limiter.RestoreInboundLimiterState("inbound", snapshot); err != nil {
		t.Fatalf("RestoreInboundLimiterState() error = %v", err)
	}
	if _, _, rejected := limiter.Admit("inbound", candidateKey, "198.51.100.2", nil, nil); !rejected {
		t.Fatal("restored applied generation admitted a candidate-only user")
	}
	online, err := limiter.GetOnlineDevice("inbound")
	if err != nil {
		t.Fatalf("GetOnlineDevice() error = %v", err)
	}
	for _, user := range *online {
		if user.UID == 2 {
			t.Fatalf("restored applied generation retained candidate online state: %#v", *online)
		}
	}
}

func TestRestoreSnapshotAfterMultiplePartialUpdates(t *testing.T) {
	limiter := New()
	appliedUsers := []api.UserInfo{
		{UID: 1, Email: "one@example.test", SpeedLimit: 100},
		{UID: 2, Email: "two@example.test", SpeedLimit: 200},
	}
	if err := limiter.AddInboundLimiter("inbound", 0, &appliedUsers, nil); err != nil {
		t.Fatalf("AddInboundLimiter() error = %v", err)
	}
	oneKey := "inbound|one@example.test|1"
	twoKey := "inbound|two@example.test|2"
	oneBucket, _, _ := limiter.getUserBucket("inbound", oneKey, "192.0.2.1")
	twoBucket, _, _ := limiter.getUserBucket("inbound", twoKey, "192.0.2.2")
	snapshot, err := limiter.SnapshotInboundLimiterState("inbound")
	if err != nil {
		t.Fatalf("SnapshotInboundLimiterState() error = %v", err)
	}

	if err := limiter.UpdateInboundLimiter("inbound", &[]api.UserInfo{{
		UID: 1, Email: "one@example.test", SpeedLimit: 300,
	}}); err != nil {
		t.Fatalf("first UpdateInboundLimiter() error = %v", err)
	}
	if err := limiter.UpdateInboundLimiter("inbound", &[]api.UserInfo{{
		UID: 2, Email: "two@example.test", SpeedLimit: 400,
	}}); err != nil {
		t.Fatalf("second UpdateInboundLimiter() error = %v", err)
	}
	candidate := api.UserInfo{UID: 3, Email: "candidate@example.test", SpeedLimit: 500}
	if err := limiter.UpdateInboundLimiter("inbound", &[]api.UserInfo{candidate}); err != nil {
		t.Fatalf("candidate UpdateInboundLimiter() error = %v", err)
	}
	candidateKey := "inbound|candidate@example.test|3"
	if _, _, rejected := limiter.Admit("inbound", candidateKey, "192.0.2.3", nil, nil); rejected {
		t.Fatal("candidate user was rejected before rollback")
	}

	if err := limiter.RestoreInboundLimiterState("inbound", snapshot); err != nil {
		t.Fatalf("RestoreInboundLimiterState() error = %v", err)
	}
	restoredOne, _, rejected := limiter.getUserBucket("inbound", oneKey, "192.0.2.1")
	if rejected || restoredOne != oneBucket {
		t.Fatal("first applied bucket was not restored exactly")
	}
	restoredTwo, _, rejected := limiter.getUserBucket("inbound", twoKey, "192.0.2.2")
	if rejected || restoredTwo != twoBucket {
		t.Fatal("second applied bucket was not restored exactly")
	}
	if _, _, rejected := limiter.Admit("inbound", candidateKey, "198.51.100.3", nil, nil); !rejected {
		t.Fatal("candidate-only user remained admitted after rollback")
	}
}

func TestRestoreSnapshotPreservesCompatibleBucketCreatedAfterSnapshot(t *testing.T) {
	limiter := New()
	users := []api.UserInfo{
		{UID: 1, Email: "one@example.test", SpeedLimit: 100},
		{UID: 2, Email: "two@example.test", SpeedLimit: 200},
	}
	if err := limiter.AddInboundLimiter("inbound", 0, &users, nil); err != nil {
		t.Fatalf("AddInboundLimiter() error = %v", err)
	}
	snapshot, err := limiter.SnapshotInboundLimiterState("inbound")
	if err != nil {
		t.Fatalf("SnapshotInboundLimiterState() error = %v", err)
	}
	oneKey := "inbound|one@example.test|1"
	createdAfterSnapshot, _, rejected := limiter.getUserBucket("inbound", oneKey, "192.0.2.1")
	if rejected || createdAfterSnapshot == nil {
		t.Fatal("failed to create compatible bucket after snapshot")
	}
	if err := limiter.UpdateInboundLimiter("inbound", &[]api.UserInfo{{
		UID: 2, Email: "two@example.test", SpeedLimit: 300,
	}}); err != nil {
		t.Fatalf("UpdateInboundLimiter() error = %v", err)
	}

	if err := limiter.RestoreInboundLimiterState("inbound", snapshot); err != nil {
		t.Fatalf("RestoreInboundLimiterState() error = %v", err)
	}
	restored, _, rejected := limiter.getUserBucket("inbound", oneKey, "192.0.2.1")
	if rejected || restored != createdAfterSnapshot {
		t.Fatal("rollback discarded a compatible bucket created after the snapshot")
	}
}

func TestLimiterAdmissionInterfaceKeepsOwnedAndLegacyEntrypoints(t *testing.T) {
	typeOfLimiter := reflect.TypeOf((*Limiter)(nil))
	for _, methodName := range []string{"Admit", "GetUserBucket", "RateReader", "RateWriter"} {
		if _, exists := typeOfLimiter.MethodByName(methodName); !exists {
			t.Fatalf("Limiter is missing compatibility entrypoint %s", methodName)
		}
	}
}

func TestReplacementRetiresPriorGenerationAndRestoreReactivatesIt(t *testing.T) {
	limiter := New()
	users := []api.UserInfo{{UID: 1, Email: "user@example.test"}}
	if err := limiter.AddInboundLimiter("inbound", 0, &users, nil); err != nil {
		t.Fatalf("AddInboundLimiter() error = %v", err)
	}
	value, _ := limiter.InboundInfo.Load("inbound")
	applied := value.(*inboundState)
	snapshot, err := limiter.SnapshotInboundLimiterState("inbound")
	if err != nil {
		t.Fatalf("SnapshotInboundLimiterState() error = %v", err)
	}

	if err := limiter.ReplaceInboundUsers("inbound", &users); err != nil {
		t.Fatalf("ReplaceInboundUsers() error = %v", err)
	}
	if admitted, _ := applied.beginAdmission(); admitted {
		applied.endAdmission()
		t.Fatal("replaced inbound generation still accepted admission")
	}

	if err := limiter.RestoreInboundLimiterState("inbound", snapshot); err != nil {
		t.Fatalf("RestoreInboundLimiterState() error = %v", err)
	}
	if admitted, _ := applied.beginAdmission(); !admitted {
		t.Fatal("restored applied generation remained retired")
	}
	applied.endAdmission()
}

func TestRetiredGenerationWaitsForReplacementNotification(t *testing.T) {
	state := &inboundState{}
	state.retireAdmissions()

	admitted, replacementReady := state.beginAdmission()
	if admitted {
		state.endAdmission()
		t.Fatal("retired generation admitted traffic")
	}
	if replacementReady == nil {
		t.Fatal("retired generation did not provide a replacement notification")
	}

	waitDone := make(chan struct{})
	go func() {
		<-replacementReady
		close(waitDone)
	}()
	select {
	case <-waitDone:
		t.Fatal("replacement notification closed before publication")
	default:
	}

	state.notifyReplacement()
	<-waitDone
	state.activateAdmissions()
	if admitted, _ := state.beginAdmission(); !admitted {
		t.Fatal("reactivated generation did not resume admission")
	}
	state.endAdmission()
}

func TestDeleteAndCloseReleaseAllRetiredAdmissionWaiters(t *testing.T) {
	const waiterCount = 8
	for _, test := range []struct {
		name   string
		finish func(*Limiter) error
	}{
		{name: "delete", finish: func(l *Limiter) error { return l.DeleteInboundLimiter("inbound") }},
		{name: "close", finish: func(l *Limiter) error { return l.Close() }},
	} {
		t.Run(test.name, func(t *testing.T) {
			limiter := New()
			users := []api.UserInfo{{UID: 1, Email: "user@example.test"}}
			if err := limiter.AddInboundLimiter("inbound", 0, &users, nil); err != nil {
				t.Fatalf("AddInboundLimiter() error = %v", err)
			}
			value, _ := limiter.InboundInfo.Load("inbound")
			value.(*inboundState).retireAdmissions()

			waiting := make(chan struct{}, waiterCount)
			results := make(chan bool, waiterCount)
			limiter.onAdmissionWaiting = func() {
				waiting <- struct{}{}
			}
			for index := 0; index < waiterCount; index++ {
				go func(index int) {
					_, _, rejected := limiter.Admit(
						"inbound",
						"inbound|user@example.test|1",
						fmt.Sprintf("192.0.2.%d", index+1),
						nil,
						nil,
					)
					results <- rejected
				}(index)
			}
			for index := 0; index < waiterCount; index++ {
				<-waiting
			}

			if err := test.finish(limiter); err != nil {
				t.Fatalf("%s error = %v", test.name, err)
			}
			for index := 0; index < waiterCount; index++ {
				if rejected := <-results; !rejected {
					t.Fatalf("waiter %d was admitted after %s", index, test.name)
				}
			}
		})
	}
}

func TestReplaceInboundUsersDrainsAdmissionBeforePublishingPreservedState(t *testing.T) {
	limiter := New()
	users := []api.UserInfo{{UID: 1, Email: "user@example.test", SpeedLimit: 100, DeviceLimit: 2}}
	if err := limiter.AddInboundLimiter("inbound", 0, &users, nil); err != nil {
		t.Fatalf("AddInboundLimiter() error = %v", err)
	}
	value, _ := limiter.InboundInfo.Load("inbound")
	applied := value.(*inboundState)

	entered := make(chan struct{})
	release := make(chan struct{})
	admissionDone := make(chan struct{})
	drainStarted := make(chan struct{})
	replaceDone := make(chan error, 1)
	limiter.onAdmissionEntered = func() {
		close(entered)
		<-release
	}
	limiter.onAdmissionDrainStarted = func() {
		close(drainStarted)
	}
	go func() {
		defer close(admissionDone)
		_, _, _ = limiter.Admit("inbound", "inbound|user@example.test|1", "192.0.2.1", nil, nil)
	}()
	<-entered
	go func() {
		replaceDone <- limiter.ReplaceInboundUsers("inbound", &users)
	}()

	<-drainStarted
	published, _ := limiter.InboundInfo.Load("inbound")
	publishedBeforeDrain := published.(*inboundState) != applied

	close(release)
	<-admissionDone
	if err := <-replaceDone; err != nil {
		t.Fatalf("ReplaceInboundUsers() error = %v", err)
	}
	if publishedBeforeDrain {
		t.Fatal("replacement generation was published before the applied admission drained")
	}

	currentValue, _ := limiter.InboundInfo.Load("inbound")
	current := currentValue.(*inboundState)
	userKey := "inbound|user@example.test|1"
	entryValue, online := current.UserOnlineIP.Load(userKey)
	if !online || !entryValue.(*userOnlineEntry).hasIP("192.0.2.1") {
		t.Fatal("replacement lost the device admitted while the applied generation drained")
	}
	appliedBucket, appliedBucketExists := applied.BucketHub.Load(userKey)
	currentBucket, currentBucketExists := current.BucketHub.Load(userKey)
	if !appliedBucketExists || !currentBucketExists || currentBucket != appliedBucket {
		t.Fatal("replacement lost the compatible token bucket created by the draining admission")
	}
}

func TestAdmissionEnteringRetiredGenerationAfterReplacementRetriesPublishedGeneration(t *testing.T) {
	limiter := New()
	users := []api.UserInfo{{UID: 1, Email: "user@example.test", SpeedLimit: 100}}
	if err := limiter.AddInboundLimiter("inbound", 0, &users, nil); err != nil {
		t.Fatalf("AddInboundLimiter() error = %v", err)
	}
	value, _ := limiter.InboundInfo.Load("inbound")
	applied := value.(*inboundState)

	replacement := []api.UserInfo{{UID: 1, Email: "user@example.test", SpeedLimit: 25}}
	if err := limiter.ReplaceInboundUsers("inbound", &replacement); err != nil {
		t.Fatalf("ReplaceInboundUsers() error = %v", err)
	}
	admitted, replacementReady := applied.beginAdmission()
	if admitted || replacementReady == nil {
		t.Fatalf("retired generation admission = admitted:%v replacementReady:%v, want retry signal", admitted, replacementReady)
	}
	select {
	case <-replacementReady:
	default:
		t.Fatal("replacement retry signal was not closed after publication")
	}

	bucket, _, rejected := limiter.getUserBucket(
		"inbound",
		"inbound|user@example.test|1",
		"192.0.2.1",
	)
	if rejected || bucket == nil || bucket.Limit() != 25 {
		t.Fatalf("published generation admission = bucket:%v rejected:%v, want limit 25", bucket, rejected)
	}
}

func TestReplacementPublicationDoesNotExposeRetiredAppliedGeneration(t *testing.T) {
	limiter := New()
	users := []api.UserInfo{{UID: 1, Email: "user@example.test", SpeedLimit: 100}}
	if err := limiter.AddInboundLimiter("inbound", 0, &users, nil); err != nil {
		t.Fatalf("AddInboundLimiter() error = %v", err)
	}

	publishEntered := make(chan struct{})
	releasePublish := make(chan struct{})
	limiter.onBeforeReplacementPublish = func() {
		close(publishEntered)
		<-releasePublish
	}
	waiting := make(chan struct{}, 1)
	limiter.onAdmissionWaiting = func() {
		waiting <- struct{}{}
	}
	replacementDone := make(chan error, 1)
	replacement := []api.UserInfo{{UID: 1, Email: "user@example.test", SpeedLimit: 25}}
	go func() {
		replacementDone <- limiter.ReplaceInboundUsers("inbound", &replacement)
	}()
	<-publishEntered

	result := make(chan bool, 1)
	go func() {
		_, _, rejected := limiter.getUserBucket(
			"inbound",
			"inbound|user@example.test|1",
			"192.0.2.1",
		)
		result <- rejected
	}()
	select {
	case <-waiting:
	case rejected := <-result:
		t.Fatalf("admission completed before replacement publication: rejected=%v, want wait", rejected)
	}

	close(releasePublish)
	if err := <-replacementDone; err != nil {
		t.Fatalf("ReplaceInboundUsers() error = %v", err)
	}
	if rejected := <-result; rejected {
		t.Fatal("admission waiting during replacement was rejected")
	}
}

func TestUpdateInboundLimiterDrainsAdmissionBeforeApplyingPartialPolicy(t *testing.T) {
	limiter := New()
	users := []api.UserInfo{{UID: 1, Email: "user@example.test", SpeedLimit: 100, DeviceLimit: 2}}
	if err := limiter.AddInboundLimiter("inbound", 0, &users, nil); err != nil {
		t.Fatalf("AddInboundLimiter() error = %v", err)
	}
	value, _ := limiter.InboundInfo.Load("inbound")
	applied := value.(*inboundState)

	entered := make(chan struct{})
	release := make(chan struct{})
	admissionDone := make(chan struct{})
	drainStarted := make(chan struct{})
	updateDone := make(chan error, 1)
	limiter.onAdmissionEntered = func() {
		close(entered)
		<-release
	}
	limiter.onAdmissionDrainStarted = func() {
		close(drainStarted)
	}
	go func() {
		defer close(admissionDone)
		_, _, _ = limiter.Admit("inbound", "inbound|user@example.test|1", "192.0.2.1", nil, nil)
	}()
	<-entered
	go func() {
		updateDone <- limiter.UpdateInboundLimiter("inbound", &users)
	}()

	<-drainStarted
	published, _ := limiter.InboundInfo.Load("inbound")
	publishedBeforeDrain := published.(*inboundState) != applied

	close(release)
	<-admissionDone
	if err := <-updateDone; err != nil {
		t.Fatalf("UpdateInboundLimiter() error = %v", err)
	}
	if publishedBeforeDrain {
		t.Fatal("updated generation was published before the applied admission drained")
	}

	currentValue, _ := limiter.InboundInfo.Load("inbound")
	current := currentValue.(*inboundState)
	userKey := "inbound|user@example.test|1"
	entryValue, online := current.UserOnlineIP.Load(userKey)
	if !online || !entryValue.(*userOnlineEntry).hasIP("192.0.2.1") {
		t.Fatal("partial update lost the device admitted while the applied generation drained")
	}
	appliedBucket, appliedBucketExists := applied.BucketHub.Load(userKey)
	currentBucket, currentBucketExists := current.BucketHub.Load(userKey)
	if !appliedBucketExists || !currentBucketExists || currentBucket != appliedBucket {
		t.Fatal("partial update lost the compatible token bucket created by the draining admission")
	}
}

func TestAddInboundLimiterDrainsAdmissionBeforePublishingPreservedState(t *testing.T) {
	limiter := New()
	users := []api.UserInfo{{UID: 1, Email: "user@example.test", SpeedLimit: 100, DeviceLimit: 2}}
	if err := limiter.AddInboundLimiter("inbound", 0, &users, nil); err != nil {
		t.Fatalf("AddInboundLimiter() error = %v", err)
	}
	value, _ := limiter.InboundInfo.Load("inbound")
	applied := value.(*inboundState)

	entered := make(chan struct{})
	release := make(chan struct{})
	admissionDone := make(chan struct{})
	drainStarted := make(chan struct{})
	addDone := make(chan error, 1)
	limiter.onAdmissionEntered = func() {
		close(entered)
		<-release
	}
	limiter.onAdmissionDrainStarted = func() {
		close(drainStarted)
	}
	go func() {
		defer close(admissionDone)
		_, _, _ = limiter.Admit("inbound", "inbound|user@example.test|1", "192.0.2.1", nil, nil)
	}()
	<-entered
	go func() {
		addDone <- limiter.AddInboundLimiter("inbound", 0, &users, nil)
	}()

	<-drainStarted
	published, _ := limiter.InboundInfo.Load("inbound")
	publishedBeforeDrain := published.(*inboundState) != applied

	close(release)
	<-admissionDone
	if err := <-addDone; err != nil {
		t.Fatalf("AddInboundLimiter() replacement error = %v", err)
	}
	if publishedBeforeDrain {
		t.Fatal("added replacement generation was published before the applied admission drained")
	}

	currentValue, _ := limiter.InboundInfo.Load("inbound")
	current := currentValue.(*inboundState)
	userKey := "inbound|user@example.test|1"
	entryValue, online := current.UserOnlineIP.Load(userKey)
	if !online || !entryValue.(*userOnlineEntry).hasIP("192.0.2.1") {
		t.Fatal("added replacement lost the device admitted while the applied generation drained")
	}
	appliedBucket, appliedBucketExists := applied.BucketHub.Load(userKey)
	currentBucket, currentBucketExists := current.BucketHub.Load(userKey)
	if !appliedBucketExists || !currentBucketExists || currentBucket != appliedBucket {
		t.Fatal("added replacement lost the compatible token bucket created by the draining admission")
	}
}

func TestUpdateInboundLimiterPublishesNewBucketWithoutMutatingInflightAdmission(t *testing.T) {
	limiter := New()
	users := []api.UserInfo{{UID: 1, Email: "user@example.test", SpeedLimit: 100}}
	if err := limiter.AddInboundLimiter("inbound", 0, &users, nil); err != nil {
		t.Fatalf("AddInboundLimiter() error = %v", err)
	}
	userKey := "inbound|user@example.test|1"
	oldBucket, speedLimited, rejected := limiter.getUserBucket("inbound", userKey, "192.0.2.1")
	if rejected || !speedLimited || oldBucket == nil {
		t.Fatalf("initial admission = bucket:%v speedLimited:%v rejected:%v", oldBucket, speedLimited, rejected)
	}

	updatedUsers := []api.UserInfo{{UID: 1, Email: "user@example.test", SpeedLimit: 200}}
	if err := limiter.UpdateInboundLimiter("inbound", &updatedUsers); err != nil {
		t.Fatalf("UpdateInboundLimiter() error = %v", err)
	}

	newBucket, speedLimited, rejected := limiter.getUserBucket("inbound", userKey, "192.0.2.1")
	if rejected || !speedLimited || newBucket == nil {
		t.Fatalf("updated admission = bucket:%v speedLimited:%v rejected:%v", newBucket, speedLimited, rejected)
	}
	if oldBucket == newBucket {
		t.Fatal("updated admission reused the in-flight bucket")
	}
	if oldBucket.Limit() != 100 || oldBucket.Burst() != 100 {
		t.Fatalf("in-flight bucket changed to limit=%v burst=%d", oldBucket.Limit(), oldBucket.Burst())
	}
	if newBucket.Limit() != 200 || newBucket.Burst() != 200 {
		t.Fatalf("new bucket = limit:%v burst:%d, want 200/200", newBucket.Limit(), newBucket.Burst())
	}
}

func TestCloseWaitsForEnteredAdmission(t *testing.T) {
	limiter := New()
	users := []api.UserInfo{{UID: 1, Email: "user@example.test"}}
	if err := limiter.AddInboundLimiter("inbound", 0, &users, nil); err != nil {
		t.Fatalf("AddInboundLimiter() error = %v", err)
	}

	entered := make(chan struct{})
	release := make(chan struct{})
	admissionDone := make(chan struct{})
	closeEntered := make(chan struct{})
	closeDone := make(chan error, 1)
	limiter.onAdmissionEntered = func() {
		close(entered)
		<-release
	}
	limiter.onCloseDrainEntered = func() {
		close(closeEntered)
	}

	go func() {
		defer close(admissionDone)
		_, _, _ = limiter.Admit("inbound", "inbound|user@example.test|1", "192.0.2.1", nil, nil)
	}()
	<-entered
	go func() {
		closeDone <- limiter.Close()
	}()
	<-closeEntered
	select {
	case err := <-closeDone:
		t.Fatalf("Close() returned before entered admission completed: %v", err)
	default:
	}

	close(release)
	<-admissionDone
	if err := <-closeDone; err != nil {
		t.Fatalf("Close() error = %v", err)
	}
}

type releasingBufferWriter struct {
	calls int
}

func (w *releasingBufferWriter) WriteMultiBuffer(mb buf.MultiBuffer) error {
	w.calls++
	buf.ReleaseMulti(mb)
	return nil
}

func oneByteMultiBuffer(t *testing.T) buf.MultiBuffer {
	t.Helper()
	buffer := buf.New()
	if _, err := buffer.Write([]byte{1}); err != nil {
		t.Fatalf("buffer.Write() error = %v", err)
	}
	return buf.MultiBuffer{buffer}
}

func TestCloseCancelsAndJoinsEnteredRateWait(t *testing.T) {
	limiter := New()
	bucket := rate.NewLimiter(rate.Every(20*time.Second), 1)
	if !bucket.Allow() {
		t.Fatal("failed to consume initial rate token")
	}
	underlying := &releasingBufferWriter{}
	writer := &limitedWriter{writer: underlying, limiter: bucket, owner: limiter}
	entered := make(chan struct{})
	closeEntered := make(chan struct{})
	writeDone := make(chan error, 1)
	closeDone := make(chan error, 1)
	limiter.onRateWaitEntered = func() {
		close(entered)
	}
	limiter.onCloseDrainEntered = func() {
		close(closeEntered)
	}

	payload := oneByteMultiBuffer(t)
	go func() {
		writeDone <- writer.WriteMultiBuffer(payload)
	}()
	<-entered
	go func() {
		closeDone <- limiter.Close()
	}()
	<-closeEntered
	if err := <-writeDone; !errors.Is(err, context.Canceled) {
		t.Fatalf("rate wait error = %v, want context canceled", err)
	}
	if err := <-closeDone; err != nil {
		t.Fatalf("Close() error = %v", err)
	}
	if underlying.calls != 0 {
		t.Fatalf("underlying writer calls = %d, want 0", underlying.calls)
	}
}

func TestWaitRateRejectsFastPathAfterClose(t *testing.T) {
	limiter := New()
	if err := limiter.Close(); err != nil {
		t.Fatalf("Close() error = %v", err)
	}
	bucket := rate.NewLimiter(rate.Inf, 1)
	if err := waitRate(limiter, bucket, 1); !errors.Is(err, context.Canceled) {
		t.Fatalf("waitRate() error = %v, want context canceled", err)
	}
}

func TestConcurrentAdmissionReplacementSnapshotDeviceSyncAndClose(t *testing.T) {
	limiter := New()
	users := []api.UserInfo{{UID: 1, Email: "user@example.test", SpeedLimit: 100, DeviceLimit: 2}}
	if err := limiter.AddInboundLimiter("inbound", 0, &users, nil); err != nil {
		t.Fatalf("AddInboundLimiter() error = %v", err)
	}
	userKey := "inbound|user@example.test|1"

	const workers = 5
	ready := make(chan struct{}, workers)
	start := make(chan struct{})
	var wait sync.WaitGroup
	wait.Add(workers)
	run := func(work func()) {
		defer wait.Done()
		ready <- struct{}{}
		<-start
		for range 100 {
			work()
		}
	}
	go run(func() {
		_, _, _ = limiter.Admit("inbound", userKey, "192.0.2.1", nil, nil)
	})
	go run(func() {
		_ = limiter.ReplaceInboundUsers("inbound", &users)
	})
	go run(func() {
		_, _ = limiter.SnapshotInboundLimiterState("inbound")
	})
	go run(func() {
		_ = limiter.UpdateGlobalDevices("inbound", map[int][]string{1: {"192.0.2.1"}})
	})
	go run(func() {
		_ = limiter.SyncAliveList("inbound", map[int][]string{1: {"192.0.2.1"}})
	})
	for range workers {
		<-ready
	}
	close(start)
	if err := limiter.Close(); err != nil {
		t.Fatalf("Close() error = %v", err)
	}
	wait.Wait()

	if _, _, rejected := limiter.Admit("inbound", userKey, "192.0.2.1", nil, nil); !rejected {
		t.Fatal("admission after concurrent Close() was not rejected")
	}
}
func TestClosedGlobalLimitStateRejectsStaleInflightAdmission(t *testing.T) {
	limiter := New()
	limiter.buildGlobalLimitBackend = func(*GlobalDeviceLimitConfig) globalLimitBackend {
		return globalLimitBackend{closer: &countingCloser{}}
	}
	users := []api.UserInfo{{UID: 1, Email: "user@example.test", DeviceLimit: 1}}
	config := &GlobalDeviceLimitConfig{Enable: true}
	if err := limiter.AddInboundLimiter("inbound", 0, &users, config); err != nil {
		t.Fatalf("AddInboundLimiter() error = %v", err)
	}
	value, exists := limiter.InboundInfo.Load("inbound")
	if !exists {
		t.Fatal("inbound state was not published")
	}
	staleState := value.(*inboundState)

	if err := limiter.Close(); err != nil {
		t.Fatalf("Close() error = %v", err)
	}
	if rejected := globalLimit(staleState, "inbound|user@example.test|1", 1, "192.0.2.1", 1); !rejected {
		t.Fatal("closed global limit state allowed stale in-flight admission")
	}
}
func TestGlobalLimitBackendDoesNotOwnAdmissionMembership(t *testing.T) {
	stateType := reflect.TypeOf(globalLimitState{})
	if _, exists := stateType.FieldByName("activeUsers"); exists {
		t.Fatal("global-limit backend duplicates the published inbound user membership")
	}
}
func TestReplaceInboundUsersPrunesRemovedGlobalLimitKeyLocks(t *testing.T) {
	limiter := New()
	limiter.buildGlobalLimitBackend = func(*GlobalDeviceLimitConfig) globalLimitBackend {
		return globalLimitBackend{closer: &countingCloser{}}
	}
	users := []api.UserInfo{
		{UID: 1, Email: "kept@example.test"},
		{UID: 2, Email: "removed@example.test"},
	}
	config := &GlobalDeviceLimitConfig{Enable: true}
	if err := limiter.AddInboundLimiter("inbound", 0, &users, config); err != nil {
		t.Fatalf("AddInboundLimiter() error = %v", err)
	}
	value, _ := limiter.InboundInfo.Load("inbound")
	state := value.(*inboundState)
	keptKey := "inbound|kept@example.test|1"
	removedKey := "inbound|removed@example.test|2"
	_ = getGlobalLimitLock(state, keptKey)
	_ = getGlobalLimitLock(state, removedKey)

	replacement := []api.UserInfo{{UID: 1, Email: "kept@example.test"}}
	if err := limiter.ReplaceInboundUsers("inbound", &replacement); err != nil {
		t.Fatalf("ReplaceInboundUsers() error = %v", err)
	}
	if _, exists := state.GlobalLimit.keyLocks.Load(removedKey); exists {
		t.Fatal("removed user global-limit lock was retained")
	}
	if _, exists := state.GlobalLimit.keyLocks.Load(keptKey); !exists {
		t.Fatal("kept user global-limit lock was removed")
	}
}
func TestGetOnlineDeviceRetiresDetachedEntryBeforeConcurrentAdmission(t *testing.T) {
	limiter := New()
	users := []api.UserInfo{{UID: 1, Email: "user@example.test", DeviceLimit: 2}}
	if err := limiter.AddInboundLimiter("inbound", 0, &users, nil); err != nil {
		t.Fatalf("AddInboundLimiter() error = %v", err)
	}
	userKey := "inbound|user@example.test|1"
	if _, _, rejected := limiter.getUserBucket("inbound", userKey, "192.0.2.1"); rejected {
		t.Fatal("initial admission was rejected")
	}
	value, _ := limiter.InboundInfo.Load("inbound")
	state := value.(*inboundState)
	entryValue, _ := state.UserOnlineIP.Load(userKey)
	detached := entryValue.(*userOnlineEntry)
	detached.ips.Store("192.0.2.1", connIP{UID: 1, LastSeen: time.Now().Unix() - ipTTL - 1})

	if _, err := limiter.GetOnlineDevice("inbound"); err != nil {
		t.Fatalf("GetOnlineDevice() error = %v", err)
	}
	if rejected, retry := detached.admitIP("198.51.100.1", 1, 2, state.GlobalDevices); rejected || !retry {
		t.Fatalf("detached entry admission = rejected:%v retry:%v, want retry", rejected, retry)
	}
	if detached.hasIP("198.51.100.1") {
		t.Fatal("detached entry accepted a new IP")
	}
}
