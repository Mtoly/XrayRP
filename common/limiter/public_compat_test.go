package limiter

import (
	"sync"
	"testing"

	"github.com/Mtoly/XrayRP/api"
	"golang.org/x/time/rate"
)

func TestLegacyLimiterMutableStateRemainsAuthoritative(t *testing.T) {
	t.Run("node speed limit", func(t *testing.T) {
		limiter := New()
		users := []api.UserInfo{{UID: 1, Email: "user@example.test"}}
		if err := limiter.AddInboundLimiter("inbound", 100, &users, nil); err != nil {
			t.Fatalf("AddInboundLimiter() error = %v", err)
		}
		value, _ := limiter.InboundInfo.Load("inbound")
		value.(*InboundInfo).NodeSpeedLimit = 25

		_, writer, rejected := limiter.Admit("inbound", "inbound|user@example.test|1", "192.0.2.1", nil, nil)
		if rejected || writer == nil {
			t.Fatalf("Admit() = writer:%T rejected:%v", writer, rejected)
		}
		if got := writer.(*limitedWriter).limiter.Limit(); got != 25 {
			t.Fatalf("applied limit = %v, want 25", got)
		}
	})

	t.Run("map pointers", func(t *testing.T) {
		limiter := New()
		users := []api.UserInfo{{UID: 1, Email: "user@example.test", SpeedLimit: 100}}
		if err := limiter.AddInboundLimiter("inbound", 0, &users, nil); err != nil {
			t.Fatalf("AddInboundLimiter() error = %v", err)
		}
		value, _ := limiter.InboundInfo.Load("inbound")
		inbound := value.(*InboundInfo)
		inbound.UserInfo = new(sync.Map)
		inbound.UserInfo.Store("inbound|user@example.test|1", UserInfo{UID: 1, SpeedLimit: 25})
		inbound.BucketHub = new(sync.Map)
		inbound.UserOnlineIP = new(sync.Map)

		_, writer, rejected := limiter.Admit("inbound", "inbound|user@example.test|1", "192.0.2.1", nil, nil)
		if rejected || writer == nil {
			t.Fatalf("Admit() = writer:%T rejected:%v", writer, rejected)
		}
		if got := writer.(*limitedWriter).limiter.Limit(); got != 25 {
			t.Fatalf("applied limit = %v, want 25", got)
		}
	})

	t.Run("outer map", func(t *testing.T) {
		limiter := New()
		users := []api.UserInfo{{UID: 1, Email: "user@example.test", SpeedLimit: 100}}
		if err := limiter.AddInboundLimiter("inbound", 0, &users, nil); err != nil {
			t.Fatalf("AddInboundLimiter() error = %v", err)
		}
		limiter.InboundInfo.Delete("inbound")

		_, writer, rejected := limiter.Admit("inbound", "inbound|user@example.test|1", "192.0.2.1", nil, nil)
		if !rejected || writer != nil {
			t.Fatalf("Admit() after legacy delete = writer:%T rejected:%v, want fail closed", writer, rejected)
		}
	})
}

func TestLegacyOuterDeletePreservesOwnedCleanup(t *testing.T) {
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

	limiter.InboundInfo.Delete("inbound")
	if err := limiter.Close(); err != nil {
		t.Fatalf("Close() error = %v", err)
	}
	if closer.calls != 1 {
		t.Fatalf("owned backend Close() calls = %d, want 1", closer.calls)
	}
}

func TestLegacyGlobalLimitReplacementPreservesOwnedCleanup(t *testing.T) {
	tests := []struct {
		name    string
		cleanup func(*Limiter, *[]api.UserInfo, *GlobalDeviceLimitConfig) error
	}{
		{name: "close", cleanup: func(l *Limiter, _ *[]api.UserInfo, _ *GlobalDeviceLimitConfig) error { return l.Close() }},
		{name: "delete", cleanup: func(l *Limiter, _ *[]api.UserInfo, _ *GlobalDeviceLimitConfig) error {
			return l.DeleteInboundLimiter("inbound")
		}},
		{name: "replace", cleanup: func(l *Limiter, users *[]api.UserInfo, config *GlobalDeviceLimitConfig) error {
			return l.AddInboundLimiter("inbound", 0, users, config)
		}},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
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
				t.Fatalf("AddInboundLimiter() error = %v", err)
			}
			value, _ := limiter.InboundInfo.Load("inbound")
			value.(*InboundInfo).GlobalLimit = nil

			if err := test.cleanup(limiter, &users, config); err != nil {
				t.Fatalf("cleanup error = %v", err)
			}
			if closers[0].calls != 1 {
				t.Fatalf("original backend Close() calls = %d, want 1", closers[0].calls)
			}
			if err := limiter.Close(); err != nil {
				t.Fatalf("final Close() error = %v", err)
			}
		})
	}
}
func TestLegacyOuterReplacementFailsClosed(t *testing.T) {
	limiter := New()
	users := []api.UserInfo{{UID: 1, Email: "user@example.test", SpeedLimit: 100}}
	if err := limiter.AddInboundLimiter("inbound", 0, &users, nil); err != nil {
		t.Fatalf("AddInboundLimiter() error = %v", err)
	}
	value, _ := limiter.InboundInfo.Load("inbound")
	applied := value.(*InboundInfo)
	forged := &InboundInfo{
		Tag:            applied.Tag,
		NodeSpeedLimit: applied.NodeSpeedLimit,
		UserInfo:       applied.UserInfo,
		BucketHub:      applied.BucketHub,
		UserOnlineIP:   applied.UserOnlineIP,
		GlobalDevices:  applied.GlobalDevices,
		GlobalLimit:    applied.GlobalLimit,
	}
	limiter.InboundInfo.Store("inbound", forged)

	_, writer, rejected := limiter.Admit("inbound", "inbound|user@example.test|1", "192.0.2.1", nil, nil)
	if !rejected || writer != nil {
		t.Fatalf("Admit() after legacy replacement = writer:%T rejected:%v, want fail closed", writer, rejected)
	}
	if err := limiter.Close(); err != nil {
		t.Fatalf("Close() error = %v", err)
	}
}

func TestLegacyOuterCrossTagAliasFailsClosed(t *testing.T) {
	limiter := New()
	users := []api.UserInfo{{UID: 1, Email: "user@example.test", SpeedLimit: 100}}
	if err := limiter.AddInboundLimiter("inbound-a", 0, &users, nil); err != nil {
		t.Fatalf("AddInboundLimiter() error = %v", err)
	}
	value, _ := limiter.InboundInfo.Load("inbound-a")
	limiter.InboundInfo.Store("inbound-b", value)

	_, writer, rejected := limiter.Admit("inbound-b", "inbound-a|user@example.test|1", "192.0.2.1", nil, nil)
	if !rejected || writer != nil {
		t.Fatalf("Admit() through cross-tag alias = writer:%T rejected:%v, want fail closed", writer, rejected)
	}
}

func TestLimiterStateSnapshotTracksValidLegacyMutationAndRejectsForgedOuterState(t *testing.T) {
	limiter := New()
	users := []api.UserInfo{{UID: 1, Email: "user@example.test", SpeedLimit: 100}}
	if err := limiter.AddInboundLimiter("inbound", 50, &users, nil); err != nil {
		t.Fatalf("AddInboundLimiter() error = %v", err)
	}
	value, ok := limiter.InboundInfo.Load("inbound")
	if !ok {
		t.Fatal("legacy inbound view was not published")
	}
	applied := value.(*InboundInfo)
	applied.NodeSpeedLimit = 25

	snapshot := limiter.StateSnapshot()
	if got := snapshot.Inbounds["inbound"].NodeSpeedLimit; got != 25 {
		t.Fatalf("StateSnapshot() node speed limit = %d, want legacy mutation 25", got)
	}

	limiter.InboundInfo.Store("forged", applied)
	if _, ok := limiter.StateSnapshot().Inbounds["forged"]; ok {
		t.Fatal("StateSnapshot() accepted forged cross-tag outer entry")
	}

	limiter.InboundInfo.Delete("inbound")
	if _, ok := limiter.StateSnapshot().Inbounds["inbound"]; ok {
		t.Fatal("StateSnapshot() reported legacy-deleted applied entry")
	}
	if err := limiter.Close(); err != nil {
		t.Fatalf("Close() error = %v", err)
	}
}

func TestLegacyLimiterAPIMutationsRemainApplied(t *testing.T) {
	limiter := New()
	users := []api.UserInfo{{
		UID:         1,
		Email:       "user@example.test",
		SpeedLimit:  100,
		DeviceLimit: 2,
	}}
	if err := limiter.AddInboundLimiter("inbound", 10, &users, nil); err != nil {
		t.Fatalf("AddInboundLimiter() error = %v", err)
	}

	value, ok := limiter.InboundInfo.Load("inbound")
	if !ok {
		t.Fatal("legacy inbound view was not published")
	}
	inbound := value.(*InboundInfo)
	userKey := "inbound|user@example.test|1"
	policyValue, ok := inbound.UserInfo.Load(userKey)
	if !ok {
		t.Fatal("legacy user view was not published")
	}
	if got := policyValue.(UserInfo); got.UID != 1 || got.SpeedLimit != 100 || got.DeviceLimit != 2 {
		t.Fatalf("legacy user view = %+v", got)
	}

	inbound.UserInfo.Delete(userKey)
	if _, _, rejected := limiter.Admit("inbound", userKey, "192.0.2.1", nil, nil); !rejected {
		t.Fatal("legacy UserInfo mutation no longer changes applied admission state")
	}
}

func TestLegacyLimiterViewTracksLiveAdmissionState(t *testing.T) {
	limiter := New()
	users := []api.UserInfo{{
		UID:         1,
		Email:       "user@example.test",
		SpeedLimit:  100,
		DeviceLimit: 2,
	}}
	if err := limiter.AddInboundLimiter("inbound", 10, &users, nil); err != nil {
		t.Fatalf("AddInboundLimiter() error = %v", err)
	}

	value, ok := limiter.InboundInfo.Load("inbound")
	if !ok {
		t.Fatal("legacy inbound view was not published")
	}
	inbound := value.(*InboundInfo)
	userKey := "inbound|user@example.test|1"
	if _, _, rejected := limiter.Admit("inbound", userKey, "192.0.2.1", nil, nil); rejected {
		t.Fatal("Admit() rejected configured user")
	}

	if _, ok := inbound.UserOnlineIP.Load(userKey); !ok {
		t.Fatal("legacy online-device view did not observe successful admission")
	}
	if bucketValue, ok := inbound.BucketHub.Load(userKey); !ok {
		t.Fatal("legacy bucket view did not observe successful admission")
	} else if bucket := bucketValue.(*rate.Limiter); bucket.Limit() != 10 || bucket.Burst() != 10 {
		t.Fatalf("legacy bucket = limit:%v burst:%d, want 10/10", bucket.Limit(), bucket.Burst())
	}
}

func TestLegacyLimiterViewTracksGlobalDeviceUpdates(t *testing.T) {
	limiter := New()
	users := []api.UserInfo{{UID: 1, Email: "user@example.test", DeviceLimit: 1}}
	if err := limiter.AddInboundLimiter("inbound", 0, &users, nil); err != nil {
		t.Fatalf("AddInboundLimiter() error = %v", err)
	}
	value, ok := limiter.InboundInfo.Load("inbound")
	if !ok {
		t.Fatal("legacy inbound view was not published")
	}
	inbound := value.(*InboundInfo)

	if err := limiter.UpdateGlobalDevices("inbound", map[int][]string{1: {"192.0.2.1"}}); err != nil {
		t.Fatalf("UpdateGlobalDevices() error = %v", err)
	}
	if !inbound.GlobalDevices.ShouldReject(1, "192.0.2.2", 1, nil) {
		t.Fatal("legacy global-device view did not observe authoritative update")
	}

	if err := limiter.ClearGlobalDevices("inbound"); err != nil {
		t.Fatalf("ClearGlobalDevices() error = %v", err)
	}
	if inbound.GlobalDevices.Fresh() {
		t.Fatal("legacy global-device view remained fresh after clear")
	}
}

func TestLegacyLimiterViewTracksAliveListUpdates(t *testing.T) {
	limiter := New()
	users := []api.UserInfo{{UID: 1, Email: "user@example.test", DeviceLimit: 2}}
	if err := limiter.AddInboundLimiter("inbound", 0, &users, nil); err != nil {
		t.Fatalf("AddInboundLimiter() error = %v", err)
	}
	value, ok := limiter.InboundInfo.Load("inbound")
	if !ok {
		t.Fatal("legacy inbound view was not published")
	}
	inbound := value.(*InboundInfo)
	userKey := "inbound|user@example.test|1"

	if err := limiter.SyncAliveList("inbound", map[int][]string{1: {"192.0.2.1"}}); err != nil {
		t.Fatalf("SyncAliveList() error = %v", err)
	}
	onlineValue, ok := inbound.UserOnlineIP.Load(userKey)
	if !ok {
		t.Fatal("legacy online-device view did not observe alive-list update")
	}
	ips := onlineValue.(*userOnlineEntry).snapshotIPs()
	if len(ips) != 1 || ips[0] != "192.0.2.1" {
		t.Fatalf("legacy online-device view = %v, want [192.0.2.1]", ips)
	}
}

func TestLegacyLimiterSnapshotFieldsAreDetachedCopies(t *testing.T) {
	limiter := New()
	users := []api.UserInfo{{UID: 1, Email: "user@example.test", SpeedLimit: 100}}
	if err := limiter.AddInboundLimiter("inbound", 0, &users, nil); err != nil {
		t.Fatalf("AddInboundLimiter() error = %v", err)
	}
	userKey := "inbound|user@example.test|1"
	if _, limitedWriter, rejected := limiter.Admit("inbound", userKey, "192.0.2.1", nil, nil); rejected || limitedWriter == nil {
		t.Fatalf("Admit() = limitedWriter:%T rejected:%v", limitedWriter, rejected)
	}

	snapshot, err := limiter.SnapshotInboundLimiterState("inbound")
	if err != nil {
		t.Fatalf("SnapshotInboundLimiterState() error = %v", err)
	}
	if got := snapshot.UserInfo[userKey]; got.UID != 1 || got.SpeedLimit != 100 {
		t.Fatalf("legacy snapshot user = %+v", got)
	}
	if got := snapshot.Buckets[userKey]; got.Limit != 100 || got.Burst != 100 {
		t.Fatalf("legacy snapshot bucket = %+v", got)
	}

	delete(snapshot.UserInfo, userKey)
	delete(snapshot.Buckets, userKey)
	if _, _, rejected := limiter.Admit("inbound", userKey, "192.0.2.1", nil, nil); rejected {
		t.Fatal("mutating legacy snapshot fields changed applied admission state")
	}
}

func TestLegacyLimiterRestoresRebuiltPublicSnapshot(t *testing.T) {
	limiter := New()
	users := []api.UserInfo{{UID: 1, Email: "user@example.test", SpeedLimit: 100}}
	if err := limiter.AddInboundLimiter("inbound", 0, &users, nil); err != nil {
		t.Fatalf("AddInboundLimiter() error = %v", err)
	}
	userKey := "inbound|user@example.test|1"
	if _, _, rejected := limiter.Admit("inbound", userKey, "192.0.2.1", nil, nil); rejected {
		t.Fatal("Admit() rejected configured user")
	}

	rebuilt := &InboundLimiterStateSnapshot{
		UserInfo: map[string]UserInfo{
			userKey: {UID: 1, SpeedLimit: 25},
		},
		Buckets: map[string]bucketStateSnapshot{
			userKey: {Limit: 25, Burst: 25},
		},
	}
	if err := limiter.RestoreInboundLimiterState("inbound", rebuilt); err != nil {
		t.Fatalf("RestoreInboundLimiterState() error = %v", err)
	}

	_, writer, rejected := limiter.Admit("inbound", userKey, "192.0.2.1", nil, nil)
	if rejected || writer == nil {
		t.Fatalf("Admit() = writer:%T rejected:%v", writer, rejected)
	}
	if got := writer.(*limitedWriter).limiter.Limit(); got != 25 {
		t.Fatalf("restored public snapshot limit = %v, want 25", got)
	}
}

func TestLegacyLimiterRestoreUsesPublicSnapshotState(t *testing.T) {
	limiter := New()
	users := []api.UserInfo{{UID: 1, Email: "user@example.test", SpeedLimit: 100}}
	if err := limiter.AddInboundLimiter("inbound", 0, &users, nil); err != nil {
		t.Fatalf("AddInboundLimiter() error = %v", err)
	}
	userKey := "inbound|user@example.test|1"
	snapshot, err := limiter.SnapshotInboundLimiterState("inbound")
	if err != nil {
		t.Fatalf("SnapshotInboundLimiterState() error = %v", err)
	}

	updated := []api.UserInfo{{UID: 1, Email: "user@example.test", SpeedLimit: 200}}
	if err := limiter.UpdateInboundLimiter("inbound", &updated); err != nil {
		t.Fatalf("UpdateInboundLimiter() error = %v", err)
	}
	delete(snapshot.UserInfo, userKey)
	delete(snapshot.Buckets, userKey)
	if err := limiter.RestoreInboundLimiterState("inbound", snapshot); err != nil {
		t.Fatalf("RestoreInboundLimiterState() error = %v", err)
	}

	if _, _, rejected := limiter.Admit("inbound", userKey, "192.0.2.1", nil, nil); !rejected {
		t.Fatal("RestoreInboundLimiterState() ignored caller changes to the public snapshot")
	}
}

func TestLegacyLimiterImmediateRestoreUsesPublicSnapshotState(t *testing.T) {
	limiter := New()
	users := []api.UserInfo{{UID: 1, Email: "user@example.test", SpeedLimit: 100}}
	if err := limiter.AddInboundLimiter("inbound", 0, &users, nil); err != nil {
		t.Fatalf("AddInboundLimiter() error = %v", err)
	}
	userKey := "inbound|user@example.test|1"
	snapshot, err := limiter.SnapshotInboundLimiterState("inbound")
	if err != nil {
		t.Fatalf("SnapshotInboundLimiterState() error = %v", err)
	}

	delete(snapshot.UserInfo, userKey)
	delete(snapshot.Buckets, userKey)
	if err := limiter.RestoreInboundLimiterState("inbound", snapshot); err != nil {
		t.Fatalf("RestoreInboundLimiterState() error = %v", err)
	}

	if _, _, rejected := limiter.Admit("inbound", userKey, "192.0.2.1", nil, nil); !rejected {
		t.Fatal("immediate restore ignored caller changes to the public snapshot")
	}
}

func TestLegacyLimiterCrossGenerationRestoreUsesPublicSnapshotState(t *testing.T) {
	limiter := New()
	users := []api.UserInfo{{UID: 1, Email: "user@example.test", SpeedLimit: 100}}
	if err := limiter.AddInboundLimiter("inbound", 0, &users, nil); err != nil {
		t.Fatalf("AddInboundLimiter() error = %v", err)
	}
	userKey := "inbound|user@example.test|1"
	snapshot, err := limiter.SnapshotInboundLimiterState("inbound")
	if err != nil {
		t.Fatalf("SnapshotInboundLimiterState() error = %v", err)
	}

	replacement := []api.UserInfo{{UID: 2, Email: "replacement@example.test", SpeedLimit: 200}}
	if err := limiter.ReplaceInboundUsers("inbound", &replacement); err != nil {
		t.Fatalf("ReplaceInboundUsers() error = %v", err)
	}
	delete(snapshot.UserInfo, userKey)
	delete(snapshot.Buckets, userKey)
	if err := limiter.RestoreInboundLimiterState("inbound", snapshot); err != nil {
		t.Fatalf("RestoreInboundLimiterState() error = %v", err)
	}

	if _, _, rejected := limiter.Admit("inbound", userKey, "192.0.2.1", nil, nil); !rejected {
		t.Fatal("cross-generation restore ignored caller changes to the public snapshot")
	}
}

func TestLegacyLimiterRestoreUsesPublicBucketSnapshot(t *testing.T) {
	limiter := New()
	users := []api.UserInfo{{UID: 1, Email: "user@example.test", SpeedLimit: 100}}
	if err := limiter.AddInboundLimiter("inbound", 0, &users, nil); err != nil {
		t.Fatalf("AddInboundLimiter() error = %v", err)
	}
	userKey := "inbound|user@example.test|1"
	if _, _, rejected := limiter.Admit("inbound", userKey, "192.0.2.1", nil, nil); rejected {
		t.Fatal("Admit() rejected configured user")
	}
	snapshot, err := limiter.SnapshotInboundLimiterState("inbound")
	if err != nil {
		t.Fatalf("SnapshotInboundLimiterState() error = %v", err)
	}

	updated := []api.UserInfo{{UID: 1, Email: "user@example.test", SpeedLimit: 200}}
	if err := limiter.UpdateInboundLimiter("inbound", &updated); err != nil {
		t.Fatalf("UpdateInboundLimiter() error = %v", err)
	}
	snapshot.Buckets[userKey] = bucketStateSnapshot{Limit: 50, Burst: 50}
	if err := limiter.RestoreInboundLimiterState("inbound", snapshot); err != nil {
		t.Fatalf("RestoreInboundLimiterState() error = %v", err)
	}

	bucket, speedLimited, rejected := limiter.getUserBucket("inbound", userKey, "192.0.2.1")
	if rejected || !speedLimited || bucket == nil {
		t.Fatalf("restored admission = bucket:%v speedLimited:%v rejected:%v", bucket, speedLimited, rejected)
	}
	if bucket.Limit() != 50 || bucket.Burst() != 50 {
		t.Fatalf("restored bucket = limit:%v burst:%d, want 50/50", bucket.Limit(), bucket.Burst())
	}
}
