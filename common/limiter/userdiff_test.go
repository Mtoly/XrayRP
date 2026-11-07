package limiter

import (
	"reflect"
	"sync"
	"testing"

	"github.com/Mtoly/XrayRP/api"
)

func TestApplyInboundUserDiffAddsWithoutRebuilding(t *testing.T) {
	l := New()
	t.Cleanup(func() { _ = l.Close() })
	users := []api.UserInfo{{UID: 1, Email: "kept@example.test", SpeedLimit: 100}}
	if err := l.AddInboundLimiter("inbound", 0, &users, nil); err != nil {
		t.Fatal(err)
	}
	value, _ := l.InboundInfo.Load("inbound")
	before := value.(*InboundInfo)
	userMap, bucketMap, onlineMap := before.UserInfo, before.BucketHub, before.UserOnlineIP
	bucket, _, rejected := l.GetUserBucket("inbound", "inbound|kept@example.test|1", "192.0.2.1")
	if rejected {
		t.Fatal("retained user rejected")
	}
	added := []api.UserInfo{{UID: 2, Email: "added@example.test", SpeedLimit: 200}}
	if err := l.ApplyInboundUserDiff("inbound", added, nil, nil); err != nil {
		t.Fatal(err)
	}
	value, _ = l.InboundInfo.Load("inbound")
	after := value.(*InboundInfo)
	if after != before || after.UserInfo != userMap || after.BucketHub != bucketMap || after.UserOnlineIP != onlineMap {
		t.Fatal("incremental addition rebuilt inbound maps")
	}
	if got, _, rejected := l.GetUserBucket("inbound", "inbound|kept@example.test|1", "192.0.2.1"); rejected || got != bucket {
		t.Fatal("retained user lost its bucket")
	}
	if got, limited, rejected := l.GetUserBucket("inbound", "inbound|added@example.test|2", "198.51.100.2"); rejected || !limited || got == nil {
		t.Fatal("added user policy was not installed")
	}
}

func TestApplyInboundUserDiffUpdatesAndDeletes(t *testing.T) {
	for _, scenario := range []string{"update", "delete", "mixed", "empty"} {
		t.Run(scenario, func(t *testing.T) {
			l := New()
			t.Cleanup(func() { _ = l.Close() })
			users := []api.UserInfo{
				{UID: 1, Email: "kept@example.test", SpeedLimit: 100, DeviceLimit: 2},
				{UID: 2, Email: "removed@example.test", SpeedLimit: 200},
			}
			if err := l.AddInboundLimiter("inbound", 0, &users, nil); err != nil {
				t.Fatal(err)
			}
			bucket, _, _ := l.GetUserBucket("inbound", "inbound|kept@example.test|1", "192.0.2.1")
			l.GetUserBucket("inbound", "inbound|removed@example.test|2", "192.0.2.2")
			value, _ := l.InboundInfo.Load("inbound")
			state := value.(*InboundInfo)
			version := state.policyVersion
			before := l.StateSnapshot()
			var added, updated, deleted []api.UserInfo
			if scenario == "update" || scenario == "mixed" {
				user := users[0]
				user.DeviceLimit = 3
				updated = []api.UserInfo{user}
			}
			if scenario == "delete" || scenario == "mixed" {
				deleted = users[1:]
			}
			if scenario == "mixed" {
				added = []api.UserInfo{{UID: 3, Email: "added@example.test", SpeedLimit: 300}}
			}
			if err := l.ApplyInboundUserDiff("inbound", added, updated, deleted); err != nil {
				t.Fatal(err)
			}
			if got, _, rejected := l.GetUserBucket("inbound", "inbound|kept@example.test|1", "192.0.2.1"); rejected || got != bucket {
				t.Fatal("unchanged rate lost its bucket")
			}
			after := l.StateSnapshot().Inbounds["inbound"]
			if len(updated) > 0 && after.Users["inbound|kept@example.test|1"].DeviceLimit != 3 {
				t.Fatal("updated policy was not installed")
			}
			if len(added) > 0 && after.Users["inbound|added@example.test|3"].SpeedLimit != 300 {
				t.Fatal("mixed diff did not add user")
			}
			if len(deleted) > 0 {
				for _, entries := range []*sync.Map{state.UserInfo, state.BucketHub, state.UserOnlineIP} {
					if _, exists := entries.Load("inbound|removed@example.test|2"); exists {
						t.Fatal("deleted user retained state")
					}
				}
				if !reflect.DeepEqual(after.OnlineUsers, []api.OnlineUser{{UID: 1, IP: "192.0.2.1"}}) {
					t.Fatalf("online users = %#v", after.OnlineUsers)
				}
			} else if !reflect.DeepEqual(after.OnlineUsers, before.Inbounds["inbound"].OnlineUsers) {
				t.Fatal("retained users lost online IPs")
			}
			if scenario == "empty" {
				if state.policyVersion != version || !reflect.DeepEqual(l.StateSnapshot(), before) {
					t.Fatal("empty diff mutated state")
				}
			} else if state.policyVersion != version+1 {
				t.Fatal("diff did not advance policy version once")
			}
		})
	}
}

func TestApplyInboundUserDiffRollbackRestoresDeletedOnlineUser(t *testing.T) {
	l := New()
	t.Cleanup(func() { _ = l.Close() })
	users := []api.UserInfo{{UID: 1, Email: "user@example.test", SpeedLimit: 100, DeviceLimit: 2}}
	if err := l.AddInboundLimiter("inbound", 0, &users, nil); err != nil {
		t.Fatal(err)
	}
	bucket, _, _ := l.GetUserBucket("inbound", "inbound|user@example.test|1", "192.0.2.1")
	before := l.StateSnapshot()
	snapshot, err := l.SnapshotInboundLimiterState("inbound")
	if err != nil {
		t.Fatal(err)
	}
	if err := l.ApplyInboundUserDiff("inbound", nil, nil, users); err != nil {
		t.Fatal(err)
	}
	if err := l.RestoreInboundLimiterState("inbound", snapshot); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(l.StateSnapshot(), before) {
		t.Fatal("rollback lost the deleted user's policy, bucket or online IP")
	}
	if got, _, rejected := l.GetUserBucket("inbound", "inbound|user@example.test|1", "192.0.2.1"); rejected || got != bucket {
		t.Fatal("rollback did not restore the original bucket")
	}
}

func TestApplyInboundUserDiffChangesEffectiveRate(t *testing.T) {
	l := New()
	t.Cleanup(func() { _ = l.Close() })
	users := []api.UserInfo{{UID: 1, Email: "user@example.test", SpeedLimit: 100}}
	if err := l.AddInboundLimiter("inbound", 200, &users, nil); err != nil {
		t.Fatal(err)
	}
	previous, _, _ := l.GetUserBucket("inbound", "inbound|user@example.test|1", "192.0.2.1")
	for _, speed := range []uint64{300, 0, 50} {
		users[0].SpeedLimit = speed
		if err := l.ApplyInboundUserDiff("inbound", nil, users, nil); err != nil {
			t.Fatal(err)
		}
		bucket, limited, rejected := l.GetUserBucket("inbound", "inbound|user@example.test|1", "192.0.2.1")
		want := 200
		if speed == 50 {
			want = 50
		}
		if rejected || !limited || bucket == nil || bucket.Burst() != want {
			t.Fatalf("speed %d did not apply effective rate %d", speed, want)
		}
		if speed == 0 && bucket != previous {
			t.Fatal("unchanged node-limited rate did not reuse bucket")
		}
		if speed != 0 && bucket == previous {
			t.Fatal("changed rate reused old bucket")
		}
		previous = bucket
	}

	unlimited := []api.UserInfo{{UID: 2, Email: "unlimited@example.test", SpeedLimit: 100}}
	if err := l.AddInboundLimiter("unlimited", 0, &unlimited, nil); err != nil {
		t.Fatal(err)
	}
	unlimited[0].SpeedLimit = 0
	if err := l.ApplyInboundUserDiff("unlimited", nil, unlimited, nil); err != nil {
		t.Fatal(err)
	}
	if bucket, limited, rejected := l.GetUserBucket("unlimited", "unlimited|unlimited@example.test|2", "198.51.100.2"); rejected || limited || bucket != nil {
		t.Fatal("unlimited policy retained rate bucket")
	}
}

func TestApplyInboundUserDiffDrainsAdmissionsBeforeWriting(t *testing.T) {
	l := New()
	t.Cleanup(func() { _ = l.Close() })
	users := []api.UserInfo{{UID: 1, Email: "user@example.test", SpeedLimit: 100, DeviceLimit: 2}}
	if err := l.AddInboundLimiter("inbound", 0, &users, nil); err != nil {
		t.Fatal(err)
	}
	entered, release, drained := make(chan struct{}), make(chan struct{}), make(chan struct{})
	admissionDone, updateDone := make(chan struct{}), make(chan error, 1)
	l.onAdmissionEntered = func() { close(entered); <-release }
	l.onAdmissionDrainStarted = func() { close(drained) }
	go func() {
		defer close(admissionDone)
		l.GetUserBucket("inbound", "inbound|user@example.test|1", "192.0.2.1")
	}()
	<-entered
	updated := []api.UserInfo{users[0]}
	updated[0].DeviceLimit = 1
	go func() { updateDone <- l.ApplyInboundUserDiff("inbound", nil, updated, nil) }()
	<-drained
	value, _ := l.InboundInfo.Load("inbound")
	policy, _ := value.(*InboundInfo).UserInfo.Load("inbound|user@example.test|1")
	close(release)
	<-admissionDone
	if err := <-updateDone; err != nil {
		t.Fatal(err)
	}
	if policy.(UserInfo).DeviceLimit != 2 {
		t.Fatal("policy changed before admission drained")
	}
	l.onAdmissionEntered = nil
	if _, _, rejected := l.GetUserBucket("inbound", "inbound|user@example.test|1", "198.51.100.1"); !rejected {
		t.Fatal("new admission did not observe updated device limit and retained IP")
	}
}

func TestApplyInboundUserDiffRollbackRestoresDeletedUIDCount(t *testing.T) {
	l := New()
	t.Cleanup(func() { _ = l.Close() })
	users := []api.UserInfo{{UID: 1, Email: "user@example.test", DeviceLimit: 1}}
	if err := l.AddInboundLimiter("inbound", 0, &users, nil); err != nil {
		t.Fatal(err)
	}
	if err := l.SyncAliveSnapshot("inbound", &api.AliveSnapshot{Counts: map[int]int{1: 1}}, map[int][]string{}); err != nil {
		t.Fatal(err)
	}
	snapshot, err := l.SnapshotInboundLimiterState("inbound")
	if err != nil {
		t.Fatal(err)
	}
	if err := l.ApplyInboundUserDiff("inbound", nil, nil, users); err != nil {
		t.Fatal(err)
	}
	if err := l.RestoreInboundLimiterState("inbound", snapshot); err != nil {
		t.Fatal(err)
	}
	if _, _, rejected := l.GetUserBucket("inbound", "inbound|user@example.test|1", "192.0.2.1"); !rejected {
		t.Fatal("rollback lost panel count state")
	}
	if err := l.ApplyInboundUserDiff("inbound", nil, nil, users); err != nil {
		t.Fatal(err)
	}
	if err := l.ApplyInboundUserDiff("inbound", users, nil, nil); err != nil {
		t.Fatal(err)
	}
	if _, _, rejected := l.GetUserBucket("inbound", "inbound|user@example.test|1", "192.0.2.1"); rejected {
		t.Fatal("re-added user inherited deleted panel count state")
	}
}

func TestApplyInboundUserDiffReplacesOpaqueUserKey(t *testing.T) {
	l := New()
	t.Cleanup(func() { _ = l.Close() })
	users := []api.UserInfo{{UID: 1, Email: "inbound|1", SpeedLimit: 100}}
	if err := l.AddInboundLimiter("inbound", 0, &users, nil); err != nil {
		t.Fatal(err)
	}
	added := []api.UserInfo{{UID: 1, Email: "inbound|1", SpeedLimit: 200}}
	if err := l.ApplyInboundUserDiff("inbound", added, nil, users); err != nil {
		t.Fatal(err)
	}
	if bucket, limited, rejected := l.GetUserBucket("inbound", "inbound|1", "192.0.2.1"); rejected || !limited || bucket == nil || bucket.Burst() != 200 {
		t.Fatal("added policy sharing a deleted opaque key was lost")
	}
}

func TestApplyInboundUserDiffRollbackKeepsAdmissionsAfterSnapshot(t *testing.T) {
	l := New()
	t.Cleanup(func() { _ = l.Close() })
	users := []api.UserInfo{{UID: 1, Email: "user@example.test", DeviceLimit: 2}}
	if err := l.AddInboundLimiter("inbound", 0, &users, nil); err != nil {
		t.Fatal(err)
	}
	first, err := l.SnapshotInboundLimiterState("inbound")
	if err != nil {
		t.Fatal(err)
	}
	second, err := l.SnapshotInboundLimiterState("inbound")
	if err != nil {
		t.Fatal(err)
	}
	if _, _, rejected := l.GetUserBucket("inbound", "inbound|user@example.test|1", "192.0.2.1"); rejected {
		t.Fatal("user rejected before diff")
	}
	for _, snapshot := range []*InboundLimiterStateSnapshot{second, first} {
		if err := l.ApplyInboundUserDiff("inbound", nil, nil, users); err != nil {
			t.Fatal(err)
		}
		if err := l.RestoreInboundLimiterState("inbound", snapshot); err != nil {
			t.Fatal(err)
		}
		if got := l.StateSnapshot().Inbounds["inbound"].OnlineUsers; !reflect.DeepEqual(got, []api.OnlineUser{{UID: 1, IP: "192.0.2.1"}}) {
			t.Fatalf("rollback lost admission after snapshot: %#v", got)
		}
	}
}
