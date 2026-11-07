package controller

import (
	"context"
	"errors"
	"reflect"
	"testing"

	"github.com/Mtoly/XrayRP/api"
	"github.com/Mtoly/XrayRP/app/mydispatcher"
	"github.com/Mtoly/XrayRP/common/limiter"
)

func TestSyncApply_UserDiffRetainsLimiterMapsAndOnlineIPs(t *testing.T) {
	current := []api.UserInfo{
		{UID: 1, Email: "runtime@example.test", UUID: "old", SpeedLimit: 100, DeviceLimit: 2},
		{UID: 2, Email: "limit@example.test", SpeedLimit: 200, DeviceLimit: 2},
		{UID: 3, Email: "removed@example.test", SpeedLimit: 300},
		{UID: 5, Email: "previous@example.test", SpeedLimit: 500},
	}
	next := []api.UserInfo{current[0], current[1], {UID: 4, Email: "added@example.test", SpeedLimit: 400}, current[3]}
	next[0].UUID = "new"
	next[1].DeviceLimit = 3
	next[3].Email = "changed@example.test"
	c, _ := newTestSyncApplyController(nil)
	node := &api.NodeInfo{NodeType: "V2ray", NodeID: 1, Port: 443}
	tag := c.buildNodeTagFrom(node)
	c.setNodeState(node, tag)
	c.setUserList(&current)
	l := limiter.New()
	t.Cleanup(func() { _ = l.Close() })
	c.dispatcher = &mydispatcher.DefaultDispatcher{Limiter: l}
	c.syncApplyHooks.limiter = syncApplyLimiterHooks{}
	if err := c.AddInboundLimiter(tag, 0, &current, nil); err != nil {
		t.Fatal(err)
	}
	bucket, _, _ := l.GetUserBucket(tag, tag+"|1", "192.0.2.1")
	l.GetUserBucket(tag, tag+"|2", "192.0.2.2")
	l.GetUserBucket(tag, tag+"|3", "192.0.2.3")
	rotatedBucket, _, _ := l.GetUserBucket(tag, tag+"|5", "192.0.2.5")
	value, _ := l.InboundInfo.Load(tag)
	before := value.(*limiter.InboundInfo)
	users, buckets, online := before.UserInfo, before.BucketHub, before.UserOnlineIP
	c.syncApplyHooks.limiter.replaceInbound = func(string, *[]api.UserInfo) error {
		t.Fatal("user diff called full limiter replacement")
		return nil
	}
	a := nodeRuntimeStateApplyModule{controller: c, hooks: c.resolveSyncApplyHooks()}
	if err := a.applySyncSnapshotContext(context.Background(), syncApplySnapshot{
		Action:   newSyncAction(syncActionTypeSyncUsers, syncActionSourceWS, syncActionMetadata{}),
		UserList: &next,
	}); err != nil {
		t.Fatal(err)
	}
	value, _ = l.InboundInfo.Load(tag)
	after := value.(*limiter.InboundInfo)
	if after != before || after.UserInfo != users || after.BucketHub != buckets || after.UserOnlineIP != online {
		t.Fatal("user diff rebuilt limiter maps")
	}
	snapshot := l.StateSnapshot().Inbounds[tag]
	if len(snapshot.Users) != 4 || snapshot.Users[tag+"|2"].DeviceLimit != 3 || snapshot.Users[tag+"|4"].SpeedLimit != 400 || snapshot.Users[tag+"|5"].SpeedLimit != 500 {
		t.Fatalf("wrong user policies: %#v", snapshot.Users)
	}
	if !reflect.DeepEqual(snapshot.OnlineUsers, []api.OnlineUser{{UID: 1, IP: "192.0.2.1"}, {UID: 2, IP: "192.0.2.2"}, {UID: 5, IP: "192.0.2.5"}}) {
		t.Fatalf("wrong online users: %#v", snapshot.OnlineUsers)
	}
	if got, _, rejected := l.GetUserBucket(tag, tag+"|1", "192.0.2.1"); rejected || got != bucket {
		t.Fatal("runtime update lost a compatible bucket")
	}
	if _, _, rejected := l.GetUserBucket(tag, tag+"|3", "192.0.2.3"); !rejected {
		t.Fatal("removed user still admitted")
	}
	if got, _, rejected := l.GetUserBucket(tag, tag+"|5", "192.0.2.5"); rejected || got != rotatedBucket {
		t.Fatal("panel identity change lost its opaque runtime policy or bucket")
	}
}

func TestSyncApply_UserDiffFailureRestoresLimiterSnapshot(t *testing.T) {
	current := []api.UserInfo{
		{UID: 1, Email: "removed@example.test", SpeedLimit: 100},
		{UID: 2, Email: "updated@example.test", SpeedLimit: 200},
	}
	next := []api.UserInfo{current[1], {UID: 3, Email: "added@example.test", SpeedLimit: 300}}
	next[0].SpeedLimit = 400
	c, _ := newTestSyncApplyController(nil)
	node := &api.NodeInfo{NodeType: "V2ray", NodeID: 1, Port: 443}
	tag := c.buildNodeTagFrom(node)
	c.setNodeState(node, tag)
	c.setUserList(&current)
	l := limiter.New()
	t.Cleanup(func() { _ = l.Close() })
	c.dispatcher = &mydispatcher.DefaultDispatcher{Limiter: l}
	c.syncApplyHooks.limiter = syncApplyLimiterHooks{}
	if err := c.AddInboundLimiter(tag, 0, &current, nil); err != nil {
		t.Fatal(err)
	}
	l.GetUserBucket(tag, tag+"|1", "192.0.2.1")
	l.GetUserBucket(tag, tag+"|2", "192.0.2.2")
	before := l.StateSnapshot()
	applyErr := errors.New("incremental limiter apply failed")
	c.syncApplyHooks.limiter.applyInboundUserDiff = func(tag string, added, updated, deleted []api.UserInfo) error {
		if err := c.applyInboundLimiterUserDiff(tag, added, updated, deleted); err != nil {
			return err
		}
		return applyErr
	}
	a := nodeRuntimeStateApplyModule{controller: c, hooks: c.resolveSyncApplyHooks()}
	err := a.applySyncSnapshotContext(context.Background(), syncApplySnapshot{
		Action:   newSyncAction(syncActionTypeSyncUsers, syncActionSourceWS, syncActionMetadata{}),
		UserList: &next,
	})
	if !errors.Is(err, applyErr) {
		t.Fatalf("apply error = %v, want incremental limiter failure", err)
	}
	if !reflect.DeepEqual(l.StateSnapshot(), before) {
		t.Fatal("limiter rollback did not restore policies, buckets and online IPs")
	}
	_, _, applied := c.getStateSnapshot()
	if applied == nil || !reflect.DeepEqual(*applied, current) {
		t.Fatal("failed user diff changed applied controller users")
	}
}
