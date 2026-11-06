package controller

import (
	"context"
	"fmt"
	"reflect"
	"testing"

	"github.com/Mtoly/XrayRP/api"
)

func BenchmarkUnchangedUserPoll5000Users(b *testing.B) {
	for _, scenario := range []struct {
		name  string
		fetch bool
	}{
		{name: "fetch-and-apply", fetch: true},
		{name: "apply-only"},
	} {
		b.Run(scenario.name, func(b *testing.B) {
			users := make([]api.UserInfo, 5000)
			for i := range users {
				users[i] = api.UserInfo{
					UID:         i + 1,
					Email:       fmt.Sprintf("user-%04d@example.test", i),
					UUID:        fmt.Sprintf("00000000-0000-4000-8000-%012x", i+1),
					SpeedLimit:  uint64(1+i%4) * 12_500_000,
					DeviceLimit: 2 + i%3,
				}
			}
			client := &fakeSyncApplyAPI{userErr: api.ErrUserNotModified}
			controller, recorder := newTestSyncApplyController(client)
			// The test observer clones and retains snapshots; production has no observer.
			controller.syncApplyHooks.onSnapshotApplied = nil
			node := &api.NodeInfo{NodeType: "V2ray", NodeID: 1, Port: 443}
			controller.setNodeState(node, controller.buildNodeTagFrom(node))
			controller.setUserList(&users)
			ctx := context.Background()
			apply := newNodeRuntimeStateApplyModule(controller, ctx)
			action := newSyncAction(syncActionTypeSyncUsers, syncActionSourcePolling, syncActionMetadata{})
			snapshot, err := apply.fetchSyncApplySnapshotContext(ctx, action)
			if err != nil {
				b.Fatal(err)
			}
			if snapshot.UserList == nil || !reflect.DeepEqual(*snapshot.UserList, users) {
				b.Fatal("not-modified fetch did not preserve current users")
			}
			if err := apply.applySyncSnapshotContext(ctx, snapshot); err != nil {
				b.Fatal(err)
			}
			_, _, appliedUsers := controller.getStateSnapshot()
			if appliedUsers == nil || !reflect.DeepEqual(*appliedUsers, users) {
				b.Fatal("not-modified apply changed current users")
			}
			if recorder.addUserCalls != 0 || len(recorder.removedUsers) != 0 ||
				recorder.addLimiterCalls != 0 || recorder.deleteLimiterCalls != 0 || recorder.updateLimiterCalls != 0 ||
				recorder.snapshotLimiterCalls != 0 || recorder.restoreLimiterCalls != 0 {
				b.Fatal("not-modified apply invoked runtime user or limiter hooks")
			}

			b.ReportAllocs()
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				if scenario.fetch {
					snapshot, err = apply.fetchSyncApplySnapshotContext(ctx, action)
					if err != nil {
						b.Fatal(err)
					}
				}
				if err := apply.applySyncSnapshotContext(ctx, snapshot); err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}
