package limiter_test

import (
	"fmt"
	"reflect"
	"strings"
	"testing"

	"github.com/Mtoly/XrayRP/api"
	commonlimiter "github.com/Mtoly/XrayRP/common/limiter"
	"github.com/xtls/xray-core/common/buf"
	"golang.org/x/time/rate"
)

var (
	_ func(*commonlimiter.Limiter, string, string, string, buf.Reader, buf.Writer) (buf.Reader, buf.Writer, bool) = (*commonlimiter.Limiter).Admit
	_ func(*commonlimiter.Limiter, string, string, string) (*rate.Limiter, bool, bool)                            = (*commonlimiter.Limiter).GetUserBucket
	_ func(*commonlimiter.Limiter, buf.Writer, *rate.Limiter) buf.Writer                                          = (*commonlimiter.Limiter).RateWriter
	_ func(*commonlimiter.Limiter, buf.Reader, *rate.Limiter) buf.Reader                                          = (*commonlimiter.Limiter).RateReader
	_ func(*commonlimiter.Limiter) commonlimiter.LimiterSnapshot                                                  = (*commonlimiter.Limiter).StateSnapshot
	_ buf.Writer                                                                                                  = (*commonlimiter.Writer)(nil)
	_ buf.Reader                                                                                                  = (*commonlimiter.Reader)(nil)
)

func TestLegacyRateWrapperTypeNamesRemainStable(t *testing.T) {
	if got := reflect.TypeOf((*commonlimiter.Writer)(nil)).Elem().Name(); got != "Writer" {
		t.Fatalf("Writer reflection name = %q, want Writer", got)
	}
	if got := reflect.TypeOf((*commonlimiter.Reader)(nil)).Elem().Name(); got != "Reader" {
		t.Fatalf("Reader reflection name = %q, want Reader", got)
	}
}

func TestLimiterStateSnapshotSupportsNilAndClosedLimiter(t *testing.T) {
	var nilLimiter *commonlimiter.Limiter
	if snapshot := nilLimiter.StateSnapshot(); !snapshot.Closed || len(snapshot.Inbounds) != 0 {
		t.Fatalf("nil StateSnapshot() = closed:%v inbounds:%d", snapshot.Closed, len(snapshot.Inbounds))
	}

	runtimeLimiter := commonlimiter.New()
	users := []api.UserInfo{{UID: 1, Email: "user@example.test"}}
	if err := runtimeLimiter.AddInboundLimiter("inbound", 0, &users, nil); err != nil {
		t.Fatalf("AddInboundLimiter() error = %v", err)
	}
	if err := runtimeLimiter.Close(); err != nil {
		t.Fatalf("Close() error = %v", err)
	}
	if snapshot := runtimeLimiter.StateSnapshot(); !snapshot.Closed || len(snapshot.Inbounds) != 0 {
		t.Fatalf("closed StateSnapshot() = closed:%v inbounds:%d", snapshot.Closed, len(snapshot.Inbounds))
	}
}

func TestLimiterStateSnapshotIsDetachedAndCredentialFree(t *testing.T) {
	runtimeLimiter := commonlimiter.New()
	t.Cleanup(func() {
		if err := runtimeLimiter.Close(); err != nil {
			t.Errorf("Close() error = %v", err)
		}
	})

	users := []api.UserInfo{{
		UID:         1,
		Email:       "user@example.test",
		SpeedLimit:  100,
		DeviceLimit: 2,
	}}
	if err := runtimeLimiter.AddInboundLimiter("inbound", 10, &users, nil); err != nil {
		t.Fatalf("AddInboundLimiter(inbound) error = %v", err)
	}
	userKey := "inbound|user@example.test|1"
	if _, _, rejected := runtimeLimiter.Admit("inbound", userKey, "192.0.2.1", nil, nil); rejected {
		t.Fatal("Admit() rejected configured user")
	}
	if err := runtimeLimiter.UpdateGlobalDevices("inbound", map[int][]string{
		1: {"198.51.100.1"},
	}); err != nil {
		t.Fatalf("UpdateGlobalDevices() error = %v", err)
	}

	const redisPassword = "snapshot-must-not-contain-this-password"
	globalUsers := []api.UserInfo{{UID: 2, Email: "global@example.test"}}
	if err := runtimeLimiter.AddInboundLimiter("global", 0, &globalUsers, &commonlimiter.GlobalDeviceLimitConfig{
		Enable:        true,
		RedisNetwork:  "tcp",
		RedisAddr:     "127.0.0.1:6379",
		RedisUsername: "snapshot-user",
		RedisPassword: redisPassword,
		RedisDB:       3,
		Timeout:       1,
		Expiry:        60,
	}); err != nil {
		t.Fatalf("AddInboundLimiter(global) error = %v", err)
	}

	snapshot := runtimeLimiter.StateSnapshot()
	if snapshot.Closed {
		t.Fatal("StateSnapshot().Closed = true for active limiter")
	}
	inbound, ok := snapshot.Inbounds["inbound"]
	if !ok {
		t.Fatal("StateSnapshot() omitted applied inbound")
	}
	if inbound.Tag != "inbound" || inbound.NodeSpeedLimit != 10 {
		t.Fatalf("inbound identity = tag:%q node_limit:%d", inbound.Tag, inbound.NodeSpeedLimit)
	}
	if got := inbound.Users[userKey]; got.UID != 1 || got.SpeedLimit != 100 || got.DeviceLimit != 2 {
		t.Fatalf("user snapshot = %+v", got)
	}
	if got := inbound.Buckets[userKey]; got.Limit != 10 || got.Burst != 10 {
		t.Fatalf("bucket snapshot = %+v, want limit/burst 10", got)
	}
	if len(inbound.OnlineUsers) != 1 || inbound.OnlineUsers[0].UID != 1 || inbound.OnlineUsers[0].IP != "192.0.2.1" {
		t.Fatalf("online snapshot = %#v", inbound.OnlineUsers)
	}
	if !inbound.GlobalDevicesFresh || len(inbound.GlobalDevices[1]) != 1 ||
		inbound.GlobalDevices[1][0] != "198.51.100.1" {
		t.Fatalf("global device snapshot = fresh:%v devices:%#v", inbound.GlobalDevicesFresh, inbound.GlobalDevices)
	}
	global, ok := snapshot.Inbounds["global"]
	if !ok || !global.GlobalLimitEnabled || global.GlobalLimitClosed {
		t.Fatalf("global limit snapshot = present:%v enabled:%v closed:%v", ok, global.GlobalLimitEnabled, global.GlobalLimitClosed)
	}
	if rendered := fmt.Sprintf("%#v", snapshot); strings.Contains(rendered, redisPassword) ||
		strings.Contains(rendered, "snapshot-user") || strings.Contains(rendered, "127.0.0.1:6379") {
		t.Fatalf("StateSnapshot() exposed Redis credentials or address: %s", rendered)
	}

	delete(inbound.Users, userKey)
	delete(inbound.Buckets, userKey)
	inbound.OnlineUsers[0].IP = "203.0.113.99"
	inbound.GlobalDevices[1][0] = "203.0.113.100"
	snapshot.Inbounds["inbound"] = inbound
	delete(snapshot.Inbounds, "global")

	fresh := runtimeLimiter.StateSnapshot()
	freshInbound := fresh.Inbounds["inbound"]
	if _, ok := freshInbound.Users[userKey]; !ok {
		t.Fatal("mutating snapshot users changed limiter state")
	}
	if _, ok := freshInbound.Buckets[userKey]; !ok {
		t.Fatal("mutating snapshot buckets changed limiter state")
	}
	if freshInbound.OnlineUsers[0].IP != "192.0.2.1" {
		t.Fatalf("mutating snapshot online IP changed limiter state: %#v", freshInbound.OnlineUsers)
	}
	if freshInbound.GlobalDevices[1][0] != "198.51.100.1" {
		t.Fatalf("mutating snapshot global devices changed limiter state: %#v", freshInbound.GlobalDevices)
	}
	if _, ok := fresh.Inbounds["global"]; !ok {
		t.Fatal("deleting snapshot inbound changed limiter state")
	}
}
