package limiter

import (
	"sort"
	"time"

	"github.com/Mtoly/XrayRP/api"
	"golang.org/x/time/rate"
)

// LimiterSnapshot is a detached read-only view of the currently applied
// limiter state. Mutating its maps or slices does not change admission state.
// It contains user keys and IP addresses and must not be logged unredacted or
// used as metrics labels.
type LimiterSnapshot struct {
	Closed   bool
	Inbounds map[string]InboundSnapshot
}

// InboundSnapshot is a detached read-only view of one applied inbound.
// Runtime objects, cache backends, and global-limit credentials are omitted.
type InboundSnapshot struct {
	Tag                    string
	NodeSpeedLimit         uint64
	Users                  map[string]UserInfo
	Buckets                map[string]BucketSnapshot
	OnlineUsers            []api.OnlineUser
	GlobalDevices          map[int][]string
	GlobalDevicesUpdatedAt time.Time
	GlobalDevicesFresh     bool
	GlobalLimitEnabled     bool
	GlobalLimitClosed      bool
}

// BucketSnapshot contains the observable value state of one rate limiter.
type BucketSnapshot struct {
	Limit float64
	Burst int
}

// StateSnapshot returns a detached snapshot of valid applied inbounds.
// Forged or detached entries in the legacy mutable map are not published.
func (l *Limiter) StateSnapshot() LimiterSnapshot {
	snapshot := LimiterSnapshot{Inbounds: make(map[string]InboundSnapshot)}
	if l == nil {
		snapshot.Closed = true
		return snapshot
	}

	l.lifecycleMu.Lock()
	defer l.lifecycleMu.Unlock()

	snapshot.Closed = l.closed.Load()
	if l.ownedInboundInfo == nil {
		return snapshot
	}
	l.ownedInboundInfo.Range(func(key, value interface{}) bool {
		tag, keyOK := key.(string)
		owned, valueOK := value.(*inboundState)
		if !keyOK || !valueOK || owned == nil {
			return true
		}
		applied, ok := l.loadAppliedInbound(tag)
		if !ok || applied != owned {
			return true
		}
		if inbound, ok := snapshotAppliedInbound(owned); ok {
			snapshot.Inbounds[tag] = inbound
		}
		return true
	})
	return snapshot
}

func snapshotAppliedInbound(state *inboundState) (InboundSnapshot, bool) {
	if state == nil {
		return InboundSnapshot{}, false
	}

	state.admissionMu.Lock()
	defer state.admissionMu.Unlock()
	if state.retired || !state.applied.Load() {
		return InboundSnapshot{}, false
	}

	snapshot := InboundSnapshot{
		Tag:            state.Tag,
		NodeSpeedLimit: state.NodeSpeedLimit,
		Users:          make(map[string]UserInfo),
		Buckets:        make(map[string]BucketSnapshot),
		GlobalDevices:  make(map[int][]string),
	}
	if state.UserInfo != nil {
		state.UserInfo.Range(func(key, value interface{}) bool {
			userKey, keyOK := key.(string)
			user, valueOK := value.(UserInfo)
			if keyOK && valueOK {
				snapshot.Users[userKey] = user
			}
			return true
		})
	}
	if state.BucketHub != nil {
		state.BucketHub.Range(func(key, value interface{}) bool {
			userKey, keyOK := key.(string)
			bucket, valueOK := value.(*rate.Limiter)
			if keyOK && valueOK {
				snapshot.Buckets[userKey] = BucketSnapshot{
					Limit: float64(bucket.Limit()),
					Burst: bucket.Burst(),
				}
			}
			return true
		})
	}
	if state.UserOnlineIP != nil {
		state.UserOnlineIP.Range(func(_, value interface{}) bool {
			entry, ok := value.(*userOnlineEntry)
			if ok && entry != nil {
				entry.collectOnline(&snapshot.OnlineUsers)
			}
			return true
		})
	}
	sort.Slice(snapshot.OnlineUsers, func(i, j int) bool {
		if snapshot.OnlineUsers[i].UID == snapshot.OnlineUsers[j].UID {
			return snapshot.OnlineUsers[i].IP < snapshot.OnlineUsers[j].IP
		}
		return snapshot.OnlineUsers[i].UID < snapshot.OnlineUsers[j].UID
	})

	snapshot.GlobalDevices, snapshot.GlobalDevicesUpdatedAt, snapshot.GlobalDevicesFresh =
		snapshotGlobalDeviceState(state.GlobalDevices)
	snapshot.GlobalLimitEnabled, snapshot.GlobalLimitClosed = snapshotGlobalLimitState(state.GlobalLimit)
	return snapshot, true
}

func snapshotGlobalDeviceState(state *globalDeviceState) (map[int][]string, time.Time, bool) {
	devices := make(map[int][]string)
	if state == nil {
		return devices, time.Time{}, false
	}

	state.mu.RLock()
	defer state.mu.RUnlock()
	for uid, values := range state.devices {
		ips := make([]string, 0, len(values))
		for ip := range values {
			ips = append(ips, ip)
		}
		sort.Strings(ips)
		devices[uid] = ips
	}
	return devices, state.updatedAt, state.freshAtLocked(state.currentTime())
}

func snapshotGlobalLimitState(state *globalLimitState) (enabled bool, closed bool) {
	if state == nil {
		return false, false
	}

	state.useMu.RLock()
	defer state.useMu.RUnlock()
	return state.config != nil && state.config.Enable, state.closed
}
