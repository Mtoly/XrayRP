package limiter

import (
	"fmt"
	"sync"
	"time"

	"github.com/Mtoly/XrayRP/api"
)

// aliveSnapshotState keeps HTTP count-mode policy separate from the online
// entries, whose records expire according to the local online TTL.
type aliveSnapshotState struct {
	uids sync.Map // Key: panel UID -> *aliveUIDState
}

type aliveUIDState struct {
	// mu serializes every alias of one panel UID. Admission lock order is the
	// inbound admission lock, this mutex, then the selected online-entry mutex.
	mu         sync.Mutex
	countMode  bool
	panelCount int
	localIPs   map[string]struct{}
	pending    map[string]struct{}
}

func newAliveSnapshotState() *aliveSnapshotState {
	return &aliveSnapshotState{}
}

func (s *aliveSnapshotState) uidState(uid int, create bool) *aliveUIDState {
	if s == nil {
		return nil
	}
	if value, ok := s.uids.Load(uid); ok {
		return value.(*aliveUIDState)
	}
	if !create {
		return nil
	}
	candidate := &aliveUIDState{}
	value, _ := s.uids.LoadOrStore(uid, candidate)
	return value.(*aliveUIDState)
}

func (s *aliveSnapshotState) inheritForUsers(source *aliveSnapshotState, users *sync.Map) {
	if s == nil || source == nil || users == nil {
		return
	}
	seen := make(map[int]struct{})
	users.Range(func(_, value interface{}) bool {
		uid := value.(userPolicy).UID
		if _, ok := seen[uid]; ok {
			return true
		}
		seen[uid] = struct{}{}
		if inherited := source.uidState(uid, false); inherited != nil {
			s.uids.Store(uid, inherited)
		}
		return true
	})
}

func (s *aliveSnapshotState) retainForUsers(users *sync.Map) {
	if s == nil {
		return
	}
	kept := make(map[int]struct{})
	if users != nil {
		users.Range(func(_, value interface{}) bool {
			kept[value.(userPolicy).UID] = struct{}{}
			return true
		})
	}
	s.uids.Range(func(key, _ interface{}) bool {
		if _, ok := kept[key.(int)]; !ok {
			s.uids.Delete(key)
		}
		return true
	})
}

func (s *aliveSnapshotState) clearModes() {
	if s == nil {
		return
	}
	s.uids.Range(func(_, value interface{}) bool {
		state := value.(*aliveUIDState)
		state.mu.Lock()
		state.countMode = false
		state.panelCount = 0
		state.localIPs = nil
		state.pending = nil
		state.mu.Unlock()
		return true
	})
}

func (s *aliveSnapshotState) applyCount(uid, count int, reported map[string]struct{}, localIPs map[string]struct{}) {
	state := s.uidState(uid, true)
	state.mu.Lock()
	defer state.mu.Unlock()

	state.countMode = true
	state.panelCount = count
	state.localIPs = cloneIPSet(localIPs)
	state.pending = make(map[string]struct{}, len(localIPs))
	for ip := range localIPs {
		if _, covered := reported[ip]; !covered {
			state.pending[ip] = struct{}{}
		}
	}
}

func (s *aliveSnapshotState) applyList(uid int) {
	state := s.uidState(uid, true)
	state.mu.Lock()
	state.countMode = false
	state.panelCount = 0
	state.localIPs = nil
	state.pending = nil
	state.mu.Unlock()
}

func cloneIPSet(source map[string]struct{}) map[string]struct{} {
	if source == nil {
		return make(map[string]struct{})
	}
	result := make(map[string]struct{}, len(source))
	for ip := range source {
		result[ip] = struct{}{}
	}
	return result
}

func (s *aliveUIDState) admitIP(entry *userOnlineEntry, ip string, uid, deviceLimit int, globalDevices *globalDeviceState) (reject bool, retry bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if !s.countMode {
		return entry.admitIP(ip, uid, deviceLimit, globalDevices)
	}

	entry.mu.Lock()
	defer entry.mu.Unlock()
	if entry.retired {
		return false, true
	}

	if entry.hasLocalIP(ip) {
		entry.touchLocalIP(ip, uid)
		s.localIPs[ip] = struct{}{}
		return false, false
	}

	localIPs := entry.snapshotIPs()
	reject, usedFreshGlobal, admitted := globalDevices.admissionDecisionFresh(uid, ip, deviceLimit, localIPs)
	if usedFreshGlobal {
		if reject {
			return true, false
		}
		entry.pruneToAdmitted(admitted)
		entry.touchLocalIP(ip, uid)
		s.localIPs[ip] = struct{}{}
		s.pending[ip] = struct{}{}
		return false, false
	}

	if hasIP(s.localIPs, ip) || hasIP(s.pending, ip) {
		entry.touchLocalIP(ip, uid)
		s.localIPs[ip] = struct{}{}
		return false, false
	}

	if deviceLimit > 0 && s.panelCount+len(s.pending) >= deviceLimit {
		return true, false
	}
	entry.touchLocalIP(ip, uid)
	s.localIPs[ip] = struct{}{}
	s.pending[ip] = struct{}{}
	return false, false
}

func hasIP(ips map[string]struct{}, ip string) bool {
	_, ok := ips[ip]
	return ok
}

func (i *inboundState) admitIP(entry *userOnlineEntry, ip string, uid, deviceLimit int, globalDevices *globalDeviceState, atomicGlobal bool) (reject bool, retry bool) {
	if atomicGlobal || i == nil || i.aliveSnapshot == nil {
		return entry.admitIP(ip, uid, deviceLimit, globalDevices)
	}
	if i.GlobalLimit != nil && i.GlobalLimit.config != nil && i.GlobalLimit.config.Enable {
		return entry.admitIP(ip, uid, deviceLimit, globalDevices)
	}
	if state := i.aliveSnapshot.uidState(uid, false); state != nil {
		return state.admitIP(entry, ip, uid, deviceLimit, globalDevices)
	}
	return entry.admitIP(ip, uid, deviceLimit, globalDevices)
}

// SyncAliveSnapshot applies a complete typed panel snapshot. A nil snapshot is
// not an update. Counts advance only when reportedIPs is non-nil, the receipt
// of a successful report from the same cycle; an empty non-nil map is a valid
// empty report.
func (l *Limiter) SyncAliveSnapshot(tag string, snapshot *api.AliveSnapshot, reportedIPs map[int][]string) error {
	if err := l.beginMutation(); err != nil {
		return err
	}
	defer l.endMutation()

	inboundInfo, ok := l.loadAppliedInbound(tag)
	if !ok {
		return fmt.Errorf("no such inbound in limiter: %s", tag)
	}
	if snapshot == nil {
		return nil
	}
	if inboundInfo.GlobalLimit != nil && inboundInfo.GlobalLimit.config != nil && inboundInfo.GlobalLimit.config.Enable {
		return nil
	}

	l.drainAdmissions(inboundInfo)
	defer inboundInfo.activateAdmissions()

	now := time.Now().Unix()
	currentLocal := localIPsByUID(inboundInfo, now)
	clearPanelSeedIPs(inboundInfo)

	for uid, ips := range snapshot.IPs {
		inboundInfo.aliveSnapshot.applyList(uid)
		applyPanelIPs(inboundInfo, uid, ips)
	}

	if reportedIPs == nil {
		return nil
	}
	reportedSets := reportIPSets(reportedIPs)
	processed := make(map[int]struct{}, len(snapshot.Counts))
	for uid, count := range snapshot.Counts {
		if _, isList := snapshot.IPs[uid]; isList {
			continue
		}
		processed[uid] = struct{}{}
		inboundInfo.aliveSnapshot.applyCount(uid, count, reportedSets[uid], currentLocal[uid])
	}
	inboundInfo.aliveSnapshot.uids.Range(func(key, value interface{}) bool {
		uid := key.(int)
		state := value.(*aliveUIDState)
		state.mu.Lock()
		countMode := state.countMode
		state.mu.Unlock()
		if !countMode {
			return true
		}
		if _, ok := processed[uid]; ok {
			return true
		}
		if _, isList := snapshot.IPs[uid]; isList {
			return true
		}
		inboundInfo.aliveSnapshot.applyCount(uid, 0, reportedSets[uid], currentLocal[uid])
		return true
	})
	return nil
}

func reportIPSets(reported map[int][]string) map[int]map[string]struct{} {
	result := make(map[int]map[string]struct{}, len(reported))
	for uid, ips := range reported {
		set := make(map[string]struct{}, len(ips))
		for _, ip := range ips {
			set[ip] = struct{}{}
		}
		result[uid] = set
	}
	return result
}

func localIPsByUID(inboundInfo *inboundState, now int64) map[int]map[string]struct{} {
	result := make(map[int]map[string]struct{})
	inboundInfo.UserOnlineIP.Range(func(key, value interface{}) bool {
		userValue, ok := inboundInfo.UserInfo.Load(key)
		if !ok {
			return true
		}
		uid := userValue.(userPolicy).UID
		entry := value.(*userOnlineEntry)
		entry.mu.Lock()
		entry.ips.Range(func(ip, value interface{}) bool {
			conn := value.(connIP)
			if !conn.Local || now-conn.LastSeen > ipTTL {
				return true
			}
			ips := result[uid]
			if ips == nil {
				ips = make(map[string]struct{})
				result[uid] = ips
			}
			ips[ip.(string)] = struct{}{}
			return true
		})
		entry.mu.Unlock()
		return true
	})
	return result
}

func clearPanelSeedIPs(inboundInfo *inboundState) {
	inboundInfo.UserOnlineIP.Range(func(_, value interface{}) bool {
		entry := value.(*userOnlineEntry)
		entry.mu.Lock()
		entry.ips.Range(func(ip, value interface{}) bool {
			if !value.(connIP).Local {
				entry.deleteIP(ip)
			}
			return true
		})
		entry.mu.Unlock()
		return true
	})
}

func applyPanelIPs(inboundInfo *inboundState, uid int, ips []string) {
	inboundInfo.UserInfo.Range(func(key, value interface{}) bool {
		if value.(userPolicy).UID != uid {
			return true
		}
		entryValue, ok := inboundInfo.UserOnlineIP.Load(key)
		if !ok {
			entryValue, _ = inboundInfo.UserOnlineIP.LoadOrStore(key, newUserOnlineEntry())
		}
		entry := entryValue.(*userOnlineEntry)
		entry.mu.Lock()
		for _, ip := range ips {
			entry.touchPanelIP(ip, uid)
		}
		entry.mu.Unlock()
		return true
	})
}
