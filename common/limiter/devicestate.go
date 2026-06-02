package limiter

import (
	"sort"
	"sync"
	"time"
)

const defaultGlobalDeviceTTL = 60 * time.Second

type globalDeviceState struct {
	mu        sync.RWMutex
	devices   map[int]map[string]struct{}
	updatedAt time.Time
	ttl       time.Duration
	now       func() time.Time
}

func newGlobalDeviceState() *globalDeviceState {
	return &globalDeviceState{
		ttl: defaultGlobalDeviceTTL,
		now: time.Now,
	}
}

func (s *globalDeviceState) Replace(devices map[int][]string) {
	if s == nil {
		return
	}

	copied := make(map[int]map[string]struct{}, len(devices))
	for uid, ips := range devices {
		ipSet := make(map[string]struct{}, len(ips))
		for _, ip := range ips {
			ipSet[ip] = struct{}{}
		}
		copied[uid] = ipSet
	}

	s.mu.Lock()
	defer s.mu.Unlock()
	s.devices = copied
	s.updatedAt = s.currentTime()
}

func (s *globalDeviceState) Clear() {
	if s == nil {
		return
	}

	s.mu.Lock()
	defer s.mu.Unlock()
	s.devices = nil
	s.updatedAt = time.Time{}
}

func (s *globalDeviceState) Fresh() bool {
	if s == nil {
		return false
	}

	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.freshAtLocked(s.currentTime())
}

func (s *globalDeviceState) ShouldReject(uid int, candidateIP string, deviceLimit int, localIPs []string) bool {
	if s == nil || deviceLimit <= 0 {
		return false
	}

	s.mu.RLock()
	defer s.mu.RUnlock()
	if !s.freshAtLocked(s.currentTime()) {
		return false
	}

	combined := make(map[string]struct{}, len(localIPs)+1)
	if globalIPs, ok := s.devices[uid]; ok {
		for ip := range globalIPs {
			combined[ip] = struct{}{}
		}
	}
	for _, ip := range localIPs {
		combined[ip] = struct{}{}
	}
	combined[candidateIP] = struct{}{}

	if len(combined) <= deviceLimit {
		return false
	}

	ips := make([]string, 0, len(combined))
	for ip := range combined {
		ips = append(ips, ip)
	}
	sort.Strings(ips)

	for idx, ip := range ips {
		if idx >= deviceLimit {
			break
		}
		if ip == candidateIP {
			return false
		}
	}
	return true
}

func (s *globalDeviceState) currentTime() time.Time {
	if s.now != nil {
		return s.now()
	}
	return time.Now()
}

func (s *globalDeviceState) stateTTL() time.Duration {
	if s.ttl > 0 {
		return s.ttl
	}
	return defaultGlobalDeviceTTL
}

func (s *globalDeviceState) freshAtLocked(now time.Time) bool {
	return s.devices != nil && !s.updatedAt.IsZero() && now.Sub(s.updatedAt) <= s.stateTTL()
}
