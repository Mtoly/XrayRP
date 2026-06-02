package limiter

import (
	"sort"
	"strings"
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
			trimmed := strings.TrimSpace(ip)
			if trimmed == "" {
				continue
			}
			ipSet[trimmed] = struct{}{}
		}
		if len(ipSet) > 0 {
			copied[uid] = ipSet
		}
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
	reject, _, _ := s.admissionDecisionFresh(uid, candidateIP, deviceLimit, localIPs)
	return reject
}

func (s *globalDeviceState) ShouldRejectFresh(uid int, candidateIP string, deviceLimit int, localIPs []string) (reject bool, fresh bool) {
	reject, fresh, _ = s.admissionDecisionFresh(uid, candidateIP, deviceLimit, localIPs)
	return reject, fresh
}

func (s *globalDeviceState) admissionDecisionFresh(uid int, candidateIP string, deviceLimit int, localIPs []string) (reject bool, fresh bool, admitted map[string]struct{}) {
	if s == nil {
		return false, false, nil
	}

	s.mu.RLock()
	defer s.mu.RUnlock()
	if !s.freshAtLocked(s.currentTime()) {
		return false, false, nil
	}

	if deviceLimit <= 0 {
		return false, true, nil
	}

	globalIPs := s.devices[uid]
	candidateKnownGlobally := false
	if _, ok := globalIPs[candidateIP]; ok {
		candidateKnownGlobally = true
	}

	combined := make(map[string]struct{}, len(globalIPs)+len(localIPs)+1)
	for ip := range globalIPs {
		combined[ip] = struct{}{}
	}
	for _, ip := range localIPs {
		combined[ip] = struct{}{}
	}
	combined[candidateIP] = struct{}{}

	if candidateKnownGlobally {
		return false, true, firstSortedIPsWithRequired(combined, candidateIP, deviceLimit)
	}

	admitted = firstSortedIPs(combined, deviceLimit)
	if _, ok := admitted[candidateIP]; ok {
		return false, true, admitted
	}
	return true, true, admitted
}

func firstSortedIPs(ips map[string]struct{}, limit int) map[string]struct{} {
	if limit <= 0 {
		return nil
	}
	sorted := make([]string, 0, len(ips))
	for ip := range ips {
		sorted = append(sorted, ip)
	}
	sort.Strings(sorted)
	if len(sorted) > limit {
		sorted = sorted[:limit]
	}
	admitted := make(map[string]struct{}, len(sorted))
	for _, ip := range sorted {
		admitted[ip] = struct{}{}
	}
	return admitted
}

func firstSortedIPsWithRequired(ips map[string]struct{}, requiredIP string, limit int) map[string]struct{} {
	if limit <= 0 {
		return nil
	}
	admitted := make(map[string]struct{}, limit)
	admitted[requiredIP] = struct{}{}
	if limit == 1 {
		return admitted
	}

	sorted := make([]string, 0, len(ips))
	for ip := range ips {
		if ip != requiredIP {
			sorted = append(sorted, ip)
		}
	}
	sort.Strings(sorted)
	for _, ip := range sorted {
		if len(admitted) >= limit {
			break
		}
		admitted[ip] = struct{}{}
	}
	return admitted
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
