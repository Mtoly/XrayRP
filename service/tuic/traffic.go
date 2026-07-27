package tuic

import (
	"errors"
	"net"
	"reflect"
	"time"

	"github.com/sagernet/sing-box/option"
	log "github.com/sirupsen/logrus"
	"golang.org/x/time/rate"

	"github.com/Mtoly/XrayRP/api"
	"github.com/Mtoly/XrayRP/common/serverstatus"
	"github.com/Mtoly/XrayRP/service/internal/trafficstats"
)

func (s *TuicService) syncUsers(userInfo *[]api.UserInfo) {
	if userInfo == nil {
		return
	}

	nodeInfo, _, _ := s.appliedStateSnapshot()
	var nodeLimit uint64
	if nodeInfo != nil {
		nodeLimit = nodeInfo.SpeedLimit
	}

	s.mu.Lock()
	defer s.mu.Unlock()
	state := reconcileUserState(*userInfo, nodeLimit, userState{
		traffic:      s.traffic,
		onlineIPs:    s.onlineIPs,
		ipLastActive: s.ipLastActive,
		rateLimiters: s.rateLimiters,
	})
	s.applyUserStateLocked(state)
	if s.logger != nil {
		s.logger.Infof("TUIC user sync complete: %d auth users configured", len(state.authUsers))
	}
}

func (s *TuicService) buildCandidateUserState(userInfo *[]api.UserInfo, nodeInfo *api.NodeInfo) userState {
	state := s.cloneCandidateUserState()
	if userInfo == nil {
		return state
	}
	var nodeLimit uint64
	if nodeInfo != nil {
		nodeLimit = nodeInfo.SpeedLimit
	}
	return reconcileUserState(*userInfo, nodeLimit, state)
}

func (s *TuicService) cloneCandidateUserState() userState {
	s.mu.RLock()
	defer s.mu.RUnlock()

	state := userState{
		users:        make(map[string]userRecord, len(s.users)),
		traffic:      make(map[string]*userTraffic, len(s.traffic)),
		onlineIPs:    make(map[string]map[string]struct{}, len(s.onlineIPs)),
		ipLastActive: make(map[string]map[string]time.Time, len(s.ipLastActive)),
		authUsers:    append([]option.TUICUser(nil), s.authUsers...),
		rateLimiters: cloneRateLimiters(s.rateLimiters),
	}
	for key, user := range s.users {
		state.users[key] = user
	}
	for key, traffic := range s.traffic {
		if traffic == nil {
			state.traffic[key] = nil
			continue
		}
		cloned := *traffic
		state.traffic[key] = &cloned
	}
	for key, ips := range s.onlineIPs {
		cloned := make(map[string]struct{}, len(ips))
		for ip := range ips {
			cloned[ip] = struct{}{}
		}
		state.onlineIPs[key] = cloned
	}
	for key, activity := range s.ipLastActive {
		cloned := make(map[string]time.Time, len(activity))
		for ip, seenAt := range activity {
			cloned[ip] = seenAt
		}
		state.ipLastActive[key] = cloned
	}
	return state
}

func (s *TuicService) authUsersSnapshot() []option.TUICUser {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return append([]option.TUICUser(nil), s.authUsers...)
}

func cloneRateLimiters(current map[string]*rate.Limiter) map[string]*rate.Limiter {
	cloned := make(map[string]*rate.Limiter, len(current))
	for key, limiter := range current {
		if limiter != nil {
			cloned[key] = rate.NewLimiter(limiter.Limit(), limiter.Burst())
		}
	}
	return cloned
}

func reconcileUserState(userInfo []api.UserInfo, nodeLimit uint64, state userState) userState {
	if state.traffic == nil {
		state.traffic = make(map[string]*userTraffic)
	}
	if state.onlineIPs == nil {
		state.onlineIPs = make(map[string]map[string]struct{})
	}
	if state.ipLastActive == nil {
		state.ipLastActive = make(map[string]map[string]time.Time)
	}
	if state.rateLimiters == nil {
		state.rateLimiters = make(map[string]*rate.Limiter)
	}

	newUsers := make(map[string]userRecord, len(userInfo))
	authUsers := make([]option.TUICUser, 0, len(userInfo))
	newRateLimiters := make(map[string]*rate.Limiter)

	for _, u := range userInfo {
		// TUIC uses UUID as the primary authentication key
		key := u.UUID
		if key == "" {
			continue
		}

		rec := userRecord{
			UID:         u.UID,
			Email:       u.Email,
			DeviceLimit: u.DeviceLimit,
			SpeedLimit:  u.SpeedLimit,
		}

		limit := determineRate(nodeLimit, u.SpeedLimit)
		var limiter *rate.Limiter
		if limit > 0 {
			if old, ok := state.rateLimiters[key]; ok && old != nil {
				old.SetLimit(rate.Limit(limit))
				old.SetBurst(int(limit))
				limiter = old
			}
			if limiter == nil {
				limiter = rate.NewLimiter(rate.Limit(limit), int(limit))
			}
		}

		if _, ok := newUsers[key]; !ok {
			newUsers[key] = rec
		}
		if limiter != nil {
			newRateLimiters[key] = limiter
		}
		if _, ok := state.traffic[key]; !ok {
			state.traffic[key] = &userTraffic{}
		}

		// TUIC user with UUID and password (using Passwd as password)
		password := u.Passwd
		if password == "" {
			password = u.UUID
		}
		authUsers = append(authUsers, option.TUICUser{
			Name:     u.UUID,
			UUID:     u.UUID,
			Password: password,
		})
	}

	state.users = newUsers
	state.authUsers = authUsers
	state.rateLimiters = newRateLimiters

	for uuid := range state.onlineIPs {
		if _, ok := newUsers[uuid]; !ok {
			delete(state.onlineIPs, uuid)
		}
	}
	for uuid := range state.ipLastActive {
		if _, ok := newUsers[uuid]; !ok {
			delete(state.ipLastActive, uuid)
		}
	}
	return state
}

func (s *TuicService) applyUserStateLocked(state userState) {
	s.users = state.users
	s.traffic = state.traffic
	s.onlineIPs = state.onlineIPs
	s.ipLastActive = state.ipLastActive
	s.authUsers = state.authUsers
	s.rateLimiters = state.rateLimiters
}

func (s *TuicService) recordTraffic(uuid string, up, down uint64, host string) {
	s.mu.Lock()
	defer s.mu.Unlock()

	t, ok := s.traffic[uuid]
	if !ok {
		t = &userTraffic{}
		s.traffic[uuid] = t
	}
	t.Upload = trafficstats.Add(t.Upload, up)
	t.Download = trafficstats.Add(t.Download, down)

	if host == "" {
		return
	}
	if ipSet, exists := s.onlineIPs[uuid]; exists {
		ipSet[host] = struct{}{}
	} else {
		s.onlineIPs[uuid] = map[string]struct{}{host: {}}
	}
	seenAt := time.Now()
	if activeMap, exists := s.ipLastActive[uuid]; exists {
		activeMap[host] = seenAt
	} else {
		s.ipLastActive[uuid] = map[string]time.Time{host: seenAt}
	}
}

func (s *TuicService) allowConnection(uuid, ip string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()

	user, ok := s.users[uuid]
	if !ok {
		return false
	}

	host := ip
	if host != "" {
		if h, _, err := net.SplitHostPort(host); err == nil {
			host = h
		}
	}
	if host == "" {
		host = "unknown"
	}

	ips, ok := s.onlineIPs[uuid]
	if !ok {
		ips = make(map[string]struct{})
		s.onlineIPs[uuid] = ips
	}

	// Initialize ipLastActive map for this user if not exists
	activeMap, ok := s.ipLastActive[uuid]
	if !ok {
		activeMap = make(map[string]time.Time)
		s.ipLastActive[uuid] = activeMap
	}

	if _, exists := ips[host]; !exists {
		if user.DeviceLimit > 0 && len(ips) >= user.DeviceLimit {
			s.logger.WithFields(log.Fields{
				"uid":         user.UID,
				"deviceLimit": user.DeviceLimit,
				"remote":      ip,
			}).Warn("TUIC user exceeded device limit")
			return false
		}
		ips[host] = struct{}{}
	}

	// Update last active time for this IP
	activeMap[host] = time.Now()

	return true
}

func trafficHost(addr net.Addr) string {
	if addr == nil {
		return ""
	}

	host := addr.String()
	if h, _, err := net.SplitHostPort(host); err == nil {
		host = h
	}
	return host
}

func (s *TuicService) collectUsage() ([]api.UserTraffic, []api.OnlineUser, map[string]userTraffic) {
	s.mu.Lock()
	defer s.mu.Unlock()

	snapshot := make(map[string]userTraffic)
	var uts []api.UserTraffic
	for uuid, t := range s.traffic {
		user, ok := s.users[uuid]
		if !ok {
			continue
		}
		if t.Upload == 0 && t.Download == 0 {
			continue
		}
		snapshot[uuid] = userTraffic{
			Upload:   t.Upload,
			Download: t.Download,
		}
		uts = append(uts, api.UserTraffic{
			UID:      user.UID,
			Email:    user.Email,
			Upload:   t.Upload,
			Download: t.Download,
		})
		t.Upload = 0
		t.Download = 0
	}

	// Collect online users before clearing
	// This mimics the behavior of traditional Xray protocols (VMess/VLESS/Trojan)
	var online []api.OnlineUser
	for uuid, ipSet := range s.onlineIPs {
		user, ok := s.users[uuid]
		if !ok {
			continue
		}
		for ip := range ipSet {
			online = append(online, api.OnlineUser{UID: user.UID, IP: ip})
		}
	}

	// Clear online IPs and last active tracking after collection
	// This prevents zombie connections from accumulating over time
	// Similar to limiter.GetOnlineDevice() which calls inboundInfo.UserOnlineIP.Delete(email)
	// Only IPs that are actively used in the next reporting cycle will be tracked again
	s.onlineIPs = make(map[string]map[string]struct{})
	s.ipLastActive = make(map[string]map[string]time.Time)

	return uts, online, snapshot
}

func (s *TuicService) restoreTraffic(snapshot map[string]userTraffic) {
	if len(snapshot) == 0 {
		return
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	for uuid, snap := range snapshot {
		counter, ok := s.traffic[uuid]
		if !ok || counter == nil {
			counter = &userTraffic{}
			s.traffic[uuid] = counter
		}
		counter.Upload = trafficstats.Add(counter.Upload, uint64(snap.Upload))
		counter.Download = trafficstats.Add(counter.Download, uint64(snap.Download))
	}
}

func (s *TuicService) userMonitor() error {
	_, tag, startAt := s.appliedStateSnapshot()
	if startAt.IsZero() || time.Since(startAt) < time.Duration(s.config.UpdatePeriodic)*time.Second {
		return nil
	}

	CPU, Mem, Disk, Uptime, err := serverstatus.GetSystemInfo()
	if err != nil {
		s.logger.Print(err)
	} else {
		if err = s.apiClient.ReportNodeStatus(&api.NodeStatus{CPU: CPU, Mem: Mem, Disk: Disk, Uptime: Uptime}); err != nil {
			s.logger.Print(err)
		}
	}

	usersChanged := true
	newUserInfo, err := s.apiClient.GetUserList()
	if err != nil {
		if errors.Is(err, api.ErrUserNotModified) {
			usersChanged = false
		} else {
			s.logger.Print(err)
			return nil
		}
	}
	if usersChanged {
		s.syncUsers(newUserInfo)
	}

	// Check Rule
	if !s.config.DisableGetRule && s.rules != nil {
		if ruleList, err := s.apiClient.GetNodeRule(); err != nil {
			if !errors.Is(err, api.ErrRuleNotModified) {
				s.logger.Printf("Get rule list filed: %s", err)
			}
		} else if ruleList != nil {
			if err := s.rules.UpdateRule(tag, *ruleList); err != nil {
				s.logger.Print(err)
			}
		}
	}

	userTraffic, onlineUsers, snapshot := s.collectUsage()
	if len(userTraffic) > 0 && !s.config.DisableUploadTraffic {
		if err = s.apiClient.ReportUserTraffic(&userTraffic); err != nil {
			s.logger.Print(err)
			// Restore counters so traffic is not lost and can be retried.
			s.restoreTraffic(snapshot)
		}
	}
	if len(onlineUsers) > 0 {
		if err = s.apiClient.ReportNodeOnlineUsers(&onlineUsers); err != nil {
			s.logger.Print(err)
		}
	}

	// Report Illegal user
	if s.rules != nil {
		if detectResult, err := s.rules.GetDetectResult(tag); err != nil {
			s.logger.Print(err)
		} else if len(*detectResult) > 0 {
			if err = s.apiClient.ReportIllegal(detectResult); err != nil {
				s.logger.Print(err)
			} else {
				s.logger.Printf("Report %d illegal behaviors", len(*detectResult))
			}
		}
	}

	return nil
}

// nodeMonitor watches for TUIC node configuration changes from the panel
// (port, TLS/SNI, TUIC-specific options, etc.) and hot-reloads the sing-box
// instance when a change is detected.
func (s *TuicService) nodeMonitor() error {
	currentNode, _, startAt := s.appliedStateSnapshot()
	if startAt.IsZero() || time.Since(startAt) < time.Duration(s.config.UpdatePeriodic)*time.Second {
		return nil
	}

	nodeInfo, err := s.apiClient.GetNodeInfo()
	if err != nil {
		if errors.Is(err, api.ErrNodeNotModified) {
			return nil
		}
		s.logger.Print(err)
		return nil
	}

	if nodeInfo == nil || nodeInfo.NodeType != "Tuic" {
		if s.logger != nil {
			if nodeInfo == nil {
				s.logger.Warn("TUIC node monitor: unexpected node info: <nil>")
			} else {
				s.logger.Warnf("TUIC node monitor: unexpected node info: type=%s id=%d", nodeInfo.NodeType, nodeInfo.NodeID)
			}
		}
		return nil
	}

	// Some panels update node-related metadata frequently without changing the
	// actual TUIC configuration, which may cause the ETag to change on every
	// poll. Guard against unnecessary hot-reloads by comparing the new NodeInfo
	// with the current in-memory value, similar to controller.nodeInfoMonitor.
	if currentNode != nil && reflect.DeepEqual(currentNode, nodeInfo) {
		return nil
	}

	if err := s.reloadNode(nodeInfo); err != nil {
		s.logger.Printf("TUIC node reload failed: %v", err)
	}

	return nil
}

func determineRate(nodeLimit, userLimit uint64) (limit uint64) {
	if nodeLimit == 0 || userLimit == 0 {
		if nodeLimit > userLimit {
			return nodeLimit
		} else if nodeLimit < userLimit {
			return userLimit
		}
		return 0
	}

	if nodeLimit > userLimit {
		return userLimit
	} else if nodeLimit < userLimit {
		return nodeLimit
	}
	return nodeLimit
}

func (s *TuicService) applyNodeRateLimitLocked(nodeLimit uint64) {
	updated := make(map[string]*rate.Limiter)
	for key, user := range s.users {
		limit := determineRate(nodeLimit, user.SpeedLimit)
		if limit == 0 {
			continue
		}
		limiter := s.rateLimiters[key]
		if limiter == nil {
			limiter = rate.NewLimiter(rate.Limit(limit), int(limit))
		} else {
			limiter.SetLimit(rate.Limit(limit))
			limiter.SetBurst(int(limit))
		}
		updated[key] = limiter
	}
	s.rateLimiters = updated
}
