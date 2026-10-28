package tuic

import (
	"context"
	"errors"
	"time"

	"github.com/sagernet/sing-box/option"
	log "github.com/sirupsen/logrus"
	"golang.org/x/time/rate"

	"github.com/Mtoly/XrayRP/api"
	"github.com/Mtoly/XrayRP/common/serverstatus"
	"github.com/Mtoly/XrayRP/service"
	"github.com/Mtoly/XrayRP/service/internal/trafficstats"
)

// syncUsers installs a user snapshot in the published runtime before changing
// in-memory user state. Callers hold reloadMu so the runtime cannot be
// replaced concurrently.
func (s *TuicService) syncUsers(userInfo *[]api.UserInfo) error {
	if userInfo == nil {
		return nil
	}

	nodeInfo, _, _ := s.appliedStateSnapshot()
	var nodeLimit uint64
	if nodeInfo != nil {
		nodeLimit = nodeInfo.SpeedLimit
	}
	s.lifecycleMu.Lock()
	runtime := s.box
	s.lifecycleMu.Unlock()
	if runtime == nil {
		return errors.New("no published TUIC runtime")
	}

	s.mu.Lock()
	state := reconcileUserState(*userInfo, nodeLimit, userState{
		traffic:      s.traffic,
		onlineIPs:    s.onlineIPs,
		ipLastActive: s.ipLastActive,
		rateLimiters: s.rateLimiters,
	})
	if err := runtime.UpdateUsers(state.authUsers); err != nil {
		s.mu.Unlock()
		return err
	}
	s.applyUserStateLocked(state)
	admission := s.globalAdmission
	limits := userDeviceLimits(state.users)
	s.mu.Unlock()
	if admission != nil {
		admission.SetUsers(limits)
	}
	if s.logger != nil {
		s.logger.Infof("TUIC user sync complete: %d auth users configured", len(state.authUsers))
	}
	return nil
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

	return state
}

func (s *TuicService) applyUserStateLocked(state userState) {
	// User updates affect new authentication, not established connections.
	// Keep live reservations until their last connection closes, even if the
	// user is removed and later re-added.
	s.users = state.users
	s.traffic = state.traffic
	s.onlineIPs = state.onlineIPs
	s.ipLastActive = state.ipLastActive
	s.authUsers = state.authUsers
	s.rateLimiters = state.rateLimiters
	s.policyGeneration++
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

	// Admission owns online membership. Late traffic must not recreate an IP
	// after its last connection released the reservation.
	if _, ok := s.onlineIPs[uuid][host]; ok {
		s.ipLastActive[uuid][host] = time.Now()
	}
}

// allowConnection reserves one connection slot for an authenticated user and
// returns this connection's shared global lease, if any.
//
// Redis admission runs outside s.mu: the user snapshot and manager are read
// under a read lock, the shared reservation happens without locks, and the
// local slot is only published after the same user policy and manager are
// revalidated. Any rejection aborts the tentative Redis hold so a denied
// connection never leaves a phantom reservation behind.
func (s *TuicService) allowConnection(ctx context.Context, uuid, ip string) (*deviceConnections, globalLease, bool) {
	host := admissionHost(ip)

	s.mu.RLock()
	user, known := s.users[uuid]
	admission := s.globalAdmission
	generation := s.policyGeneration
	existing := s.connections[uuid][host]
	s.mu.RUnlock()

	if !known {
		return nil, nil, false
	}

	// A live reservation for this user and IP already holds the local slot.
	// Reusing it is local-only; in Redis mode each connection owns its own
	// global lease so renewal stops exactly when that connection closes.
	if existing != nil && admission == nil {
		s.mu.Lock()
		current, stillKnown := s.users[uuid]
		device := s.connections[uuid][host]
		if !stillKnown || current != user || device != existing || s.globalAdmission != admission || s.policyGeneration != generation {
			s.mu.Unlock()
			return nil, nil, false
		}
		device.count++
		s.onlineIPs[uuid][host] = struct{}{}
		s.ipLastActive[uuid][host] = time.Now()
		s.mu.Unlock()
		return device, nil, true
	}

	var lease globalLease
	if admission != nil {
		acquired, err := admission.Acquire(admissionContext(ctx), user.UID, host, user.DeviceLimit)
		if err != nil {
			s.logger.WithFields(log.Fields{
				"uid":    user.UID,
				"remote": ip,
			}).Warn("TUIC global device admission rejected connection")
			return nil, nil, false
		}
		lease = acquired
	}

	s.mu.Lock()
	current, stillKnown := s.users[uuid]
	if !stillKnown || current != user || s.globalAdmission != admission || s.policyGeneration != generation {
		s.mu.Unlock()
		abortGlobalLease(lease)
		return nil, nil, false
	}

	// The shared manager owns distributed capacity. Local capacity would
	// otherwise count /64-normalized IPs as separate devices, so it is only
	// applied in local-only mode. Online/reporting state is preserved either
	// way.
	if admission == nil && current.DeviceLimit > 0 {
		if _, exists := s.onlineIPs[uuid][host]; !exists && len(s.onlineIPs[uuid]) >= current.DeviceLimit {
			s.mu.Unlock()
			s.logger.WithFields(log.Fields{
				"uid":         current.UID,
				"deviceLimit": current.DeviceLimit,
				"remote":      ip,
			}).Warn("TUIC user exceeded device limit")
			return nil, nil, false
		}
	}

	if s.onlineIPs == nil {
		s.onlineIPs = make(map[string]map[string]struct{})
	}
	ips, ok := s.onlineIPs[uuid]
	if !ok {
		ips = make(map[string]struct{})
		s.onlineIPs[uuid] = ips
	}
	ips[host] = struct{}{}

	if s.ipLastActive == nil {
		s.ipLastActive = make(map[string]map[string]time.Time)
	}
	activeMap, ok := s.ipLastActive[uuid]
	if !ok {
		activeMap = make(map[string]time.Time)
		s.ipLastActive[uuid] = activeMap
	}
	activeMap[host] = time.Now()

	if s.connections == nil {
		s.connections = make(map[string]map[string]*deviceConnections)
	}
	if s.connections[uuid] == nil {
		s.connections[uuid] = make(map[string]*deviceConnections)
	}
	device := s.connections[uuid][host]
	if device == nil {
		device = &deviceConnections{}
		s.connections[uuid][host] = device
	}
	device.count++
	s.mu.Unlock()

	if lease != nil {
		if err := lease.Commit(); err != nil {
			s.logger.WithFields(log.Fields{
				"uid":    user.UID,
				"remote": ip,
			}).Warn("TUIC global device admission commit failed, rejecting connection")
			s.releaseConnection(uuid, host, device)
			_ = closeGlobalLease(lease)
			return nil, nil, false
		}
	}
	return device, lease, true
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

	// Reporting observes admission state without consuming connection ownership.
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

func (s *TuicService) userMonitorContext(ctx context.Context) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	_, tag, startAt := s.appliedStateSnapshot()
	if startAt.IsZero() || time.Since(startAt) < time.Duration(s.config.UpdatePeriodic)*time.Second {
		return nil
	}
	s.SubmitSnapshotSync(service.SnapshotSyncTrigger{
		Scope:      service.SnapshotSyncUsers | service.SnapshotSyncRules,
		Source:     service.SnapshotSyncSourcePolling,
		OccurredAt: time.Now(),
	})

	CPU, Mem, Disk, Uptime, err := serverstatus.GetSystemInfo()
	if err != nil {
		s.logger.Print(err)
	} else {
		if err = api.ReportNodeStatusContext(ctx, s.apiClient, &api.NodeStatus{CPU: CPU, Mem: Mem, Disk: Disk, Uptime: Uptime}); err != nil {
			s.logger.Print(err)
		}
	}

	if err := ctx.Err(); err != nil {
		return err
	}
	userTraffic, onlineUsers, snapshot := s.collectUsage()
	s.health.SetTrafficBacklog(len(userTraffic))
	if err := ctx.Err(); err != nil {
		s.restoreTraffic(snapshot)
		return err
	}
	if len(userTraffic) > 0 && !s.config.DisableUploadTraffic {
		if err = api.ReportUserTrafficContext(ctx, s.apiClient, &userTraffic); err != nil {
			s.logger.Print(err)
			// Restore counters so traffic is not lost and can be retried.
			s.restoreTraffic(snapshot)
			s.health.RecordFailure(service.FailureStageReport, time.Now())
		} else {
			s.health.SetTrafficBacklog(0)
		}
	} else {
		s.health.SetTrafficBacklog(0)
	}
	if len(onlineUsers) > 0 {
		if err = api.ReportNodeOnlineUsersContext(ctx, s.apiClient, &onlineUsers); err != nil {
			s.logger.Print(err)
		}
	}

	// Report Illegal user
	if s.rules != nil {
		if detectResult, err := s.rules.GetDetectResult(tag); err != nil {
			s.logger.Print(err)
		} else if len(*detectResult) > 0 {
			if err = api.ReportIllegalContext(ctx, s.apiClient, detectResult); err != nil {
				s.logger.Print(err)
			} else {
				s.logger.Printf("Report %d illegal behaviors", len(*detectResult))
			}
		}
	}

	return nil
}

func (s *TuicService) nodeMonitorContext(ctx context.Context) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	_, _, startAt := s.appliedStateSnapshot()
	if startAt.IsZero() || time.Since(startAt) < time.Duration(s.config.UpdatePeriodic)*time.Second {
		return nil
	}

	s.SubmitSnapshotSync(service.SnapshotSyncTrigger{
		Scope:      service.SnapshotSyncNode,
		Source:     service.SnapshotSyncSourcePolling,
		OccurredAt: time.Now(),
	})
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
