package controller

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/Mtoly/XrayRP/api"
	"github.com/Mtoly/XrayRP/common/serverstatus"
	"github.com/Mtoly/XrayRP/service"
	"github.com/xtls/xray-core/features/stats"
)

type controllerDeviceReporter interface {
	ReportDevices(map[int][]string) error
}

type controllerNodeDeviceReporter interface {
	ReportNodeDevices(map[int][]string) error
}

type controllerNodeDeviceReporterReadiness interface {
	DeviceReporterReady() bool
}

type controllerDeviceReporterReadiness interface {
	DeviceReporterReady() bool
}

func (c *Controller) ensureDeviceReportState() *deviceReportState {
	c.stateMu.RLock()
	state := c.deviceReportState
	c.stateMu.RUnlock()
	if state != nil {
		return state
	}

	c.stateMu.Lock()
	defer c.stateMu.Unlock()
	if c.deviceReportState == nil {
		c.deviceReportState = newDeviceReportState()
	}
	return c.deviceReportState
}

func (c *Controller) reportOnlineDevices(tag string, onlineDevice *[]api.OnlineUser) {
	ctx, cancel := service.WithDefaultTimeout(context.Background(), service.DefaultSyncTimeout)
	defer cancel()
	c.reportOnlineDevicesContext(ctx, tag, onlineDevice)
}

func (c *Controller) reportOnlineDevicesContext(ctx context.Context, tag string, onlineDevice *[]api.OnlineUser) {
	if reporter, ok := c.deviceReporter(); ok && deviceReporterReady(reporter) {
		state := c.ensureDeviceReportState()
		if devices, pending, changed := state.PrepareChangedReport(onlineDevice); changed {
			if err := ctx.Err(); err != nil {
				return
			}
			if err := reporter.ReportDevices(devices); err != nil {
				if c.logger != nil {
					c.logger.WithField("tag", tag).Print(err)
				}
			} else if ctx.Err() == nil {
				state.CommitChangedReport(pending)
			}
		}
	}

	if onlineDevice != nil && len(*onlineDevice) > 0 {
		if err := api.ReportNodeOnlineUsersContext(ctx, c.apiClient, onlineDevice); err != nil {
			c.logger.Print(err)
		} else {
			c.logger.Printf("Report %d online users", len(*onlineDevice))
		}
	}
}

func (c *Controller) deviceReporter() (controllerDeviceReporter, bool) {
	if reporter, ok := c.currentWSRuntime().(controllerDeviceReporter); ok {
		return reporter, true
	}
	if reporter, ok := c.apiClient.(controllerNodeDeviceReporter); ok {
		return nodeDeviceReporterAdapter{reporter: reporter}, true
	}
	return nil, false
}

type nodeDeviceReporterAdapter struct {
	reporter controllerNodeDeviceReporter
}

func (a nodeDeviceReporterAdapter) ReportDevices(devices map[int][]string) error {
	if a.reporter == nil {
		return nil
	}
	return a.reporter.ReportNodeDevices(devices)
}

func (a nodeDeviceReporterAdapter) DeviceReporterReady() bool {
	readiness, ok := a.reporter.(controllerNodeDeviceReporterReadiness)
	return !ok || readiness.DeviceReporterReady()
}

func deviceReporterReady(reporter controllerDeviceReporter) bool {
	readiness, ok := reporter.(controllerDeviceReporterReadiness)
	if !ok {
		return true
	}
	return readiness.DeviceReporterReady()
}

func speedLimitBytes(megabitsPerSecond int) uint64 {
	return uint64((megabitsPerSecond * 1_000_000) / 8)
}

type limiterUserOverlayCandidate struct {
	limiterUsers *[]api.UserInfo
	limitedUsers map[api.UserInfo]LimitInfo
	warnedUsers  map[api.UserInfo]int
}

func (c *Controller) buildLimiterUserOverlayCandidate(users *[]api.UserInfo) limiterUserOverlayCandidate {
	if users == nil {
		return limiterUserOverlayCandidate{}
	}
	result := cloneSlice(*users)

	c.stateMu.RLock()
	defer c.stateMu.RUnlock()
	limitedByIdentity := make(map[userIdentityKey]LimitInfo, len(c.limitedUsers))
	for user, info := range c.limitedUsers {
		limitedByIdentity[userIdentityKey{UID: user.UID, Email: user.Email}] = info
	}
	warnedByIdentity := make(map[userIdentityKey]int, len(c.warnedUsers))
	for user, count := range c.warnedUsers {
		warnedByIdentity[userIdentityKey{UID: user.UID, Email: user.Email}] = count
	}

	nextLimited := make(map[api.UserInfo]LimitInfo, len(limitedByIdentity))
	nextWarned := make(map[api.UserInfo]int, len(warnedByIdentity))
	for index, user := range result {
		identity := userIdentityKey{UID: user.UID, Email: user.Email}
		if info, limited := limitedByIdentity[identity]; limited {
			info.originSpeedLimit = user.SpeedLimit
			nextLimited[user] = info
			result[index].SpeedLimit = speedLimitBytes(info.currentSpeedLimit)
		}
		if count, warned := warnedByIdentity[identity]; warned {
			nextWarned[user] = count
		}
	}
	return limiterUserOverlayCandidate{
		limiterUsers: &result,
		limitedUsers: nextLimited,
		warnedUsers:  nextWarned,
	}
}

func limitUser(c *Controller, user api.UserInfo, tag string, silentUsers *[]api.UserInfo) {
	c.limitedUsers[user] = LimitInfo{
		end:               time.Now().Unix() + int64(c.config.AutoSpeedLimitConfig.LimitDuration*60),
		currentSpeedLimit: c.config.AutoSpeedLimitConfig.LimitSpeed,
		originSpeedLimit:  user.SpeedLimit,
	}
	userTag := c.buildUserTagFrom(user, tag)
	c.logger.Printf("Limit User: %s Speed: %d End: %s", userTag, c.config.AutoSpeedLimitConfig.LimitSpeed, time.Unix(c.limitedUsers[user].end, 0).Format("01-02 15:04:05"))
	user.SpeedLimit = speedLimitBytes(c.config.AutoSpeedLimitConfig.LimitSpeed)
	*silentUsers = append(*silentUsers, user)
}

func (c *Controller) updateInboundLimiterFromUserMonitor(tag string, users *[]api.UserInfo) error {
	if c.beforeUserMonitorLimiterUpdate != nil {
		c.beforeUserMonitorLimiterUpdate()
	}
	return c.UpdateInboundLimiter(tag, users)
}

func (c *Controller) userInfoMonitor() error {
	ctx, cancel := service.WithDefaultTimeout(context.Background(), service.DefaultSyncTimeout)
	defer cancel()
	return c.userInfoMonitorContext(ctx)
}

func (c *Controller) userInfoMonitorContext(ctx context.Context) (err error) {
	if err := ctx.Err(); err != nil {
		return err
	}
	// delay to start
	if time.Since(c.startAt) < time.Duration(c.config.UpdatePeriodic)*time.Second {
		return nil
	}

	// Get server status
	CPU, Mem, Disk, Uptime, err := serverstatus.GetSystemInfo()
	if err != nil {
		c.logger.Print(err)
	}
	err = api.ReportNodeStatusContext(ctx, c.apiClient,
		&api.NodeStatus{
			CPU:    CPU,
			Mem:    Mem,
			Disk:   Disk,
			Uptime: Uptime,
		})
	if err != nil {
		c.logger.Print(err)
	}

	c.reloadMu.Lock()
	currentNodeInfo, currentTag, currentUserList := c.getStateSnapshot()
	if currentNodeInfo == nil || currentUserList == nil {
		c.reloadMu.Unlock()
		return nil
	}

	var (
		toReleaseUsers      []api.UserInfo
		limitedCount        int
		appliedLimitedUsers map[api.UserInfo]LimitInfo
		appliedWarnedUsers  map[api.UserInfo]int
	)
	// Unlock users
	if c.config.AutoSpeedLimitConfig.Limit > 0 {
		c.withStateLock(func() {
			appliedLimitedUsers = cloneMap(c.limitedUsers)
			appliedWarnedUsers = cloneMap(c.warnedUsers)
			if len(c.limitedUsers) == 0 {
				limitedCount = 0
				return
			}
			toReleaseUsers = make([]api.UserInfo, 0)
			now := time.Now().Unix()
			for user, limitInfo := range c.limitedUsers {
				if now > limitInfo.end {
					user.SpeedLimit = limitInfo.originSpeedLimit
					toReleaseUsers = append(toReleaseUsers, user)
					delete(c.limitedUsers, user)
				}
			}
			limitedCount = len(c.limitedUsers)
		})
	}

	// Get User traffic — optimized: pre-allocate and batch
	userCount := len(*currentUserList)
	userTraffic := make([]api.UserTraffic, 0, userCount/10) // typically ~10% have traffic
	upCounterList := make([]stats.Counter, 0, userCount/10)
	downCounterList := make([]stats.Counter, 0, userCount/10)
	AutoSpeedLimit := int64(c.config.AutoSpeedLimitConfig.Limit)
	UpdatePeriodic := int64(c.config.UpdatePeriodic)
	limitedUsers := make([]api.UserInfo, 0)
	speedThreshold := AutoSpeedLimit * 1000000 * UpdatePeriodic / 8
	for _, user := range *currentUserList {
		userTag := c.buildUserTagFrom(user, currentTag)
		up, down, upCounter, downCounter := c.getTraffic(userTag)
		if up > 0 || down > 0 {
			// Over speed users
			if AutoSpeedLimit > 0 {
				c.withStateLock(func() {
					if down > speedThreshold || up > speedThreshold {
						if _, ok := c.limitedUsers[user]; !ok {
							if c.config.AutoSpeedLimitConfig.WarnTimes == 0 {
								limitUser(c, user, currentTag, &limitedUsers)
							} else {
								c.warnedUsers[user] += 1
								if c.warnedUsers[user] > c.config.AutoSpeedLimitConfig.WarnTimes {
									limitUser(c, user, currentTag, &limitedUsers)
									delete(c.warnedUsers, user)
								}
							}
						}
					} else {
						delete(c.warnedUsers, user)
					}
				})
			}
			userTraffic = append(userTraffic, api.UserTraffic{
				UID:      user.UID,
				Email:    user.Email,
				Upload:   up,
				Download: down})

			if upCounter != nil {
				upCounterList = append(upCounterList, upCounter)
			}
			if downCounter != nil {
				downCounterList = append(downCounterList, downCounter)
			}
		} else {
			if AutoSpeedLimit > 0 {
				c.withStateLock(func() {
					delete(c.warnedUsers, user)
				})
			}
		}
	}
	limitUpdates := make([]api.UserInfo, 0, len(toReleaseUsers)+len(limitedUsers))
	limitUpdates = append(limitUpdates, toReleaseUsers...)
	limitUpdates = append(limitUpdates, limitedUsers...)
	if len(limitUpdates) > 0 {
		if err := c.updateInboundLimiterFromUserMonitor(currentTag, &limitUpdates); err != nil {
			c.withStateLock(func() {
				c.limitedUsers = appliedLimitedUsers
				c.warnedUsers = appliedWarnedUsers
			})
			c.reloadMu.Unlock()
			return fmt.Errorf("apply automatic speed-limit changes: %w", err)
		}
	}
	if len(toReleaseUsers) > 0 {
		c.logger.Printf("Releasing %d speed-limited users, %d still limited", len(toReleaseUsers), limitedCount)
	}
	c.reloadMu.Unlock()

	if len(userTraffic) > 0 {
		c.health.SetTrafficBacklog(len(userTraffic))
		c.logger.Printf("Reporting %d user(s) traffic to panel; example: UID=%d up=%d down=%d", len(userTraffic), userTraffic[0].UID, userTraffic[0].Upload, userTraffic[0].Download)
		var reportErr error
		if !c.config.DisableUploadTraffic {
			reportErr = api.ReportUserTrafficContext(ctx, c.apiClient, &userTraffic)
		}
		// If report traffic error, not clear the traffic
		if reportErr != nil {
			c.logger.Print(reportErr)
			c.health.RecordFailure(service.FailureStageReport, time.Now())
		} else {
			c.resetTraffic(&upCounterList, &downCounterList)
			c.health.SetTrafficBacklog(0)
		}
	} else {
		c.health.SetTrafficBacklog(0)
	}

	// Report Online info
	if onlineDevice, err := c.GetOnlineDevice(currentTag); err != nil {
		c.logger.Print(err)
	} else {
		c.reportOnlineDevicesContext(ctx, currentTag, onlineDevice)
	}

	c.syncAliveListFromPanelContext(ctx, currentTag)

	// Report Illegal user
	if detectResult, err := c.GetDetectResult(currentTag); err != nil {
		c.logger.Print(err)
	} else if len(*detectResult) > 0 {
		if err = c.pushIllegalResultsContext(ctx, detectResult); err != nil {
			c.logger.Print(err)
		}
	}
	return nil
}

func (c *Controller) syncAliveListFromPanel(tag string) {
	ctx, cancel := service.WithDefaultTimeout(context.Background(), service.DefaultSyncTimeout)
	defer cancel()
	c.syncAliveListFromPanelContext(ctx, tag)
}

func (c *Controller) syncAliveListFromPanelContext(ctx context.Context, tag string) {
	provider, ok := c.apiClient.(api.AliveListProvider)
	if !ok {
		return
	}
	aliveList, err := api.GetAliveListContext(ctx, provider)
	if err != nil {
		if !errors.Is(err, api.ErrUnsupportedPanelFeature) {
			c.logger.Print(err)
		}
		return
	}
	if aliveList == nil {
		return
	}
	if err := c.SyncAliveList(tag, aliveList); err != nil {
		c.logger.Print(err)
	}
}

func (c *Controller) pushIllegalResults(detectResult *[]api.DetectResult) error {
	ctx, cancel := service.WithDefaultTimeout(context.Background(), service.DefaultSyncTimeout)
	defer cancel()
	return c.pushIllegalResultsContext(ctx, detectResult)
}

func (c *Controller) pushIllegalResultsContext(ctx context.Context, detectResult *[]api.DetectResult) error {
	if detectResult == nil || len(*detectResult) == 0 {
		return nil
	}
	if err := api.ReportIllegalContext(ctx, c.apiClient, detectResult); err != nil {
		c.logger.WithError(err).Warn("Report illegal results failed")
		return err
	}
	c.logger.Printf("Report %d illegal behaviors", len(*detectResult))
	return nil
}
