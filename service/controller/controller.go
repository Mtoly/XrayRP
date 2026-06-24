package controller

import (
	"context"
	"errors"
	"fmt"
	"net/url"
	"reflect"
	"strconv"
	"strings"
	"sync"
	"time"

	log "github.com/sirupsen/logrus"
	"github.com/xtls/xray-core/common/protocol"
	"github.com/xtls/xray-core/common/task"
	"github.com/xtls/xray-core/core"
	"github.com/xtls/xray-core/features/inbound"
	"github.com/xtls/xray-core/features/outbound"
	"github.com/xtls/xray-core/features/policy"
	"github.com/xtls/xray-core/features/stats"

	"github.com/Mtoly/XrayRP/api"
	"github.com/Mtoly/XrayRP/api/newV2board"
	"github.com/Mtoly/XrayRP/app/mydispatcher"
	"github.com/Mtoly/XrayRP/common/mylego"
	"github.com/Mtoly/XrayRP/common/serverstatus"
)

type LimitInfo struct {
	end               int64
	currentSpeedLimit int
	originSpeedLimit  uint64
}

type Controller struct {
	server                 *core.Instance
	config                 *Config
	clientInfo             api.ClientInfo
	apiClient              api.API
	stateMu                sync.RWMutex
	nodeInfo               *api.NodeInfo
	Tag                    string
	userList               *[]api.UserInfo
	appliedRuleTag         string
	appliedRuleList        []api.DetectRule
	syncApplyHooks         syncApplyHooks
	tasks                  []periodicTask
	limitedUsers           map[api.UserInfo]LimitInfo
	warnedUsers            map[api.UserInfo]int
	panelType              string
	ibm                    inbound.Manager
	obm                    outbound.Manager
	stm                    stats.Manager
	pm                     policy.Manager
	dispatcher             *mydispatcher.DefaultDispatcher
	startAt                time.Time
	logger                 *log.Entry
	syncCoordinator        syncCoordinatorLifecycle
	wsRuntime              wsRuntimeLifecycle
	deviceReportState      *deviceReportState
	syncCoordinatorFactory func(syncActionExecutor) syncCoordinatorLifecycle
	wsRuntimeFactory       func(syncActionSubmitter) (wsRuntimeLifecycle, error)
}

type periodicTask struct {
	tag string
	*task.Periodic
}

// New return a Controller service with default parameters.
func New(server *core.Instance, api api.API, config *Config, panelType string) *Controller {
	logger := log.NewEntry(log.StandardLogger()).WithFields(log.Fields{
		"Host": api.Describe().APIHost,
		"Type": api.Describe().NodeType,
		"ID":   api.Describe().NodeID,
	})
	ibmRaw := server.GetFeature(inbound.ManagerType())
	ibmTyped, ok := ibmRaw.(inbound.Manager)
	if !ok {
		logger.Panicf("failed to get inbound.Manager feature, got %T", ibmRaw)
	}
	obmRaw := server.GetFeature(outbound.ManagerType())
	obmTyped, ok := obmRaw.(outbound.Manager)
	if !ok {
		logger.Panicf("failed to get outbound.Manager feature, got %T", obmRaw)
	}
	stmRaw := server.GetFeature(stats.ManagerType())
	stmTyped, ok := stmRaw.(stats.Manager)
	if !ok {
		logger.Panicf("failed to get stats.Manager feature, got %T", stmRaw)
	}
	pmRaw := server.GetFeature(policy.ManagerType())
	pmTyped, ok := pmRaw.(policy.Manager)
	if !ok {
		logger.Panicf("failed to get policy.Manager feature, got %T", pmRaw)
	}
	dispRaw := server.GetFeature(mydispatcher.Type())
	dispTyped, ok := dispRaw.(*mydispatcher.DefaultDispatcher)
	if !ok {
		logger.Panicf("failed to get mydispatcher.DefaultDispatcher feature, got %T", dispRaw)
	}

	controller := &Controller{
		server:     server,
		config:     config,
		apiClient:  api,
		panelType:  panelType,
		ibm:        ibmTyped,
		obm:        obmTyped,
		stm:        stmTyped,
		pm:         pmTyped,
		dispatcher: dispTyped,
		startAt:    time.Now(),
		logger:     logger,
	}
	controller.deviceReportState = newDeviceReportState()
	controller.syncCoordinatorFactory = func(executor syncActionExecutor) syncCoordinatorLifecycle {
		return newSyncCoordinator(executor)
	}
	controller.wsRuntimeFactory = controller.newConfiguredWSRuntime

	return controller
}

func (c *Controller) buildSyncCoordinator() syncCoordinatorLifecycle {
	if c.syncCoordinatorFactory == nil {
		return nil
	}
	return c.syncCoordinatorFactory(c)
}

func (c *Controller) buildWSRuntime(submitter syncActionSubmitter) (wsRuntimeLifecycle, error) {
	if c.wsRuntimeFactory == nil {
		return nil, errors.New("controller: websocket runtime factory not configured")
	}
	return c.wsRuntimeFactory(submitter)
}

type WSEventRuntimeFactory func(WSEventSubmitter) (WSRuntimeLifecycle, error)

func (c *Controller) SetWSEventRuntimeFactory(factory WSEventRuntimeFactory) {
	if factory == nil {
		c.wsRuntimeFactory = c.newConfiguredWSRuntime
		return
	}

	c.wsRuntimeFactory = func(submitter syncActionSubmitter) (wsRuntimeLifecycle, error) {
		return factory(wsEventSubmitter{submitter: submitter})
	}
}

type wsEventSubmitter struct {
	submitter syncActionSubmitter
}

func (s wsEventSubmitter) SubmitWSEvent(event *newV2board.WSEvent) {
	if s.submitter == nil {
		return
	}
	action, ok := syncActionFromWSEventPayload(event, time.Now())
	if !ok {
		return
	}
	s.submitter.Submit(action)
}

func (s wsEventSubmitter) SubmitWSParseError() {
	if s.submitter == nil {
		return
	}
	s.submitter.Submit(syncActionFromWSParseError(time.Now()))
}

func (s wsEventSubmitter) SubmitWSDisconnect() {
	if s.submitter == nil {
		return
	}
	s.submitter.Submit(syncActionFromWSDisconnect(time.Now()))
}

func (s wsEventSubmitter) SubmitWSReconnect() {
	if s.submitter == nil {
		return
	}
	s.submitter.Submit(newSyncAction(syncActionTypeResyncAll, syncActionSourceReconnect, syncActionMetadata{
		Trigger:    wsRuntimeReconnectTrigger,
		OccurredAt: time.Now(),
		Reason:     "websocket runtime reconnected",
	}))
}

type controllerDeviceReporter interface {
	ReportDevices(map[int][]string) error
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
	if reporter, ok := c.wsRuntime.(controllerDeviceReporter); ok && deviceReporterReady(reporter) {
		state := c.ensureDeviceReportState()
		if devices, pending, changed := state.PrepareChangedReport(onlineDevice); changed {
			if err := reporter.ReportDevices(devices); err != nil {
				if c.logger != nil {
					c.logger.WithField("tag", tag).Print(err)
				}
			} else {
				state.CommitChangedReport(pending)
			}
		}
	}

	if onlineDevice != nil && len(*onlineDevice) > 0 {
		if err := c.apiClient.ReportNodeOnlineUsers(onlineDevice); err != nil {
			c.logger.Print(err)
		} else {
			c.logger.Printf("Report %d online users", len(*onlineDevice))
		}
	}
}

func deviceReporterReady(reporter controllerDeviceReporter) bool {
	readiness, ok := reporter.(controllerDeviceReporterReadiness)
	if !ok {
		return true
	}
	return readiness.DeviceReporterReady()
}

func (c *Controller) shouldStartWSRuntime() bool {
	if c.config == nil || c.config.WebSocketConfig == nil || !c.config.WebSocketConfig.Enable {
		return false
	}
	_, ok := c.apiClient.(api.WSCapable)
	return ok
}

func (c *Controller) newConfiguredWSRuntime(submitter syncActionSubmitter) (wsRuntimeLifecycle, error) {
	capable, ok := c.apiClient.(api.WSCapable)
	if !ok {
		return nil, api.ErrUnsupportedPanelFeature
	}
	wsConfig := capable.GetWSConfig()
	if wsConfig == nil {
		return nil, errors.New("controller: websocket config unavailable")
	}
	endpoint, err := resolveWSEndpoint(c.apiClient, wsConfig, c.config.WebSocketConfig)
	if err != nil {
		return nil, err
	}
	options := wsRuntimeOptions{
		ReconnectBackoff:  time.Duration(c.config.WebSocketConfig.ReconnectBackoff) * time.Second,
		HeartbeatInterval: time.Duration(c.config.WebSocketConfig.HeartbeatInterval) * time.Second,
		ResyncOnReconnect: c.config.WebSocketConfig.ResyncOnReconnect,
	}
	factory := func(ctx context.Context) (wsRuntimeClient, error) {
		return newV2board.NewWSClientContext(ctx, endpoint)
	}
	return newWSRuntime(factory, submitter, options), nil
}

func resolveWSEndpoint(apiClient any, wsConfig *api.WSConfig, runtimeConfig *WebSocketConfig) (string, error) {
	if runtimeConfig != nil && strings.TrimSpace(runtimeConfig.Endpoint) != "" {
		return BuildWSEndpoint(wsConfig, runtimeConfig)
	}

	if discoverer, ok := apiClient.(api.WSEndpointDiscoverer); ok {
		if endpoint, err := discoverer.DiscoverWSEndpoint(); err == nil && strings.TrimSpace(endpoint) != "" {
			derived := WebSocketConfig{}
			if runtimeConfig != nil {
				derived = *runtimeConfig
			}
			derived.Endpoint = endpoint
			return BuildWSEndpoint(wsConfig, &derived)
		}
	}

	return BuildWSEndpoint(wsConfig, runtimeConfig)
}

func buildWSEndpoint(wsConfig *api.WSConfig, runtimeConfig *WebSocketConfig) (string, error) {
	return BuildWSEndpoint(wsConfig, runtimeConfig)
}

func BuildWSEndpoint(wsConfig *api.WSConfig, runtimeConfig *WebSocketConfig) (string, error) {
	if wsConfig == nil {
		return "", errors.New("controller: websocket config unavailable")
	}

	rawEndpoint := ""
	if runtimeConfig != nil {
		rawEndpoint = strings.TrimSpace(runtimeConfig.Endpoint)
	}
	if rawEndpoint == "" {
		rawEndpoint = strings.TrimRight(wsConfig.APIHost, "/") + "/api/v1/server/UniProxy/ws"
	}

	parsed, err := url.Parse(rawEndpoint)
	if err != nil {
		return "", fmt.Errorf("controller: parse websocket endpoint: %w", err)
	}
	if parsed.Scheme == "" || parsed.Host == "" {
		base, err := url.Parse(wsConfig.APIHost)
		if err != nil {
			return "", fmt.Errorf("controller: parse panel api host: %w", err)
		}
		parsed = base.ResolveReference(parsed)
	}

	switch parsed.Scheme {
	case "http":
		parsed.Scheme = "ws"
	case "https":
		parsed.Scheme = "wss"
	case "ws", "wss":
	default:
		return "", fmt.Errorf("controller: unsupported websocket endpoint scheme %q", parsed.Scheme)
	}

	query := parsed.Query()
	if wsConfig.MachineID > 0 {
		query.Del("node_id")
		query.Del("node_type")
		if query.Get("machine_id") == "" {
			query.Set("machine_id", strconv.Itoa(wsConfig.MachineID))
		}
	} else {
		if query.Get("node_id") == "" {
			query.Set("node_id", strconv.Itoa(wsConfig.NodeID))
		}
		if query.Get("node_type") == "" {
			query.Set("node_type", wsConfig.NodeType)
		}
	}
	if query.Get("token") == "" {
		query.Set("token", wsConfig.Key)
	}
	parsed.RawQuery = query.Encode()

	return parsed.String(), nil
}

// Start implement the Start() function of the service interface
func (c *Controller) Start() error {
	c.clientInfo = c.apiClient.Describe()
	hooks := c.resolveSyncApplyHooks()
	// First fetch Node Info
	newNodeInfo, err := c.apiClient.GetNodeInfo()
	if err != nil {
		return err
	}
	if newNodeInfo.Port == 0 || newNodeInfo.Port > 65535 {
		return fmt.Errorf("invalid server port: %d, must be 1-65535", newNodeInfo.Port)
	}
	tag := c.buildNodeTagFrom(newNodeInfo)
	c.setNodeState(newNodeInfo, tag)

	// Add new tag
	err = hooks.addNewTag(newNodeInfo, tag)
	if err != nil {
		c.logger.Panic(err)
		return err
	}
	// Update user
	userInfo, err := c.apiClient.GetUserList()
	if err != nil {
		return err
	}

	// sync controller userList
	c.setUserList(userInfo)

	err = hooks.addNewUser(userInfo, newNodeInfo, tag)
	if err != nil {
		return err
	}

	// Add Limiter
	if err := hooks.addInboundLimiter(tag, newNodeInfo.SpeedLimit, userInfo, c.config.GlobalDeviceLimitConfig); err != nil {
		c.logger.Print(err)
	}

	// Add Rule Manager
	if !c.config.DisableGetRule {
		if ruleList, err := c.apiClient.GetNodeRule(); err != nil {
			c.logger.Printf("Get rule list filed: %s", err)
		} else if len(*ruleList) > 0 {
			if err := hooks.updateRule(tag, *ruleList); err != nil {
				c.logger.Print(err)
			} else {
				c.setAppliedRuleState(tag, *ruleList)
			}
		}
	}

	// Init AutoSpeedLimitConfig
	if c.config.AutoSpeedLimitConfig == nil {
		c.config.AutoSpeedLimitConfig = &AutoSpeedLimitConfig{0, 0, 0, 0}
	}
	if c.config.AutoSpeedLimitConfig.Limit > 0 {
		c.limitedUsers = make(map[api.UserInfo]LimitInfo)
		c.warnedUsers = make(map[api.UserInfo]int)
	}

	c.syncCoordinator = c.buildSyncCoordinator()
	if c.syncCoordinator == nil {
		return errors.New("controller: sync coordinator not configured")
	}

	if c.shouldStartWSRuntime() {
		wsRuntime, err := c.buildWSRuntime(c.syncCoordinator)
		if err != nil {
			c.syncCoordinator.Stop()
			c.syncCoordinator = nil
			return err
		}
		c.wsRuntime = wsRuntime
		c.wsRuntime.Start()
	}

	// Add periodic tasks
	c.tasks = append(c.tasks,
		periodicTask{
			tag: "node monitor",
			Periodic: &task.Periodic{
				Interval: time.Duration(c.config.UpdatePeriodic) * time.Second,
				Execute:  c.nodeInfoMonitor,
			}},
		periodicTask{
			tag: "user monitor",
			Periodic: &task.Periodic{
				Interval: time.Duration(c.config.UpdatePeriodic) * time.Second,
				Execute:  c.userInfoMonitor,
			}},
	)

	// Check cert service in need
	var currentNodeInfo *api.NodeInfo
	c.stateMu.RLock()
	currentNodeInfo = c.nodeInfo
	c.stateMu.RUnlock()
	if currentNodeInfo != nil && currentNodeInfo.EnableTLS && c.config.EnableREALITY == false {
		c.tasks = append(c.tasks, periodicTask{
			tag: "cert monitor",
			Periodic: &task.Periodic{
				Interval: time.Duration(c.config.UpdatePeriodic) * time.Second * 60,
				Execute:  c.certMonitor,
			}})
	}

	// Start periodic tasks
	for i := range c.tasks {
		c.logger.Printf("Start %s periodic task", c.tasks[i].tag)
		go c.tasks[i].Start()
	}

	return nil
}

// Close implement the Close() function of the service interface
func (c *Controller) Close() error {
	for i := range c.tasks {
		if c.tasks[i].Periodic != nil {
			if err := c.tasks[i].Periodic.Close(); err != nil {
				c.logger.Panicf("%s periodic task close failed: %s", c.tasks[i].tag, err)
			}
		}
	}

	if c.wsRuntime != nil {
		c.wsRuntime.Stop()
		c.wsRuntime = nil
	}
	if c.syncCoordinator != nil {
		c.syncCoordinator.Stop()
		c.syncCoordinator = nil
	}

	return nil
}

func (c *Controller) nodeInfoMonitor() error {
	// delay to start
	if time.Since(c.startAt) < time.Duration(c.config.UpdatePeriodic)*time.Second {
		return nil
	}

	action := syncActionFromPollingTick(time.Now())
	if err := c.submitSyncAction(action); err != nil {
		c.logger.Print(err)
		return nil
	}
	return nil
}

func (c *Controller) removeOldTag(oldTag string) (err error) {
	err = c.removeInbound(oldTag)
	if err != nil {
		return err
	}
	err = c.removeOutbound(oldTag)
	if err != nil {
		return err
	}
	return nil
}

func (c *Controller) addNewTag(newNodeInfo *api.NodeInfo, tag string) (err error) {
	// Socks/HTTP inbounds are built with users embedded (no UserManager support).
	// Skip here — the inbound will be created by rebuildInboundWithUsers() in addNewUser().
	if newNodeInfo.NodeType == "Socks" || newNodeInfo.NodeType == "HTTP" {
		// Still need the outbound for routing
		outBoundConfig, err := OutboundBuilder(c.config, newNodeInfo, tag)
		if err != nil {
			return err
		}
		return c.addOutbound(outBoundConfig, tag, newNodeInfo.RoutePolicy)
	}

	if newNodeInfo.NodeType != "Shadowsocks-Plugin" {
		inboundConfig, err := InboundBuilder(c.config, newNodeInfo, tag)
		if err != nil {
			return err
		}
		err = c.addInbound(inboundConfig)
		if err != nil {

			return err
		}
		outBoundConfig, err := OutboundBuilder(c.config, newNodeInfo, tag)
		if err != nil {

			return err
		}
		err = c.addOutbound(outBoundConfig, tag, newNodeInfo.RoutePolicy)
		if err != nil {

			return err
		}

	} else {
		return c.addInboundForSSPlugin(*newNodeInfo, tag)
	}
	return nil
}

func (c *Controller) addInboundForSSPlugin(newNodeInfo api.NodeInfo, tag string) (err error) {
	// Shadowsocks-Plugin require a separate inbound for other TransportProtocol likes: ws, grpc
	fakeNodeInfo := newNodeInfo
	fakeNodeInfo.TransportProtocol = "tcp"
	fakeNodeInfo.EnableTLS = false
	// Add a regular Shadowsocks inbound and outbound
	inboundConfig, err := InboundBuilder(c.config, &fakeNodeInfo, tag)
	if err != nil {
		return err
	}
	err = c.addInbound(inboundConfig)
	if err != nil {

		return err
	}
	outBoundConfig, err := OutboundBuilder(c.config, &fakeNodeInfo, tag)
	if err != nil {

		return err
	}
	err = c.addOutbound(outBoundConfig, tag, fakeNodeInfo.RoutePolicy)
	if err != nil {

		return err
	}
	// Add an inbound for upper streaming protocol
	fakeNodeInfo = newNodeInfo
	fakeNodeInfo.Port++
	fakeNodeInfo.NodeType = "dokodemo-door"
	dokodemoTag := fmt.Sprintf("dokodemo-door_%s+1", tag)
	inboundConfig, err = InboundBuilder(c.config, &fakeNodeInfo, dokodemoTag)
	if err != nil {
		return err
	}
	err = c.addInbound(inboundConfig)
	if err != nil {

		return err
	}
	outBoundConfig, err = OutboundBuilder(c.config, &fakeNodeInfo, dokodemoTag)
	if err != nil {

		return err
	}
	err = c.addOutbound(outBoundConfig, dokodemoTag, fakeNodeInfo.RoutePolicy)
	if err != nil {

		return err
	}
	return nil
}

// rebuildInboundWithUsers rebuilds the socks/http inbound with all users embedded.
// This is needed because socks/http inbounds don't support proxy.UserManager.
func (c *Controller) rebuildInboundWithUsers(userInfo *[]api.UserInfo, nodeInfo *api.NodeInfo, tag string) error {
	// Remove existing inbound if present (ignore errors for first-time setup)
	_ = c.removeInbound(tag)

	// Build inbound with all users
	inboundConfig, err := InboundBuilderWithUsers(c.config, nodeInfo, tag, userInfo)
	if err != nil {
		return err
	}
	err = c.addInbound(inboundConfig)
	if err != nil {
		return err
	}

	c.logger.Printf("Rebuilt %s inbound with %d users", nodeInfo.NodeType, len(*userInfo))
	return nil
}

func (c *Controller) addNewUser(userInfo *[]api.UserInfo, nodeInfo *api.NodeInfo, tag string) (err error) {
	// Socks/HTTP don't support proxy.UserManager — rebuild entire inbound with users embedded
	if nodeInfo.NodeType == "Socks" || nodeInfo.NodeType == "HTTP" {
		return c.rebuildInboundWithUsers(userInfo, nodeInfo, tag)
	}

	users := make([]*protocol.User, 0)
	switch nodeInfo.NodeType {
	case "V2ray", "Vmess", "Vless":
		if nodeInfo.EnableVless || (nodeInfo.NodeType == "Vless" && nodeInfo.NodeType != "Vmess") {
			users = c.buildVlessUser(userInfo, nodeInfo, tag)
		} else {
			users = c.buildVmessUser(userInfo, tag)
		}
	case "Trojan":
		users = c.buildTrojanUser(userInfo, tag)
	case "Shadowsocks":
		users = c.buildSSUser(userInfo, nodeInfo.CypherMethod, tag)
	case "Shadowsocks-Plugin":
		users = c.buildSSPluginUser(userInfo, tag)
	default:
		return fmt.Errorf("unsupported node type: %s", nodeInfo.NodeType)
	}

	err = c.addUsers(users, tag)
	if err != nil {
		return err
	}
	c.logger.Printf("Added %d new users", len(*userInfo))
	return nil
}

func nodeStateChanged(currentNodeInfo, newNodeInfo *api.NodeInfo) bool {
	return !reflect.DeepEqual(currentNodeInfo, newNodeInfo)
}

func compareUserList(old, new *[]api.UserInfo) (deleted, added []api.UserInfo) {
	// Use UID as the primary key for O(N) comparison instead of the full struct
	// which is expensive to hash with 50k users.
	type userKey struct {
		UID   int
		Email string
	}

	oldMap := make(map[userKey]api.UserInfo, len(*old))
	for _, v := range *old {
		oldMap[userKey{v.UID, v.Email}] = v
	}

	newMap := make(map[userKey]struct{}, len(*new))
	for _, v := range *new {
		k := userKey{v.UID, v.Email}
		newMap[k] = struct{}{}
		if _, exists := oldMap[k]; !exists {
			added = append(added, v)
		}
	}

	for k, v := range oldMap {
		if _, exists := newMap[k]; !exists {
			deleted = append(deleted, v)
		}
	}

	return deleted, added
}

func limitUser(c *Controller, user api.UserInfo, tag string, silentUsers *[]api.UserInfo) {
	c.limitedUsers[user] = LimitInfo{
		end:               time.Now().Unix() + int64(c.config.AutoSpeedLimitConfig.LimitDuration*60),
		currentSpeedLimit: c.config.AutoSpeedLimitConfig.LimitSpeed,
		originSpeedLimit:  user.SpeedLimit,
	}
	userTag := c.buildUserTagFrom(user, tag)
	c.logger.Printf("Limit User: %s Speed: %d End: %s", userTag, c.config.AutoSpeedLimitConfig.LimitSpeed, time.Unix(c.limitedUsers[user].end, 0).Format("01-02 15:04:05"))
	user.SpeedLimit = uint64((c.config.AutoSpeedLimitConfig.LimitSpeed * 1000000) / 8)
	*silentUsers = append(*silentUsers, user)
}

func (c *Controller) userInfoMonitor() (err error) {
	// delay to start
	if time.Since(c.startAt) < time.Duration(c.config.UpdatePeriodic)*time.Second {
		return nil
	}

	currentNodeInfo, currentTag, currentUserList := c.getStateSnapshot()
	if currentNodeInfo == nil || currentUserList == nil {
		return nil
	}

	// Get server status
	CPU, Mem, Disk, Uptime, err := serverstatus.GetSystemInfo()
	if err != nil {
		c.logger.Print(err)
	}
	err = c.apiClient.ReportNodeStatus(
		&api.NodeStatus{
			CPU:    CPU,
			Mem:    Mem,
			Disk:   Disk,
			Uptime: Uptime,
		})
	if err != nil {
		c.logger.Print(err)
	}

	var (
		toReleaseUsers []api.UserInfo
		limitedCount   int
	)
	// Unlock users
	if c.config.AutoSpeedLimitConfig.Limit > 0 {
		c.withStateLock(func() {
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
		if len(toReleaseUsers) > 0 {
			c.logger.Printf("Releasing %d speed-limited users, %d still limited", len(toReleaseUsers), limitedCount)
			if err := c.UpdateInboundLimiter(currentTag, &toReleaseUsers); err != nil {
				c.logger.Print(err)
			}
		}
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
	if len(limitedUsers) > 0 {
		if err := c.UpdateInboundLimiter(currentTag, &limitedUsers); err != nil {
			c.logger.Print(err)
		}
	}
	if len(userTraffic) > 0 {
		c.logger.Printf("Reporting %d user(s) traffic to panel; example: UID=%d up=%d down=%d", len(userTraffic), userTraffic[0].UID, userTraffic[0].Upload, userTraffic[0].Download)
		var reportErr error
		if !c.config.DisableUploadTraffic {
			reportErr = c.apiClient.ReportUserTraffic(&userTraffic)
		}
		// If report traffic error, not clear the traffic
		if reportErr != nil {
			c.logger.Print(reportErr)
		} else {
			c.resetTraffic(&upCounterList, &downCounterList)
		}
	}

	// Report Online info
	if onlineDevice, err := c.GetOnlineDevice(currentTag); err != nil {
		c.logger.Print(err)
	} else {
		c.reportOnlineDevices(currentTag, onlineDevice)
	}

	// Sync alive list from panel for device limit accuracy
	if aliveList, err := c.apiClient.GetAliveList(); err == nil && aliveList != nil && len(aliveList) > 0 {
		if err := c.dispatcher.Limiter.SyncAliveList(currentTag, aliveList); err != nil {
			c.logger.Print(err)
		}
	}

	// Report Illegal user
	if detectResult, err := c.GetDetectResult(currentTag); err != nil {
		c.logger.Print(err)
	} else if len(*detectResult) > 0 {
		if err = c.pushIllegalResults(detectResult); err != nil {
			c.logger.Print(err)
		}
	}
	return nil
}

func (c *Controller) buildNodeTagFrom(nodeInfo *api.NodeInfo) string {
	// Normalize NodeType for tag prefix so same-node routing and data path guards
	// consistently recognize managed protocols.
	base := nodeInfo.NodeType
	switch strings.ToLower(base) {
	case "vless":
		base = "VLESS"
	case "trojan":
		base = "Trojan"
	case "vmess", "v2ray":
		base = "Vmess"
	case "shadowsocks":
		base = "Shadowsocks"
	case "socks":
		base = "Socks"
	case "http":
		base = "HTTP"
	}

	// Include NodeID to avoid cross-node mixing when multiple logical nodes share
	// the same NodeType/ListenIP/Port (e.g., CDN or multi-node deployments).
	return fmt.Sprintf("%s_%s_%d_%d", base, c.config.ListenIP, nodeInfo.Port, nodeInfo.NodeID)
}

func (c *Controller) buildNodeTag() string {
	c.stateMu.RLock()
	nodeInfo := c.nodeInfo
	c.stateMu.RUnlock()
	if nodeInfo == nil {
		return ""
	}
	return c.buildNodeTagFrom(nodeInfo)
}

func (c *Controller) pushIllegalResults(detectResult *[]api.DetectResult) error {
	if detectResult == nil || len(*detectResult) == 0 {
		return nil
	}
	if err := c.apiClient.ReportIllegal(detectResult); err != nil {
		c.logger.WithError(err).Warn("Report illegal results failed")
		return err
	}
	c.logger.Printf("Report %d illegal behaviors", len(*detectResult))
	return nil
}

// func (c *Controller) logPrefix() string {
// 	return fmt.Sprintf("[%s] %s(ID=%d)", c.clientInfo.APIHost, c.nodeInfo.NodeType, c.nodeInfo.NodeID)
// }

// Check Cert
func (c *Controller) certMonitor() error {
	currentNodeInfo, _, _ := c.getStateSnapshot()
	if currentNodeInfo != nil && currentNodeInfo.EnableTLS && c.config.EnableREALITY == false && c.config.CertConfig != nil {
		switch c.config.CertConfig.CertMode {
		case "dns", "http", "tls":
			lego, err := mylego.New(c.config.CertConfig)
			if err != nil {
				c.logger.Print(err)
			}
			// Xray-core supports the OcspStapling certification hot renew
			_, _, _, err = lego.RenewCert()
			if err != nil {
				c.logger.Print(err)
			}
		}
	}
	return nil
}
