package controller

import (
	"context"
	"errors"
	"fmt"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"

	log "github.com/sirupsen/logrus"
	"github.com/xtls/xray-core/common/protocol"
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
	"github.com/Mtoly/XrayRP/internal/managednode"
)

type PanelClient interface {
	Describe() api.ClientInfo
	GetNodeInfo() (*api.NodeInfo, error)
	GetUserList() (*[]api.UserInfo, error)
	GetNodeRule() (*[]api.DetectRule, error)
	ReportNodeStatus(*api.NodeStatus) error
	ReportNodeOnlineUsers(*[]api.OnlineUser) error
	ReportUserTraffic(*[]api.UserTraffic) error
	ReportIllegal(*[]api.DetectResult) error
}

type LimitInfo struct {
	end               int64
	currentSpeedLimit int
	originSpeedLimit  uint64
}

type preparedCertificateRenewal interface {
	Renewed() bool
	CertificatePEM() []byte
	PrivateKeyPEM() []byte
	Commit() error
	Rollback() error
}

type prepareCertificateRenewalFunc func(*mylego.CertConfig) (preparedCertificateRenewal, error)

type Controller struct {
	server                 *core.Instance
	config                 *Config
	clientInfo             api.ClientInfo
	apiClient              PanelClient
	reloadMu               sync.Mutex
	periodicMu             sync.Mutex
	periodicJoinWG         sync.WaitGroup
	periodicGeneration     uint64
	periodicAsyncErrs      []error
	periodicClosed         bool
	periodicCloseDone      chan struct{}
	periodicCloseErr       error
	stateMu                sync.RWMutex
	runtimeState           nodeRuntimeState
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
	syncExecutionState     *syncExecutionState
	prepareRenewal         prepareCertificateRenewalFunc
	newPeriodicTask        periodicTaskFactory
	syncCoordinatorFactory func(syncActionExecutor) syncCoordinatorLifecycle
	wsRuntimeFactory       func(syncActionSubmitter) (wsRuntimeLifecycle, error)
}

type periodicTask = controllerPeriodicTask

// New return a Controller service with default parameters.
func New(server *core.Instance, apiClient PanelClient, config *Config, panelType string) *Controller {
	logger := log.NewEntry(log.StandardLogger()).WithFields(log.Fields{
		"Host": apiClient.Describe().APIHost,
		"Type": apiClient.Describe().NodeType,
		"ID":   apiClient.Describe().NodeID,
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
		apiClient:  apiClient,
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
	controller.syncExecutionState = newSyncExecutionState()
	controller.prepareRenewal = defaultControllerPrepareCertificateRenewal
	controller.syncCoordinatorFactory = func(executor syncActionExecutor) syncCoordinatorLifecycle {
		return newSyncCoordinatorWithResultHandling(executor, controller.syncExecutionState, controller.logSyncExecutionResult)
	}
	controller.wsRuntimeFactory = controller.newConfiguredWSRuntime

	return controller
}

func (c *Controller) recordSyncExecutionResult(action syncAction, err error) {
	if c == nil {
		return
	}
	if c.syncExecutionState != nil {
		c.syncExecutionState.Record(action, err)
	}
	c.logSyncExecutionResult(action, err)
}

func (c *Controller) logSyncExecutionResult(action syncAction, err error) {
	if c == nil {
		return
	}
	if err == nil || c.logger == nil {
		return
	}

	entry := c.logger.WithFields(log.Fields{
		"action_type":   action.Type,
		"action_source": action.Source,
		"trigger":       action.Metadata.Trigger,
	})
	if c.showErrorDetails() {
		entry.WithError(err).Warn("sync action failed")
		return
	}
	entry.Warn("sync action failed; error details omitted because they may contain credentials")
}

func (c *Controller) syncExecutionSnapshot() syncExecutionSnapshot {
	if c == nil || c.syncExecutionState == nil {
		return syncExecutionSnapshot{}
	}
	return c.syncExecutionState.Snapshot()
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
	if reporter, ok := c.deviceReporter(); ok && deviceReporterReady(reporter) {
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

func (c *Controller) deviceReporter() (controllerDeviceReporter, bool) {
	if reporter, ok := c.wsRuntime.(controllerDeviceReporter); ok {
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
	if wsConfig == nil {
		return "", errors.New("controller: websocket config unavailable")
	}
	if runtimeConfig != nil && strings.TrimSpace(runtimeConfig.Endpoint) != "" {
		return BuildWSEndpoint(wsConfig, runtimeConfig)
	}

	if discoverer, ok := apiClient.(api.WSEndpointDiscoverer); ok {
		if endpoint, err := discoverer.DiscoverWSEndpoint(); err == nil && strings.TrimSpace(endpoint) != "" {
			if err := validateDiscoveredWSEndpoint(wsConfig.APIHost, endpoint); err != nil {
				return "", err
			}
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

func validateDiscoveredWSEndpoint(apiHost, endpoint string) error {
	base, err := url.Parse(strings.TrimSpace(apiHost))
	if err != nil {
		return fmt.Errorf("controller: parse panel api host: %w", err)
	}
	if base.Scheme == "" || base.Host == "" {
		return errors.New("controller: panel api host must be absolute")
	}

	discovered, err := url.Parse(strings.TrimSpace(endpoint))
	if err != nil {
		return fmt.Errorf("controller: parse discovered websocket endpoint: %w", err)
	}
	discovered = base.ResolveReference(discovered)

	baseScheme, basePort, err := websocketOrigin(base)
	if err != nil {
		return err
	}
	discoveredScheme, discoveredPort, err := websocketOrigin(discovered)
	if err != nil {
		return err
	}
	if baseScheme != discoveredScheme ||
		!strings.EqualFold(base.Hostname(), discovered.Hostname()) ||
		basePort != discoveredPort {
		return errors.New("controller: discovered websocket endpoint must use the panel origin")
	}
	return nil
}

func websocketOrigin(endpoint *url.URL) (scheme, port string, err error) {
	switch strings.ToLower(endpoint.Scheme) {
	case "http", "ws":
		scheme = "ws"
		port = endpoint.Port()
		if port == "" {
			port = "80"
		}
	case "https", "wss":
		scheme = "wss"
		port = endpoint.Port()
		if port == "" {
			port = "443"
		}
	default:
		return "", "", fmt.Errorf("controller: unsupported websocket endpoint scheme %q", endpoint.Scheme)
	}
	return scheme, port, nil
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
	err = hooks.runtime.addTag(newNodeInfo, tag, c.config)
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

	err = hooks.runtime.addUsers(userInfo, newNodeInfo, tag, c.config)
	if err != nil {
		return err
	}

	// Add Limiter
	if err := hooks.limiter.addInbound(tag, newNodeInfo.SpeedLimit, userInfo, c.config.GlobalDeviceLimitConfig); err != nil {
		c.logger.Print(err)
	}

	// Add Rule Manager
	if !c.config.DisableGetRule {
		if ruleList, err := c.apiClient.GetNodeRule(); err != nil {
			c.logger.Printf("Get rule list filed: %s", err)
		} else if ruleList != nil {
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
	if err := c.startControllerPeriodicTasks(newNodeInfo); err != nil {
		return err
	}

	return nil
}

// Close implement the Close() function of the service interface
func (c *Controller) Close() error {
	var closeErrors []error
	if err := c.closePeriodicTasks(); err != nil {
		closeErrors = append(closeErrors, err)
	}

	if c.wsRuntime != nil {
		c.wsRuntime.Stop()
		c.wsRuntime = nil
	}
	if c.syncCoordinator != nil {
		c.syncCoordinator.Stop()
		c.syncCoordinator = nil
	}

	return errors.Join(closeErrors...)
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
	return c.addNewTagWithConfig(newNodeInfo, tag, c.config)
}

func (c *Controller) addNewTagWithConfig(newNodeInfo *api.NodeInfo, tag string, config *Config) (err error) {
	node := normalizeNodeInfo(newNodeInfo)
	inbound := node.inboundView()
	outbound := node.outboundView()
	routePolicy := node.routingPolicy()
	nodeType := inbound.listener.nodeType

	// Socks/HTTP inbounds are built with users embedded (no UserManager support).
	// Skip here — the inbound will be created by rebuildInboundWithUsers() in addNewUser().
	if nodeType == "Socks" || nodeType == "HTTP" {
		// Still need the outbound for routing
		outBoundConfig, err := buildOutbound(config, outbound, tag)
		if err != nil {
			return err
		}
		return c.addOutbound(outBoundConfig, tag, routePolicy)
	}

	if nodeType != "Shadowsocks-Plugin" {
		inboundConfig, err := buildInbound(config, inbound, tag)
		if err != nil {
			return err
		}
		err = c.addInbound(inboundConfig)
		if err != nil {

			return err
		}
		outBoundConfig, err := buildOutbound(config, outbound, tag)
		if err != nil {

			return err
		}
		err = c.addOutbound(outBoundConfig, tag, routePolicy)
		if err != nil {

			return err
		}

	} else {
		return c.addInboundForSSPlugin(node, tag, config)
	}
	return nil
}

func (c *Controller) addInboundForSSPlugin(node nodeValue, tag string, config *Config) (err error) {
	// Shadowsocks-Plugin require a separate inbound for other TransportProtocol likes: ws, grpc
	views := node.shadowsocksPluginViews()
	// Add a regular Shadowsocks inbound and outbound
	inboundConfig, err := buildInbound(config, views.regularInbound, tag)
	if err != nil {
		return err
	}
	err = c.addInbound(inboundConfig)
	if err != nil {

		return err
	}
	outBoundConfig, err := buildOutbound(config, views.regularOutbound, tag)
	if err != nil {

		return err
	}
	err = c.addOutbound(outBoundConfig, tag, views.routing)
	if err != nil {

		return err
	}
	// Add an inbound for upper streaming protocol
	dokodemoTag := fmt.Sprintf("dokodemo-door_%s+1", tag)
	inboundConfig, err = buildInbound(config, views.bridgeInbound, dokodemoTag)
	if err != nil {
		return err
	}
	err = c.addInbound(inboundConfig)
	if err != nil {

		return err
	}
	outBoundConfig, err = buildOutbound(config, views.bridgeOutbound, dokodemoTag)
	if err != nil {

		return err
	}
	err = c.addOutbound(outBoundConfig, dokodemoTag, views.routing)
	if err != nil {

		return err
	}
	return nil
}

// rebuildInboundWithUsers rebuilds the socks/http inbound with all users embedded.
// This is needed because socks/http inbounds don't support proxy.UserManager.
func (c *Controller) rebuildInboundWithUsers(userInfo *[]api.UserInfo, nodeInfo *api.NodeInfo, tag string) error {
	return c.rebuildInboundWithUsersWithConfig(userInfo, nodeInfo, tag, c.config)
}

func (c *Controller) rebuildInboundWithUsersWithConfig(userInfo *[]api.UserInfo, nodeInfo *api.NodeInfo, tag string, config *Config) error {
	// Remove existing inbound if present (ignore errors for first-time setup)
	_ = c.removeInbound(tag)

	// Build inbound with all users
	inboundConfig, err := buildInboundWithUsers(config, normalizeNodeInfo(nodeInfo).inboundView().listener, tag, userInfo)
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
	return c.addNewUserWithConfig(userInfo, nodeInfo, tag, c.config)
}

func (c *Controller) addNewUserWithConfig(userInfo *[]api.UserInfo, nodeInfo *api.NodeInfo, tag string, config *Config) (err error) {
	node := normalizeNodeInfo(nodeInfo).userView()

	// Socks/HTTP don't support proxy.UserManager — rebuild entire inbound with users embedded
	if node.nodeType == "Socks" || node.nodeType == "HTTP" {
		return c.rebuildInboundWithUsersWithConfig(userInfo, nodeInfo, tag, config)
	}

	users := make([]*protocol.User, 0)
	switch node.nodeType {
	case "V2ray", "Vmess", "Vless":
		if node.enableVless || (node.nodeType == "Vless" && node.nodeType != "Vmess") {
			users = c.buildVlessUser(userInfo, node.vless, tag)
		} else {
			users = c.buildVmessUser(userInfo, tag)
		}
	case "Trojan":
		users = c.buildTrojanUser(userInfo, tag)
	case "Shadowsocks":
		users = c.buildSSUser(userInfo, node.cypherMethod, tag)
	case "Shadowsocks-Plugin":
		users = c.buildSSPluginUser(userInfo, tag)
	default:
		return fmt.Errorf("unsupported node type: %s", node.nodeType)
	}

	err = c.addUsers(users, tag)
	if err != nil {
		return err
	}
	c.logger.Printf("Added %d new users", len(*userInfo))
	return nil
}

func nodeStateChanged(currentNodeInfo, newNodeInfo *api.NodeInfo) bool {
	return !normalizeNodeInfo(currentNodeInfo).equal(normalizeNodeInfo(newNodeInfo))
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

	c.syncAliveListFromPanel(currentTag)

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

func (c *Controller) syncAliveListFromPanel(tag string) {
	provider, ok := c.apiClient.(api.AliveListProvider)
	if !ok {
		return
	}
	aliveList, err := provider.GetAliveList()
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

func (c *Controller) buildNodeTagFrom(nodeInfo *api.NodeInfo) string {
	// Include NodeID to avoid cross-node mixing when multiple logical nodes share
	// the same NodeType/ListenIP/Port (e.g., CDN or multi-node deployments).
	return managednode.BuildTag(nodeInfo.NodeType, c.config.ListenIP, nodeInfo.Port, nodeInfo.NodeID)
}

func (c *Controller) buildNodeTag() string {
	state := c.runtimeStateSnapshot()
	nodeInfo := state.node.snapshot()
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
	if c == nil {
		return nil
	}
	c.reloadMu.Lock()
	defer c.reloadMu.Unlock()

	return c.renewCertificateIfNeeded()
}

func (c *Controller) certMonitorPeriodic() error {
	if err := c.certMonitor(); err != nil {
		if c.logger != nil {
			if c.showErrorDetails() {
				c.logger.WithError(err).Warn("certificate renewal failed")
			} else {
				c.logger.Warn("certificate renewal failed; error details omitted because they may contain credentials")
			}
		}
	}
	return nil
}

func (c *Controller) renewCertificateIfNeeded() (err error) {
	if c == nil || c.config == nil {
		return nil
	}
	currentNodeInfo, currentTag, currentUsers := c.getStateSnapshot()
	if currentNodeInfo != nil && currentNodeInfo.EnableTLS && c.config.EnableREALITY == false && c.config.CertConfig != nil {
		switch c.config.CertConfig.CertMode {
		case "dns", "http", "tls":
			prepare := c.prepareRenewal
			if prepare == nil {
				prepare = defaultControllerPrepareCertificateRenewal
			}
			var renewal preparedCertificateRenewal
			renewal, err = prepare(c.config.CertConfig)
			if err != nil {
				return err
			}
			if renewal == nil {
				return errors.New("certificate renewal preparation returned nil")
			}
			defer func() {
				panicErr := certificateRenewalPanicError(recover())
				err = errors.Join(err, panicErr, rollbackPreparedCertificateRenewal(renewal))
			}()
			if !renewal.Renewed() {
				return renewal.Rollback()
			}
			if currentTag == "" {
				return errors.Join(
					errors.New("cannot replace certificate runtime without an applied node tag"),
					renewal.Rollback(),
				)
			}
			certificatePEM := renewal.CertificatePEM()
			privateKeyPEM := renewal.PrivateKeyPEM()
			if len(certificatePEM) == 0 || len(privateKeyPEM) == 0 {
				return errors.Join(
					errors.New("prepared certificate renewal is missing certificate or private key PEM"),
					renewal.Rollback(),
				)
			}

			appliedConfig := cloneControllerConfig(c.config)
			candidateConfig := cloneControllerConfig(c.config)
			candidateConfig.CertConfig.CertMode = "content"
			candidateConfig.CertConfig.CertFile = ""
			candidateConfig.CertConfig.KeyFile = ""
			candidateConfig.CertConfig.CertContent = string(certificatePEM)
			candidateConfig.CertConfig.KeyContent = string(privateKeyPEM)
			return newNodeRuntimeStateApplyModule(c).replaceCertificateRuntime(
				currentNodeInfo,
				currentTag,
				currentUsers,
				appliedConfig,
				candidateConfig,
				renewal,
			)
		}
	}
	return nil
}

func rollbackPreparedCertificateRenewal(renewal preparedCertificateRenewal) (err error) {
	if renewal == nil {
		return nil
	}
	defer func() {
		err = errors.Join(err, certificateRenewalPanicError(recover()))
	}()
	return renewal.Rollback()
}

func certificateRenewalPanicError(value any) error {
	if value == nil {
		return nil
	}
	if err, ok := value.(error); ok {
		return fmt.Errorf("certificate renewal transaction panicked: %w", err)
	}
	return fmt.Errorf("certificate renewal transaction panicked: %v", value)
}

func defaultControllerPrepareCertificateRenewal(certConfig *mylego.CertConfig) (preparedCertificateRenewal, error) {
	return mylego.PrepareRenewal(certConfig)
}
