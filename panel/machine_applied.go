package panel

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"reflect"
	"sync"

	"github.com/Mtoly/XrayRP/api"
	"github.com/Mtoly/XrayRP/service"
	"github.com/Mtoly/XrayRP/service/controller"
	xraynet "github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/infra/conf"
)

type machineAppliedNodeValue struct {
	nodeInfo    *api.NodeInfo
	userList    *[]api.UserInfo
	ruleList    *[]api.DetectRule
	nodeSet     bool
	userListSet bool
	ruleListSet bool
}

func (value machineAppliedNodeValue) clone() machineAppliedNodeValue {
	return machineAppliedNodeValue{
		nodeInfo:    cloneMachineNodeInfo(value.nodeInfo),
		userList:    cloneMachineUserList(value.userList),
		ruleList:    cloneMachineRuleList(value.ruleList),
		nodeSet:     value.nodeSet,
		userListSet: value.userListSet,
		ruleListSet: value.ruleListSet,
	}
}

type machineAppliedPanelClient struct {
	source runtimePanelClient

	mu               sync.Mutex
	captured         machineAppliedNodeValue
	applied          machineAppliedNodeValue
	appliedSet       bool
	seed             machineAppliedNodeValue
	seedNodePending  bool
	seedUsersPending bool
	seedRulesPending bool
}

func newMachineAppliedPanelClient(source runtimePanelClient, seed *machineAppliedNodeValue) *machineAppliedPanelClient {
	client := &machineAppliedPanelClient{source: source}
	if seed != nil {
		client.seed = seed.clone()
		client.seedNodePending = seed.nodeSet
		client.seedUsersPending = seed.userListSet
		client.seedRulesPending = seed.ruleListSet
	}
	return client
}

func (c *machineAppliedPanelClient) Describe() api.ClientInfo {
	if c == nil || c.source == nil {
		return api.ClientInfo{}
	}
	return c.source.Describe()
}

func (c *machineAppliedPanelClient) GetNodeInfo() (*api.NodeInfo, error) {
	return c.GetNodeInfoContext(context.Background())
}

func (c *machineAppliedPanelClient) GetNodeInfoContext(ctx context.Context) (*api.NodeInfo, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	c.mu.Lock()
	if c.seedNodePending {
		c.seedNodePending = false
		nodeInfo := cloneMachineNodeInfo(c.seed.nodeInfo)
		c.captured.nodeInfo = cloneMachineNodeInfo(nodeInfo)
		c.captured.nodeSet = true
		c.mu.Unlock()
		return nodeInfo, nil
	}
	c.mu.Unlock()

	nodeInfo, err := api.GetNodeInfoContext(ctx, c.source)
	if err != nil {
		return nil, err
	}
	c.mu.Lock()
	c.captured.nodeInfo = cloneMachineNodeInfo(nodeInfo)
	c.captured.nodeSet = true
	c.mu.Unlock()
	return cloneMachineNodeInfo(nodeInfo), nil
}

func (c *machineAppliedPanelClient) GetUserList() (*[]api.UserInfo, error) {
	return c.GetUserListContext(context.Background())
}

func (c *machineAppliedPanelClient) GetUserListContext(ctx context.Context) (*[]api.UserInfo, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	c.mu.Lock()
	if c.seedUsersPending {
		c.seedUsersPending = false
		users := cloneMachineUserList(c.seed.userList)
		c.captured.userList = cloneMachineUserList(users)
		c.captured.userListSet = true
		c.mu.Unlock()
		return users, nil
	}
	c.mu.Unlock()

	users, err := api.GetUserListContext(ctx, c.source)
	if err != nil {
		return nil, err
	}
	c.mu.Lock()
	c.captured.userList = cloneMachineUserList(users)
	c.captured.userListSet = true
	c.mu.Unlock()
	return cloneMachineUserList(users), nil
}

func (c *machineAppliedPanelClient) GetNodeRule() (*[]api.DetectRule, error) {
	return c.GetNodeRuleContext(context.Background())
}

func (c *machineAppliedPanelClient) GetNodeRuleContext(ctx context.Context) (*[]api.DetectRule, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	c.mu.Lock()
	if c.seedRulesPending {
		c.seedRulesPending = false
		rules := cloneMachineRuleList(c.seed.ruleList)
		c.captured.ruleList = cloneMachineRuleList(rules)
		c.captured.ruleListSet = true
		c.mu.Unlock()
		return rules, nil
	}
	c.mu.Unlock()

	rules, err := api.GetNodeRuleContext(ctx, c.source)
	if err != nil {
		return nil, err
	}
	c.mu.Lock()
	c.captured.ruleList = cloneMachineRuleList(rules)
	c.captured.ruleListSet = true
	c.mu.Unlock()
	return cloneMachineRuleList(rules), nil
}

func (c *machineAppliedPanelClient) appliedNodeValue() (machineAppliedNodeValue, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if !c.appliedSet {
		if !c.captured.nodeSet || !c.captured.userListSet {
			return machineAppliedNodeValue{}, errors.New("machine runtime did not publish a complete applied node value")
		}
		c.applied = c.captured.clone()
		c.appliedSet = true
	}
	if !c.applied.nodeSet || !c.applied.userListSet {
		return machineAppliedNodeValue{}, errors.New("machine runtime did not publish a complete applied node value")
	}
	return c.applied.clone(), nil
}

func (c *machineAppliedPanelClient) RecordSnapshotSyncApplied(scope service.SnapshotSyncScope) {
	if c == nil {
		return
	}
	scope &= service.SnapshotSyncAll
	if !scope.Valid() {
		return
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if !c.appliedSet {
		return
	}
	if scope.Includes(service.SnapshotSyncNode) && c.captured.nodeSet {
		c.applied.nodeInfo = cloneMachineNodeInfo(c.captured.nodeInfo)
		c.applied.nodeSet = true
	}
	if scope.Includes(service.SnapshotSyncUsers) && c.captured.userListSet {
		c.applied.userList = cloneMachineUserList(c.captured.userList)
		c.applied.userListSet = true
	}
	if scope.Includes(service.SnapshotSyncRules) && c.captured.ruleListSet {
		c.applied.ruleList = cloneMachineRuleList(c.captured.ruleList)
		c.applied.ruleListSet = true
	}
}

func (c *machineAppliedPanelClient) ReportNodeStatus(status *api.NodeStatus) error {
	return c.ReportNodeStatusContext(context.Background(), status)
}

func (c *machineAppliedPanelClient) ReportNodeStatusContext(ctx context.Context, status *api.NodeStatus) error {
	return api.ReportNodeStatusContext(ctx, c.source, status)
}

func (c *machineAppliedPanelClient) ReportNodeOnlineUsers(users *[]api.OnlineUser) error {
	return c.ReportNodeOnlineUsersContext(context.Background(), users)
}

func (c *machineAppliedPanelClient) ReportNodeOnlineUsersContext(ctx context.Context, users *[]api.OnlineUser) error {
	return api.ReportNodeOnlineUsersContext(ctx, c.source, users)
}

func (c *machineAppliedPanelClient) ReportUserTraffic(traffic *[]api.UserTraffic) error {
	return c.ReportUserTrafficContext(context.Background(), traffic)
}

func (c *machineAppliedPanelClient) ReportUserTrafficContext(ctx context.Context, traffic *[]api.UserTraffic) error {
	return api.ReportUserTrafficContext(ctx, c.source, traffic)
}

func (c *machineAppliedPanelClient) ReportIllegal(results *[]api.DetectResult) error {
	return c.ReportIllegalContext(context.Background(), results)
}

func (c *machineAppliedPanelClient) ReportIllegalContext(ctx context.Context, results *[]api.DetectResult) error {
	return api.ReportIllegalContext(ctx, c.source, results)
}

func (c *machineAppliedPanelClient) GetWSConfig() *api.WSConfig {
	provider, ok := c.source.(api.WSCapable)
	if !ok {
		return nil
	}
	config := provider.GetWSConfig()
	if config == nil {
		return nil
	}
	cloned := *config
	return &cloned
}

func (c *machineAppliedPanelClient) DiscoverWSEndpoint() (string, error) {
	return c.DiscoverWSEndpointContext(context.Background())
}

func (c *machineAppliedPanelClient) DiscoverWSEndpointContext(ctx context.Context) (string, error) {
	provider, ok := c.source.(api.WSEndpointDiscoverer)
	if !ok {
		return "", api.ErrUnsupportedPanelFeature
	}
	return api.DiscoverWSEndpointContext(ctx, provider)
}

func (c *machineAppliedPanelClient) GetBaseConfig() *api.BaseConfig {
	provider, ok := c.source.(api.BaseConfigProvider)
	if !ok {
		return nil
	}
	config := provider.GetBaseConfig()
	if config == nil {
		return nil
	}
	cloned := *config
	return &cloned
}

func (c *machineAppliedPanelClient) GetXrayRCertConfig() (*api.XrayRCertConfig, error) {
	return c.GetXrayRCertConfigContext(context.Background())
}

func (c *machineAppliedPanelClient) GetXrayRCertConfigContext(ctx context.Context) (*api.XrayRCertConfig, error) {
	provider, ok := c.source.(api.CertConfigProvider)
	if !ok {
		return nil, api.ErrUnsupportedPanelFeature
	}
	return api.GetXrayRCertConfigContext(ctx, provider)
}

func (c *machineAppliedPanelClient) GetAliveList() (map[int][]string, error) {
	return c.GetAliveListContext(context.Background())
}

func (c *machineAppliedPanelClient) GetAliveListContext(ctx context.Context) (map[int][]string, error) {
	provider, ok := c.source.(api.AliveListProvider)
	if !ok {
		return nil, api.ErrUnsupportedPanelFeature
	}
	alive, err := api.GetAliveListContext(ctx, provider)
	if err != nil || alive == nil {
		return alive, err
	}
	cloned := make(map[int][]string, len(alive))
	for userID, ips := range alive {
		cloned[userID] = append([]string(nil), ips...)
	}
	return cloned, nil
}

func (c *machineAppliedPanelClient) ReportNodeDevices(devices map[int][]string) error {
	reporter, ok := c.source.(interface {
		ReportNodeDevices(map[int][]string) error
	})
	if !ok {
		return nil
	}
	return reporter.ReportNodeDevices(devices)
}

func (c *machineAppliedPanelClient) DeviceReporterReady() bool {
	readiness, ok := c.source.(interface{ DeviceReporterReady() bool })
	return !ok || readiness.DeviceReporterReady()
}

type machineRuntimeNodeService struct {
	inner            service.Service
	client           *machineAppliedPanelClient
	controllerConfig *controller.Config
	restore          func(machineAppliedNodeValue, *controller.Config) (service.Service, error)
	snapshotRuntime  machineSnapshotRuntime

	mu            sync.Mutex
	appliedValue  *machineAppliedNodeValue
	appliedConfig *controller.Config
}

type machineSnapshotRuntime interface {
	StartContext(context.Context) error
	StopContext(context.Context) error
}

func newMachineRuntimeNodeService(
	inner service.Service,
	client *machineAppliedPanelClient,
	controllerConfig *controller.Config,
	seed *machineAppliedNodeValue,
	restore func(machineAppliedNodeValue, *controller.Config) (service.Service, error),
) *machineRuntimeNodeService {
	runtime := &machineRuntimeNodeService{
		inner:            inner,
		client:           client,
		controllerConfig: controllerConfig,
		restore:          restore,
	}
	if seed != nil {
		value := seed.clone()
		runtime.appliedValue = &value
		if cloned, err := cloneControllerConfig(controllerConfig); err == nil {
			runtime.appliedConfig = cloned
		}
	}
	return runtime
}

func (s *machineRuntimeNodeService) Start() error {
	ctx, cancel := service.WithDefaultTimeout(context.Background(), service.DefaultStartTimeout)
	defer cancel()
	return s.StartContext(ctx)
}

func (s *machineRuntimeNodeService) ObservabilitySnapshot() service.RuntimeSnapshot {
	if s == nil || s.inner == nil {
		return service.RuntimeSnapshot{Lifecycle: service.RuntimeLifecycleStopped, WebSocket: service.WebSocketDisabled}
	}
	if provider, ok := s.inner.(service.RuntimeSnapshotProvider); ok {
		return provider.ObservabilitySnapshot()
	}
	return service.RuntimeSnapshot{Lifecycle: service.RuntimeLifecycleRunning, WebSocket: service.WebSocketDisabled}
}

func (s *machineRuntimeNodeService) StartContext(ctx context.Context) error {
	if s == nil || s.inner == nil {
		return errors.New("machine runtime node service is nil")
	}
	if err := service.StartContext(ctx, s.inner); err != nil {
		return err
	}
	if err := ctx.Err(); err != nil {
		return errors.Join(err, s.cleanupUnpublishedContext(ctx))
	}
	value, err := s.client.appliedNodeValue()
	if err != nil {
		return errors.Join(err, s.cleanupUnpublishedContext(ctx))
	}
	config, err := cloneControllerConfig(s.controllerConfig)
	if err != nil {
		return errors.Join(
			fmt.Errorf("clone applied machine controller config: %w", err),
			s.cleanupUnpublishedContext(ctx),
		)
	}
	if err := ctx.Err(); err != nil {
		return errors.Join(err, s.cleanupUnpublishedContext(ctx))
	}
	if s.snapshotRuntime != nil {
		if err := s.snapshotRuntime.StartContext(ctx); err != nil {
			return errors.Join(err, s.cleanupUnpublishedContext(ctx))
		}
	}
	if err := ctx.Err(); err != nil {
		return errors.Join(err, s.cleanupUnpublishedContext(ctx))
	}
	s.mu.Lock()
	s.appliedValue = &value
	s.appliedConfig = config
	s.mu.Unlock()
	return nil
}

func (s *machineRuntimeNodeService) Close() error {
	ctx, cancel := service.WithDefaultTimeout(context.Background(), service.DefaultCloseTimeout)
	defer cancel()
	return s.CloseContext(ctx)
}

func (s *machineRuntimeNodeService) CloseContext(ctx context.Context) error {
	if s == nil || s.inner == nil {
		return nil
	}
	var mailboxErr error
	if s.snapshotRuntime != nil {
		mailboxErr = s.snapshotRuntime.StopContext(ctx)
	}
	return errors.Join(mailboxErr, service.CloseContext(ctx, s.inner))
}

func (s *machineRuntimeNodeService) cleanupUnpublishedContext(ctx context.Context) error {
	cleanupCtx, cancel := service.CleanupContext(ctx)
	defer cancel()
	var mailboxErr error
	if s.snapshotRuntime != nil {
		mailboxErr = s.snapshotRuntime.StopContext(cleanupCtx)
	}
	return errors.Join(mailboxErr, service.CloseContext(cleanupCtx, s.inner))
}
func (s *machineRuntimeNodeService) RestoreMachineRuntime() (service.Service, error) {
	if s == nil || s.restore == nil {
		return nil, errors.New("machine runtime restoration is unavailable")
	}
	value, valueErr := s.client.appliedNodeValue()
	s.mu.Lock()
	if valueErr != nil && s.appliedValue != nil {
		value = s.appliedValue.clone()
		valueErr = nil
	}
	if valueErr != nil || s.appliedConfig == nil {
		s.mu.Unlock()
		return nil, errors.Join(errors.New("machine runtime applied node value is unavailable"), valueErr)
	}
	config, err := cloneControllerConfig(s.appliedConfig)
	s.mu.Unlock()
	if err != nil {
		return nil, fmt.Errorf("clone machine rollback controller config: %w", err)
	}
	return s.restore(value, config)
}

func cloneMachineUserList(users *[]api.UserInfo) *[]api.UserInfo {
	if users == nil {
		return nil
	}
	cloned := append([]api.UserInfo(nil), (*users)...)
	return &cloned
}

func cloneMachineRuleList(rules *[]api.DetectRule) *[]api.DetectRule {
	if rules == nil {
		return nil
	}
	cloned := make([]api.DetectRule, len(*rules))
	for index, rule := range *rules {
		cloned[index] = rule
		if rule.Pattern != nil {
			cloned[index].Pattern = rule.Pattern.Copy()
		}
	}
	return &cloned
}

func cloneMachineSlice[T any](values []T) []T {
	if values == nil {
		return nil
	}
	return append([]T(nil), values...)
}

func cloneMachineMap[K comparable, V any](values map[K]V) map[K]V {
	if values == nil {
		return nil
	}
	cloned := make(map[K]V, len(values))
	for key, value := range values {
		cloned[key] = value
	}
	return cloned
}

func cloneMachineValue[T any](value *T) *T {
	if value == nil {
		return nil
	}
	cloned := *value
	return &cloned
}

func cloneMachineStringList(value *conf.StringList) *conf.StringList {
	if value == nil {
		return nil
	}
	cloned := conf.StringList(cloneMachineSlice([]string(*value)))
	return &cloned
}

func cloneMachineHTTPHeaders(headers map[string]*conf.StringList) map[string]*conf.StringList {
	if headers == nil {
		return nil
	}
	cloned := make(map[string]*conf.StringList, len(headers))
	for key, values := range headers {
		cloned[key] = cloneMachineStringList(values)
	}
	return cloned
}

func isNilMachineXrayAddress(value xraynet.Address) bool {
	if value == nil {
		return true
	}
	reflected := reflect.ValueOf(value)
	switch reflected.Kind() {
	case reflect.Chan, reflect.Func, reflect.Interface, reflect.Map, reflect.Ptr, reflect.Slice:
		return reflected.IsNil()
	default:
		return false
	}
}

func cloneMachineXrayAddress(value xraynet.Address) xraynet.Address {
	if isNilMachineXrayAddress(value) {
		return value
	}
	switch reflect.TypeOf(value) {
	case machineIPv4AddressType, machineIPv6AddressType:
		return xraynet.IPAddress(cloneMachineSlice([]byte(value.IP())))
	case machineDomainAddressType:
		return xraynet.DomainAddress(value.Domain())
	default:
		return value
	}
}

var (
	machineIPv4AddressType   = reflect.TypeOf(xraynet.IPAddress([]byte{0, 0, 0, 0}))
	machineIPv6AddressType   = reflect.TypeOf(xraynet.IPAddress(make([]byte, 16)))
	machineDomainAddressType = reflect.TypeOf(xraynet.DomainAddress(""))
)

func cloneMachineAddress(value *conf.Address) *conf.Address {
	if value == nil {
		return nil
	}
	cloned := *value
	cloned.Address = cloneMachineXrayAddress(value.Address)
	return &cloned
}

func cloneMachineNameServerConfig(config *conf.NameServerConfig) *conf.NameServerConfig {
	if config == nil {
		return nil
	}
	cloned := *config
	cloned.Address = cloneMachineAddress(config.Address)
	cloned.ClientIP = cloneMachineAddress(config.ClientIP)
	cloned.Domains = cloneMachineSlice(config.Domains)
	cloned.ExpectedIPs = conf.StringList(cloneMachineSlice([]string(config.ExpectedIPs)))
	cloned.ExpectIPs = conf.StringList(cloneMachineSlice([]string(config.ExpectIPs)))
	cloned.DisableCache = cloneMachineValue(config.DisableCache)
	cloned.ServeStale = cloneMachineValue(config.ServeStale)
	cloned.ServeExpiredTTL = cloneMachineValue(config.ServeExpiredTTL)
	cloned.UnexpectedIPs = conf.StringList(cloneMachineSlice([]string(config.UnexpectedIPs)))
	return &cloned
}

func cloneMachineNodeInfo(nodeInfo *api.NodeInfo) *api.NodeInfo {
	if nodeInfo == nil {
		return nil
	}
	cloned := *nodeInfo
	cloned.Header = cloneMachineSlice(json.RawMessage(nodeInfo.Header))
	cloned.HttpHeaders = cloneMachineHTTPHeaders(nodeInfo.HttpHeaders)
	cloned.Headers = cloneMachineMap(nodeInfo.Headers)
	if nodeInfo.NameServerConfig != nil {
		cloned.NameServerConfig = make([]*conf.NameServerConfig, len(nodeInfo.NameServerConfig))
		for index, config := range nodeInfo.NameServerConfig {
			cloned.NameServerConfig[index] = cloneMachineNameServerConfig(config)
		}
	}
	if nodeInfo.REALITYConfig != nil {
		reality := *nodeInfo.REALITYConfig
		reality.ServerNames = cloneMachineSlice(nodeInfo.REALITYConfig.ServerNames)
		reality.ShortIds = cloneMachineSlice(nodeInfo.REALITYConfig.ShortIds)
		cloned.REALITYConfig = &reality
	}
	cloned.ServerNames = cloneMachineSlice(nodeInfo.ServerNames)
	cloned.ShortIds = cloneMachineSlice(nodeInfo.ShortIds)
	cloned.Hysteria2Config = cloneMachineValue(nodeInfo.Hysteria2Config)
	if nodeInfo.AnyTLSConfig != nil {
		anyTLS := *nodeInfo.AnyTLSConfig
		anyTLS.PaddingScheme = cloneMachineSlice(nodeInfo.AnyTLSConfig.PaddingScheme)
		cloned.AnyTLSConfig = &anyTLS
	}
	if nodeInfo.TuicConfig != nil {
		tuic := *nodeInfo.TuicConfig
		tuic.ALPN = cloneMachineSlice(nodeInfo.TuicConfig.ALPN)
		cloned.TuicConfig = &tuic
	}
	if nodeInfo.RoutePolicy != nil {
		policy := *nodeInfo.RoutePolicy
		policy.DirectDomains = cloneMachineSlice(nodeInfo.RoutePolicy.DirectDomains)
		policy.Outbound.Candidates = cloneMachineSlice(nodeInfo.RoutePolicy.Outbound.Candidates)
		policy.Outbound.Include = cloneMachineSlice(nodeInfo.RoutePolicy.Outbound.Include)
		policy.Outbound.Exclude = cloneMachineSlice(nodeInfo.RoutePolicy.Outbound.Exclude)
		policy.Outbound.Fallback = cloneMachineSlice(nodeInfo.RoutePolicy.Outbound.Fallback)
		cloned.RoutePolicy = &policy
	}
	cloned.XHTTPExtra = cloneMachineSlice(json.RawMessage(nodeInfo.XHTTPExtra))
	cloned.XPaddingBytes = cloneMachineValue(nodeInfo.XPaddingBytes)
	cloned.ScMaxEachPostBytes = cloneMachineValue(nodeInfo.ScMaxEachPostBytes)
	cloned.ScMinPostsIntervalMs = cloneMachineValue(nodeInfo.ScMinPostsIntervalMs)
	cloned.ScStreamUpServerSecs = cloneMachineValue(nodeInfo.ScStreamUpServerSecs)
	cloned.XmuxMaxConcurrency = cloneMachineValue(nodeInfo.XmuxMaxConcurrency)
	cloned.XmuxMaxConnections = cloneMachineValue(nodeInfo.XmuxMaxConnections)
	cloned.XmuxCMaxReuseTimes = cloneMachineValue(nodeInfo.XmuxCMaxReuseTimes)
	cloned.XmuxHMaxRequestTimes = cloneMachineValue(nodeInfo.XmuxHMaxRequestTimes)
	cloned.XmuxHMaxReusableSecs = cloneMachineValue(nodeInfo.XmuxHMaxReusableSecs)
	cloned.XHTTPDownloadSettings = cloneMachineSlice(json.RawMessage(nodeInfo.XHTTPDownloadSettings))
	return &cloned
}
