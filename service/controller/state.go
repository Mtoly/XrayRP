package controller

import (
	"encoding/json"
	"reflect"

	"github.com/Mtoly/XrayRP/api"
	xraynet "github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/infra/conf"
)

type nodeRuntimeState struct {
	nodeInfoSet     bool
	nodeInfo        api.NodeInfo
	tag             string
	userListSet     bool
	userList        []api.UserInfo
	appliedRuleTag  string
	appliedRuleList []api.DetectRule
}

func cloneSlice[T any](values []T) []T {
	if values == nil {
		return nil
	}
	return append([]T{}, values...)
}

func cloneMap[K comparable, V any](values map[K]V) map[K]V {
	if values == nil {
		return nil
	}
	cloned := make(map[K]V, len(values))
	for key, value := range values {
		cloned[key] = value
	}
	return cloned
}

func cloneValue[T any](value *T) *T {
	if value == nil {
		return nil
	}
	cloned := *value
	return &cloned
}

func cloneRawMessage(value json.RawMessage) json.RawMessage {
	return cloneSlice(value)
}

func cloneStringList(value *conf.StringList) *conf.StringList {
	if value == nil {
		return nil
	}
	cloned := conf.StringList(cloneSlice([]string(*value)))
	return &cloned
}

func cloneHTTPHeaders(headers map[string]*conf.StringList) map[string]*conf.StringList {
	if headers == nil {
		return nil
	}
	cloned := make(map[string]*conf.StringList, len(headers))
	for key, values := range headers {
		cloned[key] = cloneStringList(values)
	}
	return cloned
}

func isNilXrayAddress(value xraynet.Address) bool {
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

func cloneXrayAddress(value xraynet.Address) xraynet.Address {
	if isNilXrayAddress(value) {
		return value
	}
	switch value.Family() {
	case xraynet.AddressFamilyIPv4, xraynet.AddressFamilyIPv6:
		return xraynet.IPAddress(cloneSlice([]byte(value.IP())))
	case xraynet.AddressFamilyDomain:
		return xraynet.DomainAddress(value.Domain())
	default:
		// Xray only defines the three families above. Keep an unknown custom
		// implementation intact rather than changing its semantics by reparsing it.
		return value
	}
}

func cloneAddress(value *conf.Address) *conf.Address {
	if value == nil {
		return nil
	}
	cloned := *value
	cloned.Address = cloneXrayAddress(value.Address)
	return &cloned
}

func cloneNameServerConfig(config *conf.NameServerConfig) *conf.NameServerConfig {
	if config == nil {
		return nil
	}
	cloned := *config
	cloned.Address = cloneAddress(config.Address)
	cloned.ClientIP = cloneAddress(config.ClientIP)
	cloned.Domains = cloneSlice(config.Domains)
	cloned.ExpectedIPs = conf.StringList(cloneSlice([]string(config.ExpectedIPs)))
	cloned.ExpectIPs = conf.StringList(cloneSlice([]string(config.ExpectIPs)))
	cloned.DisableCache = cloneValue(config.DisableCache)
	cloned.ServeStale = cloneValue(config.ServeStale)
	cloned.ServeExpiredTTL = cloneValue(config.ServeExpiredTTL)
	cloned.UnexpectedIPs = conf.StringList(cloneSlice([]string(config.UnexpectedIPs)))
	return &cloned
}

func cloneNameServerConfigs(configs []*conf.NameServerConfig) []*conf.NameServerConfig {
	if configs == nil {
		return nil
	}
	cloned := make([]*conf.NameServerConfig, len(configs))
	for index, config := range configs {
		cloned[index] = cloneNameServerConfig(config)
	}
	return cloned
}

func cloneREALITYConfig(config *api.REALITYConfig) *api.REALITYConfig {
	if config == nil {
		return nil
	}
	cloned := *config
	cloned.ServerNames = cloneSlice(config.ServerNames)
	cloned.ShortIds = cloneSlice(config.ShortIds)
	return &cloned
}

func cloneAnyTLSConfig(config *api.AnyTLSConfig) *api.AnyTLSConfig {
	if config == nil {
		return nil
	}
	cloned := *config
	cloned.PaddingScheme = cloneSlice(config.PaddingScheme)
	return &cloned
}

func cloneTuicConfig(config *api.TuicConfig) *api.TuicConfig {
	if config == nil {
		return nil
	}
	cloned := *config
	cloned.ALPN = cloneSlice(config.ALPN)
	return &cloned
}

func cloneRoutePolicy(policy *api.PanelRoutePolicy) *api.PanelRoutePolicy {
	if policy == nil {
		return nil
	}
	cloned := *policy
	cloned.DirectDomains = cloneSlice(policy.DirectDomains)
	cloned.Outbound.Candidates = cloneSlice(policy.Outbound.Candidates)
	cloned.Outbound.Include = cloneSlice(policy.Outbound.Include)
	cloned.Outbound.Exclude = cloneSlice(policy.Outbound.Exclude)
	cloned.Outbound.Fallback = cloneSlice(policy.Outbound.Fallback)
	return &cloned
}

func cloneNodeInfoValue(nodeInfo api.NodeInfo) api.NodeInfo {
	cloned := nodeInfo
	cloned.Header = cloneRawMessage(nodeInfo.Header)
	cloned.HttpHeaders = cloneHTTPHeaders(nodeInfo.HttpHeaders)
	cloned.Headers = cloneMap(nodeInfo.Headers)
	cloned.NameServerConfig = cloneNameServerConfigs(nodeInfo.NameServerConfig)
	cloned.REALITYConfig = cloneREALITYConfig(nodeInfo.REALITYConfig)
	cloned.ServerNames = cloneSlice(nodeInfo.ServerNames)
	cloned.ShortIds = cloneSlice(nodeInfo.ShortIds)
	cloned.Hysteria2Config = cloneValue(nodeInfo.Hysteria2Config)
	cloned.AnyTLSConfig = cloneAnyTLSConfig(nodeInfo.AnyTLSConfig)
	cloned.TuicConfig = cloneTuicConfig(nodeInfo.TuicConfig)
	cloned.RoutePolicy = cloneRoutePolicy(nodeInfo.RoutePolicy)
	cloned.XHTTPExtra = cloneRawMessage(nodeInfo.XHTTPExtra)
	cloned.XPaddingBytes = cloneValue(nodeInfo.XPaddingBytes)
	cloned.ScMaxEachPostBytes = cloneValue(nodeInfo.ScMaxEachPostBytes)
	cloned.ScMinPostsIntervalMs = cloneValue(nodeInfo.ScMinPostsIntervalMs)
	cloned.ScStreamUpServerSecs = cloneValue(nodeInfo.ScStreamUpServerSecs)
	cloned.XmuxMaxConcurrency = cloneValue(nodeInfo.XmuxMaxConcurrency)
	cloned.XmuxMaxConnections = cloneValue(nodeInfo.XmuxMaxConnections)
	cloned.XmuxCMaxReuseTimes = cloneValue(nodeInfo.XmuxCMaxReuseTimes)
	cloned.XmuxHMaxRequestTimes = cloneValue(nodeInfo.XmuxHMaxRequestTimes)
	cloned.XmuxHMaxReusableSecs = cloneValue(nodeInfo.XmuxHMaxReusableSecs)
	cloned.XHTTPDownloadSettings = cloneRawMessage(nodeInfo.XHTTPDownloadSettings)
	return cloned
}

func cloneDetectRules(rules []api.DetectRule) []api.DetectRule {
	if rules == nil {
		return nil
	}
	cloned := make([]api.DetectRule, len(rules))
	for index, rule := range rules {
		cloned[index] = rule
		if rule.Pattern != nil {
			cloned[index].Pattern = rule.Pattern.Copy()
		}
	}
	return cloned
}

func cloneNodeRuntimeState(state nodeRuntimeState) nodeRuntimeState {
	if state.nodeInfoSet {
		state.nodeInfo = cloneNodeInfoValue(state.nodeInfo)
	}
	state.userList = cloneSlice(state.userList)
	state.appliedRuleList = cloneDetectRules(state.appliedRuleList)
	return state
}

func (state nodeRuntimeState) nodeInfoSnapshot() *api.NodeInfo {
	if !state.nodeInfoSet {
		return nil
	}
	cloned := cloneNodeInfoValue(state.nodeInfo)
	return &cloned
}

func (state nodeRuntimeState) userListSnapshot() *[]api.UserInfo {
	if !state.userListSet {
		return nil
	}
	cloned := cloneSlice(state.userList)
	return &cloned
}

func (c *Controller) runtimeStateSnapshot() nodeRuntimeState {
	c.stateMu.RLock()
	defer c.stateMu.RUnlock()
	return cloneNodeRuntimeState(c.runtimeState)
}

func (c *Controller) commitRuntimeState(state nodeRuntimeState) {
	c.stateMu.Lock()
	c.runtimeState = cloneNodeRuntimeState(state)
	c.stateMu.Unlock()
}

func (c *Controller) getStateSnapshot() (nodeInfo *api.NodeInfo, tag string, userList *[]api.UserInfo) {
	c.stateMu.RLock()
	defer c.stateMu.RUnlock()
	return c.runtimeState.nodeInfoSnapshot(), c.runtimeState.tag, c.runtimeState.userListSnapshot()
}

func (c *Controller) setNodeState(nodeInfo *api.NodeInfo, tag string) {
	c.stateMu.Lock()
	defer c.stateMu.Unlock()
	c.runtimeState.nodeInfoSet = nodeInfo != nil
	if nodeInfo == nil {
		c.runtimeState.nodeInfo = api.NodeInfo{}
	} else {
		c.runtimeState.nodeInfo = cloneNodeInfoValue(*nodeInfo)
	}
	c.runtimeState.tag = tag
}

func (c *Controller) setUserList(userList *[]api.UserInfo) {
	c.stateMu.Lock()
	defer c.stateMu.Unlock()
	c.runtimeState.userListSet = userList != nil
	if userList == nil {
		c.runtimeState.userList = nil
	} else {
		c.runtimeState.userList = cloneSlice(*userList)
	}
}

func (c *Controller) withStateLock(fn func()) {
	c.stateMu.Lock()
	defer c.stateMu.Unlock()
	fn()
}

func (c *Controller) getAppliedRuleTag() string {
	c.stateMu.RLock()
	defer c.stateMu.RUnlock()
	return c.runtimeState.appliedRuleTag
}

func (c *Controller) getAppliedRuleState() (string, []api.DetectRule) {
	c.stateMu.RLock()
	defer c.stateMu.RUnlock()
	return c.runtimeState.appliedRuleTag, cloneDetectRules(c.runtimeState.appliedRuleList)
}

func (c *Controller) setAppliedRuleState(tag string, rules []api.DetectRule) {
	c.stateMu.Lock()
	defer c.stateMu.Unlock()
	c.runtimeState.appliedRuleTag = tag
	c.runtimeState.appliedRuleList = cloneDetectRules(rules)
}

func (c *Controller) getAppliedRuleList() []api.DetectRule {
	c.stateMu.RLock()
	defer c.stateMu.RUnlock()
	return cloneDetectRules(c.runtimeState.appliedRuleList)
}

func (c *Controller) setAppliedRuleList(rules []api.DetectRule) {
	c.stateMu.Lock()
	defer c.stateMu.Unlock()
	tag := c.runtimeState.appliedRuleTag
	if tag == "" {
		tag = c.runtimeState.tag
	}
	c.runtimeState.appliedRuleTag = tag
	c.runtimeState.appliedRuleList = cloneDetectRules(rules)
}
