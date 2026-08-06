// Package appliednode owns the deep-clone contract for Applied node values.
package appliednode

import (
	"encoding/json"
	"reflect"

	"github.com/Mtoly/XrayRP/api"
	xraynet "github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/infra/conf"
)

// Clone returns an independently owned NodeInfo value. Custom xraynet.Address
// implementations remain shared because the open interface has no clone contract.
func Clone(nodeInfo *api.NodeInfo) *api.NodeInfo {
	if nodeInfo == nil {
		return nil
	}
	cloned := *nodeInfo
	cloned.Header = cloneSlice(json.RawMessage(nodeInfo.Header))
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
	cloned.XHTTPExtra = cloneSlice(json.RawMessage(nodeInfo.XHTTPExtra))
	cloned.XPaddingBytes = cloneValue(nodeInfo.XPaddingBytes)
	cloned.ScMaxEachPostBytes = cloneValue(nodeInfo.ScMaxEachPostBytes)
	cloned.ScMinPostsIntervalMs = cloneValue(nodeInfo.ScMinPostsIntervalMs)
	cloned.ScStreamUpServerSecs = cloneValue(nodeInfo.ScStreamUpServerSecs)
	cloned.XmuxMaxConcurrency = cloneValue(nodeInfo.XmuxMaxConcurrency)
	cloned.XmuxMaxConnections = cloneValue(nodeInfo.XmuxMaxConnections)
	cloned.XmuxCMaxReuseTimes = cloneValue(nodeInfo.XmuxCMaxReuseTimes)
	cloned.XmuxHMaxRequestTimes = cloneValue(nodeInfo.XmuxHMaxRequestTimes)
	cloned.XmuxHMaxReusableSecs = cloneValue(nodeInfo.XmuxHMaxReusableSecs)
	cloned.XHTTPDownloadSettings = cloneSlice(json.RawMessage(nodeInfo.XHTTPDownloadSettings))
	return &cloned
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
	switch reflect.TypeOf(value) {
	case xrayIPv4AddressType, xrayIPv6AddressType:
		return xraynet.IPAddress(cloneSlice([]byte(value.IP())))
	case xrayDomainAddressType:
		return xraynet.DomainAddress(value.Domain())
	default:
		return value
	}
}

var (
	xrayIPv4AddressType   = reflect.TypeOf(xraynet.IPAddress([]byte{0, 0, 0, 0}))
	xrayIPv6AddressType   = reflect.TypeOf(xraynet.IPAddress(make([]byte, 16)))
	xrayDomainAddressType = reflect.TypeOf(xraynet.DomainAddress(""))
)

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
