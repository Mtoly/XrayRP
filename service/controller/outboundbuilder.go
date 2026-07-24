package controller

import (
	"encoding/json"
	"fmt"

	"github.com/xtls/xray-core/core"
	"github.com/xtls/xray-core/infra/conf"

	"github.com/Mtoly/XrayRP/api"
)

// OutboundBuilder is the compatibility adapter for callers that still provide
// api.NodeInfo. Internal controller paths call buildOutbound with a focused view.
func OutboundBuilder(config *Config, nodeInfo *api.NodeInfo, tag string) (*core.OutboundHandlerConfig, error) {
	return buildOutbound(config, normalizeNodeInfo(nodeInfo).outboundView(), tag)
}

func buildOutbound(config *Config, node outboundNodeView, tag string) (*core.OutboundHandlerConfig, error) {
	outboundDetourConfig := &conf.OutboundDetourConfig{}
	outboundDetourConfig.Protocol = "freedom"
	outboundDetourConfig.Tag = tag

	// SendThrough setting
	outboundDetourConfig.SendThrough = &config.SendIP

	// Freedom Protocol setting
	var domainStrategy = "Asis"
	if config.EnableDNS {
		if config.DNSType != "" {
			domainStrategy = config.DNSType
		} else {
			domainStrategy = "UseIP"
		}
	}
	proxySetting := &conf.FreedomConfig{
		DomainStrategy: domainStrategy,
	}
	// Used for Shadowsocks-Plugin
	if node.nodeType == "dokodemo-door" {
		proxySetting.Redirect = fmt.Sprintf("127.0.0.1:%d", node.port-1)
	}
	var setting json.RawMessage
	setting, err := json.Marshal(proxySetting)
	if err != nil {
		return nil, fmt.Errorf("marshal proxy %s config failed: %s", node.nodeType, err)
	}
	outboundDetourConfig.Settings = &setting
	return outboundDetourConfig.Build()
}
