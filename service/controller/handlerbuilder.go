package controller

import (
	"errors"

	"github.com/xtls/xray-core/core"

	"github.com/Mtoly/XrayRP/api"
	"github.com/Mtoly/XrayRP/common/mylego"
)

var errNodeHandlerBuilderUnavailable = errors.New("node handler builder is not initialized")

// NodeHandlerBuilder owns normalized node and configuration inputs for
// constructing Xray inbound and outbound handlers. Its fields are deliberately
// opaque because the owned inputs may contain credentials or private keys.
type NodeHandlerBuilder struct {
	buildInbound          func(string) (*core.InboundHandlerConfig, error)
	buildInboundWithUsers func(string, []api.UserInfo) (*core.InboundHandlerConfig, error)
	buildOutbound         func(string) (*core.OutboundHandlerConfig, error)
}

// NewNodeHandlerBuilder prepares an owned handler-construction interface.
// Mutating config or nodeInfo after this call does not affect later builds.
func NewNodeHandlerBuilder(config *Config, nodeInfo *api.NodeInfo) (*NodeHandlerBuilder, error) {
	if config == nil {
		return nil, errors.New("node handler builder config is nil")
	}
	if nodeInfo == nil {
		return nil, errors.New("node handler builder node info is nil")
	}

	buildConfig := newHandlerBuildConfig(config)
	node := normalizeNodeInfo(nodeInfo)
	return &NodeHandlerBuilder{
		buildInbound: func(tag string) (*core.InboundHandlerConfig, error) {
			return buildInbound(buildConfig.snapshot(), node.inboundView(), tag)
		},
		buildInboundWithUsers: func(tag string, users []api.UserInfo) (*core.InboundHandlerConfig, error) {
			ownedUsers := cloneSlice(users)
			return buildInboundWithUsers(buildConfig.snapshot(), node.inboundView().listener, tag, &ownedUsers)
		},
		buildOutbound: func(tag string) (*core.OutboundHandlerConfig, error) {
			return buildOutbound(buildConfig.snapshot(), node.outboundView(), tag)
		},
	}, nil
}

// BuildInbound constructs an inbound handler from the owned inputs.
func (b *NodeHandlerBuilder) BuildInbound(tag string) (*core.InboundHandlerConfig, error) {
	if b == nil || b.buildInbound == nil {
		return nil, errNodeHandlerBuilderUnavailable
	}
	return b.buildInbound(tag)
}

// BuildInboundWithUsers constructs a Socks or HTTP inbound with embedded users.
func (b *NodeHandlerBuilder) BuildInboundWithUsers(tag string, users []api.UserInfo) (*core.InboundHandlerConfig, error) {
	if b == nil || b.buildInboundWithUsers == nil {
		return nil, errNodeHandlerBuilderUnavailable
	}
	return b.buildInboundWithUsers(tag, users)
}

// BuildOutbound constructs an outbound handler from the owned inputs.
func (b *NodeHandlerBuilder) BuildOutbound(tag string) (*core.OutboundHandlerConfig, error) {
	if b == nil || b.buildOutbound == nil {
		return nil, errNodeHandlerBuilderUnavailable
	}
	return b.buildOutbound(tag)
}

type handlerBuildConfig struct {
	listenIP                  string
	sendIP                    string
	certConfig                *mylego.CertConfig
	enableDNS                 bool
	dnsType                   string
	enableProxyProtocol       bool
	enableFallback            bool
	disableSniffing           bool
	fallBackConfigs           []*FallBackConfig
	disableLocalREALITYConfig bool
	enableREALITY             bool
	realityConfigs            *REALITYConfig
}

func newHandlerBuildConfig(config *Config) handlerBuildConfig {
	return handlerBuildConfig{
		listenIP:                  config.ListenIP,
		sendIP:                    config.SendIP,
		certConfig:                cloneRuntimeCertConfig(config.CertConfig),
		enableDNS:                 config.EnableDNS,
		dnsType:                   config.DNSType,
		enableProxyProtocol:       config.EnableProxyProtocol,
		enableFallback:            config.EnableFallback,
		disableSniffing:           config.DisableSniffing,
		fallBackConfigs:           cloneFallBackConfigs(config.FallBackConfigs),
		disableLocalREALITYConfig: config.DisableLocalREALITYConfig,
		enableREALITY:             config.EnableREALITY,
		realityConfigs:            cloneLocalREALITYConfig(config.REALITYConfigs),
	}
}

func (config handlerBuildConfig) snapshot() *Config {
	return &Config{
		ListenIP:                  config.listenIP,
		SendIP:                    config.sendIP,
		CertConfig:                cloneRuntimeCertConfig(config.certConfig),
		EnableDNS:                 config.enableDNS,
		DNSType:                   config.dnsType,
		EnableProxyProtocol:       config.enableProxyProtocol,
		EnableFallback:            config.enableFallback,
		DisableSniffing:           config.disableSniffing,
		FallBackConfigs:           cloneFallBackConfigs(config.fallBackConfigs),
		DisableLocalREALITYConfig: config.disableLocalREALITYConfig,
		EnableREALITY:             config.enableREALITY,
		REALITYConfigs:            cloneLocalREALITYConfig(config.realityConfigs),
	}
}

func cloneFallBackConfigs(configs []*FallBackConfig) []*FallBackConfig {
	if configs == nil {
		return nil
	}
	cloned := make([]*FallBackConfig, len(configs))
	for index, config := range configs {
		cloned[index] = cloneValue(config)
	}
	return cloned
}

func cloneLocalREALITYConfig(config *REALITYConfig) *REALITYConfig {
	if config == nil {
		return nil
	}
	cloned := *config
	cloned.ServerNames = cloneSlice(config.ServerNames)
	cloned.ShortIds = cloneSlice(config.ShortIds)
	return &cloned
}
