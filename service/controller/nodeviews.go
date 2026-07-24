package controller

import (
	"encoding/json"
	"strings"

	"github.com/Mtoly/XrayRP/api"
)

type optionalInt32Range struct {
	set  bool
	from int32
	to   int32
}

func newOptionalInt32Range(value *[2]int32) optionalInt32Range {
	if value == nil {
		return optionalInt32Range{}
	}
	return optionalInt32Range{set: true, from: value[0], to: value[1]}
}

type inboundListenerView struct {
	nodeType  string
	port      uint32
	enableTLS bool
}

type inboundRealityView struct {
	set              bool
	dest             string
	proxyProtocolVer uint64
	serverNames      []string
	privateKey       string
	minClientVer     string
	maxClientVer     string
	maxTimeDiff      uint64
	shortIDs         []string
}

type inboundTransportView struct {
	protocol             string
	acceptProxyProtocol  bool
	authority            string
	host                 string
	path                 string
	serviceName          string
	header               json.RawMessage
	headers              map[string]string
	xhttpMode            string
	xhttpExtra           json.RawMessage
	xPaddingBytes        optionalInt32Range
	xPaddingObfsMode     bool
	xPaddingKey          string
	xPaddingHeader       string
	xPaddingPlacement    string
	xPaddingMethod       string
	uplinkHTTPMethod     string
	sessionPlacement     string
	sessionKey           string
	seqPlacement         string
	seqKey               string
	uplinkDataPlacement  string
	uplinkDataKey        string
	uplinkChunkSize      uint32
	noGRPCHeader         bool
	noSSEHeader          bool
	scMaxEachPostBytes   optionalInt32Range
	scMinPostsIntervalMS optionalInt32Range
	scMaxBufferedPosts   int64
	scStreamUpServerSecs optionalInt32Range
	xmuxMaxConcurrency   optionalInt32Range
	xmuxMaxConnections   optionalInt32Range
	xmuxCMaxReuseTimes   optionalInt32Range
	xmuxHMaxRequestTimes optionalInt32Range
	xmuxHMaxReusableSecs optionalInt32Range
	xmuxHKeepAlivePeriod int64
}

type inboundNodeView struct {
	listener      inboundListenerView
	enableVless   bool
	cypherMethod  string
	serverKey     string
	enableReality bool
	reality       inboundRealityView
	transport     inboundTransportView
}

type outboundNodeView struct {
	nodeType string
	port     uint32
}

type routingPolicyValue struct {
	set        bool
	candidates []string
	include    []string
	exclude    []string
	fallback   []string
}

type vlessUserNodeView struct {
	effectiveFlow string
}

type userNodeView struct {
	nodeType     string
	enableVless  bool
	cypherMethod string
	vless        vlessUserNodeView
}

type shadowsocksPluginNodeViews struct {
	regularInbound  inboundNodeView
	regularOutbound outboundNodeView
	bridgeInbound   inboundNodeView
	bridgeOutbound  outboundNodeView
	routing         routingPolicyValue
}

func (value nodeValue) inboundView() inboundNodeView {
	nodeInfo := value.snapshot()
	if nodeInfo == nil {
		return inboundNodeView{}
	}

	view := inboundNodeView{
		listener: inboundListenerView{
			nodeType:  nodeInfo.NodeType,
			port:      nodeInfo.Port,
			enableTLS: nodeInfo.EnableTLS,
		},
		enableVless:   nodeInfo.EnableVless,
		cypherMethod:  nodeInfo.CypherMethod,
		serverKey:     nodeInfo.ServerKey,
		enableReality: nodeInfo.EnableREALITY,
		transport: inboundTransportView{
			protocol:             nodeInfo.TransportProtocol,
			acceptProxyProtocol:  nodeInfo.AcceptProxyProtocol,
			authority:            nodeInfo.Authority,
			host:                 nodeInfo.Host,
			path:                 nodeInfo.Path,
			serviceName:          nodeInfo.ServiceName,
			header:               cloneRawMessage(nodeInfo.Header),
			headers:              cloneMap(nodeInfo.Headers),
			xhttpMode:            nodeInfo.XHTTPMode,
			xhttpExtra:           cloneRawMessage(nodeInfo.XHTTPExtra),
			xPaddingBytes:        newOptionalInt32Range(nodeInfo.XPaddingBytes),
			xPaddingObfsMode:     nodeInfo.XPaddingObfsMode,
			xPaddingKey:          nodeInfo.XPaddingKey,
			xPaddingHeader:       nodeInfo.XPaddingHeader,
			xPaddingPlacement:    nodeInfo.XPaddingPlacement,
			xPaddingMethod:       nodeInfo.XPaddingMethod,
			uplinkHTTPMethod:     nodeInfo.UplinkHTTPMethod,
			sessionPlacement:     nodeInfo.SessionPlacement,
			sessionKey:           nodeInfo.SessionKey,
			seqPlacement:         nodeInfo.SeqPlacement,
			seqKey:               nodeInfo.SeqKey,
			uplinkDataPlacement:  nodeInfo.UplinkDataPlacement,
			uplinkDataKey:        nodeInfo.UplinkDataKey,
			uplinkChunkSize:      nodeInfo.UplinkChunkSize,
			noGRPCHeader:         nodeInfo.NoGRPCHeader,
			noSSEHeader:          nodeInfo.NoSSEHeader,
			scMaxEachPostBytes:   newOptionalInt32Range(nodeInfo.ScMaxEachPostBytes),
			scMinPostsIntervalMS: newOptionalInt32Range(nodeInfo.ScMinPostsIntervalMs),
			scMaxBufferedPosts:   nodeInfo.ScMaxBufferedPosts,
			scStreamUpServerSecs: newOptionalInt32Range(nodeInfo.ScStreamUpServerSecs),
			xmuxMaxConcurrency:   newOptionalInt32Range(nodeInfo.XmuxMaxConcurrency),
			xmuxMaxConnections:   newOptionalInt32Range(nodeInfo.XmuxMaxConnections),
			xmuxCMaxReuseTimes:   newOptionalInt32Range(nodeInfo.XmuxCMaxReuseTimes),
			xmuxHMaxRequestTimes: newOptionalInt32Range(nodeInfo.XmuxHMaxRequestTimes),
			xmuxHMaxReusableSecs: newOptionalInt32Range(nodeInfo.XmuxHMaxReusableSecs),
			xmuxHKeepAlivePeriod: nodeInfo.XmuxHKeepAlivePeriod,
		},
	}
	if nodeInfo.REALITYConfig != nil {
		view.reality = inboundRealityView{
			set:              true,
			dest:             nodeInfo.REALITYConfig.Dest,
			proxyProtocolVer: nodeInfo.REALITYConfig.ProxyProtocolVer,
			serverNames:      cloneSlice(nodeInfo.REALITYConfig.ServerNames),
			privateKey:       nodeInfo.REALITYConfig.PrivateKey,
			minClientVer:     nodeInfo.REALITYConfig.MinClientVer,
			maxClientVer:     nodeInfo.REALITYConfig.MaxClientVer,
			maxTimeDiff:      nodeInfo.REALITYConfig.MaxTimeDiff,
			shortIDs:         cloneSlice(nodeInfo.REALITYConfig.ShortIds),
		}
	}
	return view
}

func (value nodeValue) outboundView() outboundNodeView {
	nodeInfo := value.snapshot()
	if nodeInfo == nil {
		return outboundNodeView{}
	}
	return outboundNodeView{
		nodeType: nodeInfo.NodeType,
		port:     nodeInfo.Port,
	}
}

func (value nodeValue) routingPolicy() routingPolicyValue {
	nodeInfo := value.snapshot()
	if nodeInfo == nil {
		return routingPolicyValue{}
	}
	return newRoutingPolicyValue(nodeInfo.RoutePolicy)
}

func (value nodeValue) userView() userNodeView {
	nodeInfo := value.snapshot()
	if nodeInfo == nil {
		return userNodeView{}
	}

	flow := strings.TrimSpace(nodeInfo.VlessFlow)
	if flow != "" {
		transport := strings.ToLower(strings.TrimSpace(nodeInfo.TransportProtocol))
		if transport != "tcp" || (!nodeInfo.EnableTLS && !nodeInfo.EnableREALITY) || nodeInfo.Header != nil {
			flow = ""
		}
	}
	return userNodeView{
		nodeType:     nodeInfo.NodeType,
		enableVless:  nodeInfo.EnableVless,
		cypherMethod: nodeInfo.CypherMethod,
		vless:        vlessUserNodeView{effectiveFlow: flow},
	}
}

func (value nodeValue) shadowsocksPluginViews() shadowsocksPluginNodeViews {
	views := shadowsocksPluginNodeViews{
		regularInbound:  value.inboundView(),
		regularOutbound: value.outboundView(),
		bridgeInbound:   value.inboundView(),
		bridgeOutbound:  value.outboundView(),
		routing:         value.routingPolicy(),
	}
	views.regularInbound.transport.protocol = "tcp"
	views.regularInbound.listener.enableTLS = false
	views.bridgeInbound.listener.port++
	views.bridgeInbound.listener.nodeType = "dokodemo-door"
	views.bridgeOutbound.port++
	views.bridgeOutbound.nodeType = "dokodemo-door"
	return views
}

func newRoutingPolicyValue(policy *api.PanelRoutePolicy) routingPolicyValue {
	if policy == nil {
		return routingPolicyValue{}
	}
	return routingPolicyValue{
		set:        true,
		candidates: cloneSlice(policy.Outbound.Candidates),
		include:    cloneSlice(policy.Outbound.Include),
		exclude:    cloneSlice(policy.Outbound.Exclude),
		fallback:   cloneSlice(policy.Outbound.Fallback),
	}
}

func (value routingPolicyValue) clone() routingPolicyValue {
	value.candidates = cloneSlice(value.candidates)
	value.include = cloneSlice(value.include)
	value.exclude = cloneSlice(value.exclude)
	value.fallback = cloneSlice(value.fallback)
	return value
}
