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
	return inboundViewFromSnapshot(value.normalizedSnapshot())
}

func inboundViewFromSnapshot(snapshot *api.NodeSnapshot) inboundNodeView {
	if snapshot == nil {
		return inboundNodeView{}
	}

	view := inboundNodeView{
		listener: inboundListenerView{
			nodeType:  snapshot.NodeType,
			port:      snapshot.Port,
			enableTLS: snapshot.EnableTLS,
		},
		enableVless:   snapshot.EnableVless,
		cypherMethod:  snapshot.CypherMethod,
		serverKey:     snapshot.ServerKey,
		enableReality: snapshot.EnableREALITY,
		transport: inboundTransportView{
			protocol:             snapshot.TransportProtocol,
			acceptProxyProtocol:  snapshot.AcceptProxyProtocol,
			authority:            snapshot.Authority,
			host:                 snapshot.Host,
			path:                 snapshot.Path,
			serviceName:          snapshot.ServiceName,
			header:               cloneRawMessage(snapshot.Header),
			headers:              cloneMap(snapshot.Headers),
			xhttpMode:            snapshot.XHTTPMode,
			xhttpExtra:           cloneRawMessage(snapshot.XHTTPExtra),
			xPaddingBytes:        newOptionalInt32Range(snapshot.XPaddingBytes),
			xPaddingObfsMode:     snapshot.XPaddingObfsMode,
			xPaddingKey:          snapshot.XPaddingKey,
			xPaddingHeader:       snapshot.XPaddingHeader,
			xPaddingPlacement:    snapshot.XPaddingPlacement,
			xPaddingMethod:       snapshot.XPaddingMethod,
			uplinkHTTPMethod:     snapshot.UplinkHTTPMethod,
			sessionPlacement:     snapshot.SessionPlacement,
			sessionKey:           snapshot.SessionKey,
			seqPlacement:         snapshot.SeqPlacement,
			seqKey:               snapshot.SeqKey,
			uplinkDataPlacement:  snapshot.UplinkDataPlacement,
			uplinkDataKey:        snapshot.UplinkDataKey,
			uplinkChunkSize:      snapshot.UplinkChunkSize,
			noGRPCHeader:         snapshot.NoGRPCHeader,
			noSSEHeader:          snapshot.NoSSEHeader,
			scMaxEachPostBytes:   newOptionalInt32Range(snapshot.ScMaxEachPostBytes),
			scMinPostsIntervalMS: newOptionalInt32Range(snapshot.ScMinPostsIntervalMs),
			scMaxBufferedPosts:   snapshot.ScMaxBufferedPosts,
			scStreamUpServerSecs: newOptionalInt32Range(snapshot.ScStreamUpServerSecs),
			xmuxMaxConcurrency:   newOptionalInt32Range(snapshot.XmuxMaxConcurrency),
			xmuxMaxConnections:   newOptionalInt32Range(snapshot.XmuxMaxConnections),
			xmuxCMaxReuseTimes:   newOptionalInt32Range(snapshot.XmuxCMaxReuseTimes),
			xmuxHMaxRequestTimes: newOptionalInt32Range(snapshot.XmuxHMaxRequestTimes),
			xmuxHMaxReusableSecs: newOptionalInt32Range(snapshot.XmuxHMaxReusableSecs),
			xmuxHKeepAlivePeriod: snapshot.XmuxHKeepAlivePeriod,
		},
	}
	if snapshot.REALITYConfig != nil {
		view.reality = inboundRealityView{
			set:              true,
			dest:             snapshot.REALITYConfig.Dest,
			proxyProtocolVer: snapshot.REALITYConfig.ProxyProtocolVer,
			serverNames:      cloneSlice(snapshot.REALITYConfig.ServerNames),
			privateKey:       snapshot.REALITYConfig.PrivateKey,
			minClientVer:     snapshot.REALITYConfig.MinClientVer,
			maxClientVer:     snapshot.REALITYConfig.MaxClientVer,
			maxTimeDiff:      snapshot.REALITYConfig.MaxTimeDiff,
			shortIDs:         cloneSlice(snapshot.REALITYConfig.ShortIds),
		}
	}
	return view
}

func (value nodeValue) outboundView() outboundNodeView {
	return outboundViewFromSnapshot(value.normalizedSnapshot())
}

func outboundViewFromSnapshot(snapshot *api.NodeSnapshot) outboundNodeView {
	if snapshot == nil {
		return outboundNodeView{}
	}
	return outboundNodeView{
		nodeType: snapshot.NodeType,
		port:     snapshot.Port,
	}
}

func (value nodeValue) routingPolicy() routingPolicyValue {
	return routingPolicyFromSnapshot(value.normalizedSnapshot())
}

func routingPolicyFromSnapshot(snapshot *api.NodeSnapshot) routingPolicyValue {
	if snapshot == nil {
		return routingPolicyValue{}
	}
	return newRoutingPolicyValue(snapshot.RoutePolicy)
}

func (value nodeValue) userView() userNodeView {
	return userViewFromSnapshot(value.normalizedSnapshot())
}

func userViewFromSnapshot(snapshot *api.NodeSnapshot) userNodeView {
	if snapshot == nil {
		return userNodeView{}
	}

	flow := strings.TrimSpace(snapshot.VlessFlow)
	if flow != "" {
		transport := strings.ToLower(strings.TrimSpace(snapshot.TransportProtocol))
		if transport != "tcp" || (!snapshot.EnableTLS && !snapshot.EnableREALITY) || snapshot.Header != nil {
			flow = ""
		}
	}
	return userNodeView{
		nodeType:     snapshot.NodeType,
		enableVless:  snapshot.EnableVless,
		cypherMethod: snapshot.CypherMethod,
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
