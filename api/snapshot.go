package api

import (
	"encoding/json"
	stdnet "net"
	"reflect"

	xraynet "github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/infra/conf"
)

// NodeSnapshot is the normalized, owned panel snapshot used between panel
// adapters and runtime construction. It intentionally contains no backend
// configuration objects in its visible fields. Legacy Xray values are kept
// privately only so compatibility callers can receive an equivalent NodeInfo
// while preserving the address interface's observable value semantics.
type NodeSnapshot struct {
	AcceptProxyProtocol bool
	Authority           string
	NodeType            string
	NodeID              int
	Port                uint32
	SpeedLimit          uint64
	AlterID             uint16
	TransportProtocol   string
	FakeType            string
	Host                string
	SNI                 string
	Path                string
	EnableTLS           bool
	EnableSniffing      bool
	RouteOnly           bool
	EnableVless         bool
	VlessFlow           string
	CypherMethod        string
	ServerKey           string
	ServiceName         string
	Method              string
	Header              json.RawMessage
	HTTPHeaders         map[string][]string
	Headers             map[string]string
	NameServers         []*NameServerSnapshot
	EnableREALITY       bool
	REALITYConfig       *REALITYConfig
	Show                bool
	EnableTFO           bool
	Dest                string
	ProxyProtocolVer    uint64
	ServerNames         []string
	PrivateKey          string
	MinClientVer        string
	MaxClientVer        string
	MaxTimeDiff         uint64
	ShortIds            []string
	Xver                uint64
	Flow                string
	Security            string
	Key                 string
	RejectUnknownSni    bool
	Hysteria2Config     *Hysteria2Config
	AnyTLSConfig        *AnyTLSConfig
	TuicConfig          *TuicConfig
	RoutePolicy         *PanelRoutePolicy

	XHTTPMode             string
	XHTTPExtra            json.RawMessage
	XPaddingBytes         *[2]int32
	XPaddingObfsMode      bool
	XPaddingKey           string
	XPaddingHeader        string
	XPaddingPlacement     string
	XPaddingMethod        string
	UplinkHTTPMethod      string
	SessionPlacement      string
	SessionKey            string
	SeqPlacement          string
	SeqKey                string
	UplinkDataPlacement   string
	UplinkDataKey         string
	UplinkChunkSize       uint32
	NoGRPCHeader          bool
	NoSSEHeader           bool
	ScMaxEachPostBytes    *[2]int32
	ScMinPostsIntervalMs  *[2]int32
	ScMaxBufferedPosts    int64
	ScStreamUpServerSecs  *[2]int32
	XmuxMaxConcurrency    *[2]int32
	XmuxMaxConnections    *[2]int32
	XmuxCMaxReuseTimes    *[2]int32
	XmuxHMaxRequestTimes  *[2]int32
	XmuxHMaxReusableSecs  *[2]int32
	XmuxHKeepAlivePeriod  int64
	XHTTPDownloadSettings json.RawMessage

	legacyHTTPHeaders        map[string]*conf.StringList
	legacyHTTPHeadersNeutral map[string][]string
	legacyNameServers        []*conf.NameServerConfig
	legacyNameServersNeutral []*NameServerSnapshot
	preserveNameServers      bool
}

// NormalizeNodeInfo converts the compatibility NodeInfo contract into an
// independently owned normalized snapshot. A nil input remains nil.
func NormalizeNodeInfo(nodeInfo *NodeInfo) *NodeSnapshot {
	if nodeInfo == nil {
		return nil
	}

	snapshot := &NodeSnapshot{
		AcceptProxyProtocol:   nodeInfo.AcceptProxyProtocol,
		Authority:             nodeInfo.Authority,
		NodeType:              nodeInfo.NodeType,
		NodeID:                nodeInfo.NodeID,
		Port:                  nodeInfo.Port,
		SpeedLimit:            nodeInfo.SpeedLimit,
		AlterID:               nodeInfo.AlterID,
		TransportProtocol:     nodeInfo.TransportProtocol,
		FakeType:              nodeInfo.FakeType,
		Host:                  nodeInfo.Host,
		SNI:                   nodeInfo.SNI,
		Path:                  nodeInfo.Path,
		EnableTLS:             nodeInfo.EnableTLS,
		EnableSniffing:        nodeInfo.EnableSniffing,
		RouteOnly:             nodeInfo.RouteOnly,
		EnableVless:           nodeInfo.EnableVless,
		VlessFlow:             nodeInfo.VlessFlow,
		CypherMethod:          nodeInfo.CypherMethod,
		ServerKey:             nodeInfo.ServerKey,
		ServiceName:           nodeInfo.ServiceName,
		Method:                nodeInfo.Method,
		Header:                cloneRawMessage(nodeInfo.Header),
		HTTPHeaders:           legacyHTTPHeadersToNeutral(nodeInfo.HttpHeaders),
		Headers:               cloneStringMap(nodeInfo.Headers),
		NameServers:           cloneNameServerSnapshots(nodeInfo.NameServers),
		EnableREALITY:         nodeInfo.EnableREALITY,
		REALITYConfig:         cloneREALITYConfig(nodeInfo.REALITYConfig),
		Show:                  nodeInfo.Show,
		EnableTFO:             nodeInfo.EnableTFO,
		Dest:                  nodeInfo.Dest,
		ProxyProtocolVer:      nodeInfo.ProxyProtocolVer,
		ServerNames:           cloneStrings(nodeInfo.ServerNames),
		PrivateKey:            nodeInfo.PrivateKey,
		MinClientVer:          nodeInfo.MinClientVer,
		MaxClientVer:          nodeInfo.MaxClientVer,
		MaxTimeDiff:           nodeInfo.MaxTimeDiff,
		ShortIds:              cloneStrings(nodeInfo.ShortIds),
		Xver:                  nodeInfo.Xver,
		Flow:                  nodeInfo.Flow,
		Security:              nodeInfo.Security,
		Key:                   nodeInfo.Key,
		RejectUnknownSni:      nodeInfo.RejectUnknownSni,
		Hysteria2Config:       cloneHysteria2Config(nodeInfo.Hysteria2Config),
		AnyTLSConfig:          cloneAnyTLSConfig(nodeInfo.AnyTLSConfig),
		TuicConfig:            cloneTuicConfig(nodeInfo.TuicConfig),
		RoutePolicy:           cloneRoutePolicy(nodeInfo.RoutePolicy),
		XHTTPMode:             nodeInfo.XHTTPMode,
		XHTTPExtra:            cloneRawMessage(nodeInfo.XHTTPExtra),
		XPaddingBytes:         cloneInt32Range(nodeInfo.XPaddingBytes),
		XPaddingObfsMode:      nodeInfo.XPaddingObfsMode,
		XPaddingKey:           nodeInfo.XPaddingKey,
		XPaddingHeader:        nodeInfo.XPaddingHeader,
		XPaddingPlacement:     nodeInfo.XPaddingPlacement,
		XPaddingMethod:        nodeInfo.XPaddingMethod,
		UplinkHTTPMethod:      nodeInfo.UplinkHTTPMethod,
		SessionPlacement:      nodeInfo.SessionPlacement,
		SessionKey:            nodeInfo.SessionKey,
		SeqPlacement:          nodeInfo.SeqPlacement,
		SeqKey:                nodeInfo.SeqKey,
		UplinkDataPlacement:   nodeInfo.UplinkDataPlacement,
		UplinkDataKey:         nodeInfo.UplinkDataKey,
		UplinkChunkSize:       nodeInfo.UplinkChunkSize,
		NoGRPCHeader:          nodeInfo.NoGRPCHeader,
		NoSSEHeader:           nodeInfo.NoSSEHeader,
		ScMaxEachPostBytes:    cloneInt32Range(nodeInfo.ScMaxEachPostBytes),
		ScMinPostsIntervalMs:  cloneInt32Range(nodeInfo.ScMinPostsIntervalMs),
		ScMaxBufferedPosts:    nodeInfo.ScMaxBufferedPosts,
		ScStreamUpServerSecs:  cloneInt32Range(nodeInfo.ScStreamUpServerSecs),
		XmuxMaxConcurrency:    cloneInt32Range(nodeInfo.XmuxMaxConcurrency),
		XmuxMaxConnections:    cloneInt32Range(nodeInfo.XmuxMaxConnections),
		XmuxCMaxReuseTimes:    cloneInt32Range(nodeInfo.XmuxCMaxReuseTimes),
		XmuxHMaxRequestTimes:  cloneInt32Range(nodeInfo.XmuxHMaxRequestTimes),
		XmuxHMaxReusableSecs:  cloneInt32Range(nodeInfo.XmuxHMaxReusableSecs),
		XmuxHKeepAlivePeriod:  nodeInfo.XmuxHKeepAlivePeriod,
		XHTTPDownloadSettings: cloneRawMessage(nodeInfo.XHTTPDownloadSettings),
		legacyHTTPHeaders:     cloneLegacyHTTPHeaders(nodeInfo.HttpHeaders),
		legacyNameServers:     cloneNameServerConfigs(nodeInfo.NameServerConfig),
		preserveNameServers:   nodeInfo.NameServers != nil,
	}
	if nodeInfo.HttpHeaders != nil {
		snapshot.legacyHTTPHeadersNeutral = cloneStringMapOfSlices(snapshot.HTTPHeaders)
	}
	if snapshot.NameServers == nil && nodeInfo.NameServerConfig != nil {
		snapshot.NameServers = legacyNameServersToNeutral(nodeInfo.NameServerConfig)
	}
	if nodeInfo.NameServers == nil && nodeInfo.NameServerConfig != nil {
		snapshot.legacyNameServersNeutral = cloneNameServerSnapshots(snapshot.NameServers)
	}
	return snapshot
}

// Clone returns an independently owned normalized snapshot.
func (snapshot *NodeSnapshot) Clone() *NodeSnapshot {
	if snapshot == nil {
		return nil
	}
	cloned := *snapshot
	cloned.Header = cloneRawMessage(snapshot.Header)
	cloned.HTTPHeaders = cloneStringMapOfSlices(snapshot.HTTPHeaders)
	cloned.Headers = cloneStringMap(snapshot.Headers)
	cloned.NameServers = cloneNameServerSnapshots(snapshot.NameServers)
	cloned.REALITYConfig = cloneREALITYConfig(snapshot.REALITYConfig)
	cloned.ServerNames = cloneStrings(snapshot.ServerNames)
	cloned.ShortIds = cloneStrings(snapshot.ShortIds)
	cloned.Hysteria2Config = cloneHysteria2Config(snapshot.Hysteria2Config)
	cloned.AnyTLSConfig = cloneAnyTLSConfig(snapshot.AnyTLSConfig)
	cloned.TuicConfig = cloneTuicConfig(snapshot.TuicConfig)
	cloned.RoutePolicy = cloneRoutePolicy(snapshot.RoutePolicy)
	cloned.XHTTPExtra = cloneRawMessage(snapshot.XHTTPExtra)
	cloned.XPaddingBytes = cloneInt32Range(snapshot.XPaddingBytes)
	cloned.ScMaxEachPostBytes = cloneInt32Range(snapshot.ScMaxEachPostBytes)
	cloned.ScMinPostsIntervalMs = cloneInt32Range(snapshot.ScMinPostsIntervalMs)
	cloned.ScStreamUpServerSecs = cloneInt32Range(snapshot.ScStreamUpServerSecs)
	cloned.XmuxMaxConcurrency = cloneInt32Range(snapshot.XmuxMaxConcurrency)
	cloned.XmuxMaxConnections = cloneInt32Range(snapshot.XmuxMaxConnections)
	cloned.XmuxCMaxReuseTimes = cloneInt32Range(snapshot.XmuxCMaxReuseTimes)
	cloned.XmuxHMaxRequestTimes = cloneInt32Range(snapshot.XmuxHMaxRequestTimes)
	cloned.XmuxHMaxReusableSecs = cloneInt32Range(snapshot.XmuxHMaxReusableSecs)
	cloned.XHTTPDownloadSettings = cloneRawMessage(snapshot.XHTTPDownloadSettings)
	cloned.legacyHTTPHeaders = cloneLegacyHTTPHeaders(snapshot.legacyHTTPHeaders)
	cloned.legacyHTTPHeadersNeutral = cloneStringMapOfSlices(snapshot.legacyHTTPHeadersNeutral)
	cloned.legacyNameServers = cloneNameServerConfigs(snapshot.legacyNameServers)
	cloned.legacyNameServersNeutral = cloneNameServerSnapshots(snapshot.legacyNameServersNeutral)
	return &cloned
}

// Equal compares the normalized runtime state of two snapshots. Private
// compatibility materialization state is intentionally excluded so a legacy
// representation change does not trigger an equivalent runtime rebuild.
func (snapshot *NodeSnapshot) Equal(other *NodeSnapshot) bool {
	if snapshot == nil || other == nil {
		return snapshot == other
	}
	left := *snapshot
	right := *other
	left.legacyHTTPHeaders = nil
	left.legacyHTTPHeadersNeutral = nil
	left.legacyNameServers = nil
	left.legacyNameServersNeutral = nil
	left.preserveNameServers = false
	right.legacyHTTPHeaders = nil
	right.legacyHTTPHeadersNeutral = nil
	right.legacyNameServers = nil
	right.legacyNameServersNeutral = nil
	right.preserveNameServers = false
	return reflect.DeepEqual(left, right)
}

// ToNodeInfo materializes the compatibility contract. Backend-specific Xray
// values are created here, or restored from the private compatibility copy.
func (snapshot *NodeSnapshot) ToNodeInfo() *NodeInfo {
	if snapshot == nil {
		return nil
	}

	info := &NodeInfo{
		AcceptProxyProtocol:   snapshot.AcceptProxyProtocol,
		Authority:             snapshot.Authority,
		NodeType:              snapshot.NodeType,
		NodeID:                snapshot.NodeID,
		Port:                  snapshot.Port,
		SpeedLimit:            snapshot.SpeedLimit,
		AlterID:               snapshot.AlterID,
		TransportProtocol:     snapshot.TransportProtocol,
		FakeType:              snapshot.FakeType,
		Host:                  snapshot.Host,
		SNI:                   snapshot.SNI,
		Path:                  snapshot.Path,
		EnableTLS:             snapshot.EnableTLS,
		EnableSniffing:        snapshot.EnableSniffing,
		RouteOnly:             snapshot.RouteOnly,
		EnableVless:           snapshot.EnableVless,
		VlessFlow:             snapshot.VlessFlow,
		CypherMethod:          snapshot.CypherMethod,
		ServerKey:             snapshot.ServerKey,
		ServiceName:           snapshot.ServiceName,
		Method:                snapshot.Method,
		Header:                cloneRawMessage(snapshot.Header),
		Headers:               cloneStringMap(snapshot.Headers),
		EnableREALITY:         snapshot.EnableREALITY,
		REALITYConfig:         cloneREALITYConfig(snapshot.REALITYConfig),
		Show:                  snapshot.Show,
		EnableTFO:             snapshot.EnableTFO,
		Dest:                  snapshot.Dest,
		ProxyProtocolVer:      snapshot.ProxyProtocolVer,
		ServerNames:           cloneStrings(snapshot.ServerNames),
		PrivateKey:            snapshot.PrivateKey,
		MinClientVer:          snapshot.MinClientVer,
		MaxClientVer:          snapshot.MaxClientVer,
		MaxTimeDiff:           snapshot.MaxTimeDiff,
		ShortIds:              cloneStrings(snapshot.ShortIds),
		Xver:                  snapshot.Xver,
		Flow:                  snapshot.Flow,
		Security:              snapshot.Security,
		Key:                   snapshot.Key,
		RejectUnknownSni:      snapshot.RejectUnknownSni,
		Hysteria2Config:       cloneHysteria2Config(snapshot.Hysteria2Config),
		AnyTLSConfig:          cloneAnyTLSConfig(snapshot.AnyTLSConfig),
		TuicConfig:            cloneTuicConfig(snapshot.TuicConfig),
		RoutePolicy:           cloneRoutePolicy(snapshot.RoutePolicy),
		XHTTPMode:             snapshot.XHTTPMode,
		XHTTPExtra:            cloneRawMessage(snapshot.XHTTPExtra),
		XPaddingBytes:         cloneInt32Range(snapshot.XPaddingBytes),
		XPaddingObfsMode:      snapshot.XPaddingObfsMode,
		XPaddingKey:           snapshot.XPaddingKey,
		XPaddingHeader:        snapshot.XPaddingHeader,
		XPaddingPlacement:     snapshot.XPaddingPlacement,
		XPaddingMethod:        snapshot.XPaddingMethod,
		UplinkHTTPMethod:      snapshot.UplinkHTTPMethod,
		SessionPlacement:      snapshot.SessionPlacement,
		SessionKey:            snapshot.SessionKey,
		SeqPlacement:          snapshot.SeqPlacement,
		SeqKey:                snapshot.SeqKey,
		UplinkDataPlacement:   snapshot.UplinkDataPlacement,
		UplinkDataKey:         snapshot.UplinkDataKey,
		UplinkChunkSize:       snapshot.UplinkChunkSize,
		NoGRPCHeader:          snapshot.NoGRPCHeader,
		NoSSEHeader:           snapshot.NoSSEHeader,
		ScMaxEachPostBytes:    cloneInt32Range(snapshot.ScMaxEachPostBytes),
		ScMinPostsIntervalMs:  cloneInt32Range(snapshot.ScMinPostsIntervalMs),
		ScMaxBufferedPosts:    snapshot.ScMaxBufferedPosts,
		ScStreamUpServerSecs:  cloneInt32Range(snapshot.ScStreamUpServerSecs),
		XmuxMaxConcurrency:    cloneInt32Range(snapshot.XmuxMaxConcurrency),
		XmuxMaxConnections:    cloneInt32Range(snapshot.XmuxMaxConnections),
		XmuxCMaxReuseTimes:    cloneInt32Range(snapshot.XmuxCMaxReuseTimes),
		XmuxHMaxRequestTimes:  cloneInt32Range(snapshot.XmuxHMaxRequestTimes),
		XmuxHMaxReusableSecs:  cloneInt32Range(snapshot.XmuxHMaxReusableSecs),
		XmuxHKeepAlivePeriod:  snapshot.XmuxHKeepAlivePeriod,
		XHTTPDownloadSettings: cloneRawMessage(snapshot.XHTTPDownloadSettings),
	}
	legacyHTTPHeadersUnchanged := snapshot.legacyHTTPHeaders != nil && reflect.DeepEqual(snapshot.HTTPHeaders, snapshot.legacyHTTPHeadersNeutral)
	if snapshot.legacyHTTPHeaders == nil || !legacyHTTPHeadersUnchanged {
		info.HttpHeaders = neutralHTTPHeadersToLegacy(snapshot.HTTPHeaders)
	} else {
		info.HttpHeaders = cloneLegacyHTTPHeaders(snapshot.legacyHTTPHeaders)
	}

	legacyNameServersUnchanged := snapshot.legacyNameServers != nil && reflect.DeepEqual(snapshot.NameServers, snapshot.legacyNameServersNeutral)
	if snapshot.legacyNameServers == nil || snapshot.preserveNameServers || !legacyNameServersUnchanged {
		info.NameServers = cloneNameServerSnapshots(snapshot.NameServers)
	}
	if snapshot.legacyNameServers != nil && legacyNameServersUnchanged {
		info.NameServerConfig = cloneNameServerConfigs(snapshot.legacyNameServers)
	} else {
		info.NameServerConfig = neutralNameServersToLegacy(snapshot.NameServers)
	}
	return info
}

func cloneRawMessage(value json.RawMessage) json.RawMessage {
	if value == nil {
		return nil
	}
	return append(json.RawMessage{}, value...)
}

func cloneStrings(value []string) []string {
	if value == nil {
		return nil
	}
	return append([]string{}, value...)
}

func cloneStringMap(value map[string]string) map[string]string {
	if value == nil {
		return nil
	}
	cloned := make(map[string]string, len(value))
	for key, item := range value {
		cloned[key] = item
	}
	return cloned
}

func cloneStringMapOfSlices(value map[string][]string) map[string][]string {
	if value == nil {
		return nil
	}
	cloned := make(map[string][]string, len(value))
	for key, item := range value {
		cloned[key] = cloneStrings(item)
	}
	return cloned
}

func cloneInt32Range(value *[2]int32) *[2]int32 {
	if value == nil {
		return nil
	}
	cloned := *value
	return &cloned
}

func cloneBool(value *bool) *bool {
	if value == nil {
		return nil
	}
	cloned := *value
	return &cloned
}

func cloneUint32(value *uint32) *uint32 {
	if value == nil {
		return nil
	}
	cloned := *value
	return &cloned
}

func cloneNameServerSnapshots(value []*NameServerSnapshot) []*NameServerSnapshot {
	if value == nil {
		return nil
	}
	cloned := make([]*NameServerSnapshot, len(value))
	for index, item := range value {
		if item == nil {
			continue
		}
		copy := *item
		copy.Domains = cloneStrings(item.Domains)
		copy.ExpectedIPs = cloneStrings(item.ExpectedIPs)
		copy.ExpectIPs = cloneStrings(item.ExpectIPs)
		copy.UnexpectedIPs = cloneStrings(item.UnexpectedIPs)
		copy.DisableCache = cloneBool(item.DisableCache)
		copy.ServeStale = cloneBool(item.ServeStale)
		copy.ServeExpiredTTL = cloneUint32(item.ServeExpiredTTL)
		cloned[index] = &copy
	}
	return cloned
}

func cloneREALITYConfig(value *REALITYConfig) *REALITYConfig {
	if value == nil {
		return nil
	}
	cloned := *value
	cloned.ServerNames = cloneStrings(value.ServerNames)
	cloned.ShortIds = cloneStrings(value.ShortIds)
	return &cloned
}

func cloneHysteria2Config(value *Hysteria2Config) *Hysteria2Config {
	if value == nil {
		return nil
	}
	cloned := *value
	return &cloned
}

func cloneAnyTLSConfig(value *AnyTLSConfig) *AnyTLSConfig {
	if value == nil {
		return nil
	}
	cloned := *value
	cloned.PaddingScheme = cloneStrings(value.PaddingScheme)
	return &cloned
}

func cloneTuicConfig(value *TuicConfig) *TuicConfig {
	if value == nil {
		return nil
	}
	cloned := *value
	cloned.ALPN = cloneStrings(value.ALPN)
	return &cloned
}

func cloneRoutePolicy(value *PanelRoutePolicy) *PanelRoutePolicy {
	if value == nil {
		return nil
	}
	cloned := *value
	cloned.DirectDomains = cloneStrings(value.DirectDomains)
	cloned.Outbound.Candidates = cloneStrings(value.Outbound.Candidates)
	cloned.Outbound.Include = cloneStrings(value.Outbound.Include)
	cloned.Outbound.Exclude = cloneStrings(value.Outbound.Exclude)
	cloned.Outbound.Fallback = cloneStrings(value.Outbound.Fallback)
	return &cloned
}

func legacyHTTPHeadersToNeutral(value map[string]*conf.StringList) map[string][]string {
	if value == nil {
		return nil
	}
	cloned := make(map[string][]string, len(value))
	for key, item := range value {
		if item == nil {
			cloned[key] = nil
			continue
		}
		cloned[key] = cloneStrings([]string(*item))
	}
	return cloned
}

func neutralHTTPHeadersToLegacy(value map[string][]string) map[string]*conf.StringList {
	if value == nil {
		return nil
	}
	cloned := make(map[string]*conf.StringList, len(value))
	for key, item := range value {
		if item == nil {
			cloned[key] = nil
			continue
		}
		list := conf.StringList(cloneStrings(item))
		cloned[key] = &list
	}
	return cloned
}

func cloneLegacyHTTPHeaders(value map[string]*conf.StringList) map[string]*conf.StringList {
	if value == nil {
		return nil
	}
	cloned := make(map[string]*conf.StringList, len(value))
	for key, item := range value {
		if item == nil {
			cloned[key] = nil
			continue
		}
		list := conf.StringList(cloneStrings([]string(*item)))
		cloned[key] = &list
	}
	return cloned
}

func cloneNameServerConfigs(value []*conf.NameServerConfig) []*conf.NameServerConfig {
	if value == nil {
		return nil
	}
	cloned := make([]*conf.NameServerConfig, len(value))
	for index, item := range value {
		if item == nil {
			continue
		}
		copy := *item
		copy.Address = cloneAddress(item.Address)
		copy.ClientIP = cloneAddress(item.ClientIP)
		copy.Domains = cloneStrings(item.Domains)
		copy.ExpectedIPs = conf.StringList(cloneStrings([]string(item.ExpectedIPs)))
		copy.ExpectIPs = conf.StringList(cloneStrings([]string(item.ExpectIPs)))
		copy.UnexpectedIPs = conf.StringList(cloneStrings([]string(item.UnexpectedIPs)))
		copy.DisableCache = cloneBool(item.DisableCache)
		copy.ServeStale = cloneBool(item.ServeStale)
		copy.ServeExpiredTTL = cloneUint32(item.ServeExpiredTTL)
		cloned[index] = &copy
	}
	return cloned
}

func cloneAddress(value *conf.Address) *conf.Address {
	if value == nil {
		return nil
	}
	cloned := *value
	cloned.Address = cloneXrayAddress(value.Address)
	return &cloned
}

func cloneXrayAddress(value xraynet.Address) xraynet.Address {
	if isNilXrayAddress(value) {
		return value
	}
	switch address := value.(type) {
	case opaqueAddress:
		return address.clone()
	case *opaqueAddress:
		if address == nil {
			return address
		}
		return address.clone()
	}
	switch reflect.TypeOf(value) {
	case reflect.TypeOf(xraynet.IPAddress([]byte{0, 0, 0, 0})):
		return xraynet.IPAddress(cloneStringsAsBytes(value.IP()))
	case reflect.TypeOf(xraynet.IPAddress(make([]byte, 16))):
		return xraynet.IPAddress(cloneStringsAsBytes(value.IP()))
	case reflect.TypeOf(xraynet.DomainAddress("")):
		return xraynet.DomainAddress(value.Domain())
	default:
		return newOpaqueAddress(value)
	}
}

// opaqueAddress is the immutable compatibility representation for an
// xraynet.Address implementation that does not expose a clone contract.
// xraynet.Address only promises value accessors, so preserving those values
// retains runtime behavior without retaining a mutable implementation pointer.
type opaqueAddress struct {
	typeName string
	ip       []byte
	domain   string
	family   xraynet.AddressFamily
	text     string
}

func newOpaqueAddress(value xraynet.Address) opaqueAddress {
	family := value.Family()
	address := opaqueAddress{
		typeName: reflect.TypeOf(value).String(),
		family:   family,
		text:     value.String(),
	}
	if family == xraynet.AddressFamilyIPv4 || family == xraynet.AddressFamilyIPv6 {
		address.ip = cloneStringsAsBytes(value.IP())
	} else {
		address.domain = value.Domain()
	}
	return address
}

func (address opaqueAddress) clone() opaqueAddress {
	address.ip = cloneStringsAsBytes(address.ip)
	return address
}

func (address opaqueAddress) IP() stdnet.IP {
	return stdnet.IP(cloneStringsAsBytes(address.ip))
}

func (address opaqueAddress) Domain() string {
	return address.domain
}

func (address opaqueAddress) Family() xraynet.AddressFamily {
	return address.family
}

func (address opaqueAddress) String() string {
	return address.text
}

func cloneStringsAsBytes(value []byte) []byte {
	if value == nil {
		return nil
	}
	return append([]byte{}, value...)
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

func legacyNameServersToNeutral(value []*conf.NameServerConfig) []*NameServerSnapshot {
	if value == nil {
		return nil
	}
	cloned := make([]*NameServerSnapshot, len(value))
	for index, item := range value {
		if item == nil {
			continue
		}
		entry := &NameServerSnapshot{
			Port:            item.Port,
			SkipFallback:    item.SkipFallback,
			Domains:         cloneStrings(item.Domains),
			ExpectedIPs:     cloneStrings([]string(item.ExpectedIPs)),
			ExpectIPs:       cloneStrings([]string(item.ExpectIPs)),
			QueryStrategy:   item.QueryStrategy,
			Tag:             item.Tag,
			TimeoutMs:       item.TimeoutMs,
			DisableCache:    cloneBool(item.DisableCache),
			ServeStale:      cloneBool(item.ServeStale),
			ServeExpiredTTL: cloneUint32(item.ServeExpiredTTL),
			FinalQuery:      item.FinalQuery,
			UnexpectedIPs:   cloneStrings([]string(item.UnexpectedIPs)),
		}
		if item.Address != nil && !isNilXrayAddress(item.Address.Address) {
			entry.Address = item.Address.String()
		}
		if item.ClientIP != nil && !isNilXrayAddress(item.ClientIP.Address) {
			entry.ClientIP = item.ClientIP.String()
		}
		cloned[index] = entry
	}
	return cloned
}

func neutralNameServersToLegacy(value []*NameServerSnapshot) []*conf.NameServerConfig {
	if value == nil {
		return nil
	}
	cloned := make([]*conf.NameServerConfig, len(value))
	for index, item := range value {
		if item == nil {
			continue
		}
		entry := &conf.NameServerConfig{
			Port:            item.Port,
			SkipFallback:    item.SkipFallback,
			Domains:         cloneStrings(item.Domains),
			ExpectedIPs:     conf.StringList(cloneStrings(item.ExpectedIPs)),
			ExpectIPs:       conf.StringList(cloneStrings(item.ExpectIPs)),
			QueryStrategy:   item.QueryStrategy,
			Tag:             item.Tag,
			TimeoutMs:       item.TimeoutMs,
			DisableCache:    cloneBool(item.DisableCache),
			ServeStale:      cloneBool(item.ServeStale),
			ServeExpiredTTL: cloneUint32(item.ServeExpiredTTL),
			FinalQuery:      item.FinalQuery,
			UnexpectedIPs:   conf.StringList(cloneStrings(item.UnexpectedIPs)),
		}
		if item.Address != "" {
			entry.Address = &conf.Address{Address: xraynet.ParseAddress(item.Address)}
		}
		if item.ClientIP != "" {
			entry.ClientIP = &conf.Address{Address: xraynet.ParseAddress(item.ClientIP)}
		}
		cloned[index] = entry
	}
	return cloned
}
