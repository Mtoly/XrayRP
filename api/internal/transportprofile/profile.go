// Package transportprofile applies panel-neutral transport configuration to
// the compatibility NodeInfo model.
package transportprofile

import (
	"encoding/json"

	"github.com/Mtoly/XrayRP/api"
)

// Endpoint contains the runtime endpoint values for one transport candidate.
type Endpoint struct {
	Host        string
	Path        string
	ServiceName string
	Header      json.RawMessage
	Headers     map[string]string
}

// Endpoints contains already parsed candidates. Adapters retain ownership of
// panel-specific fallback and field-precedence rules when populating it.
type Endpoints struct {
	WebSocket   Endpoint
	GRPC        Endpoint
	TCP         Endpoint
	SplitHTTP   Endpoint
	XHTTP       Endpoint
	HTTPUpgrade Endpoint
	Fallback    Endpoint
}

// Security contains security decisions already resolved by the panel adapter.
type Security struct {
	EnableTLS     bool
	EnableVless   bool
	EnableREALITY bool
	VlessFlow     string
	REALITYConfig *api.REALITYConfig
}

// XHTTP contains the runtime XHTTP values already decoded by the panel adapter.
type XHTTP struct {
	Mode                string
	Extra               json.RawMessage
	PaddingBytes        *[2]int32
	PaddingObfsMode     bool
	PaddingKey          string
	PaddingHeader       string
	PaddingPlacement    string
	PaddingMethod       string
	UplinkHTTPMethod    string
	SessionPlacement    string
	SessionKey          string
	SeqPlacement        string
	SeqKey              string
	UplinkDataPlacement string
	UplinkDataKey       string
	UplinkChunkSize     uint32
	NoGRPCHeader        bool
	NoSSEHeader         bool
}

// Input is the panel-neutral input to transport profile normalization.
type Input struct {
	Protocol  string
	Endpoints Endpoints
	Security  Security
	XHTTP     XHTTP
}

type profile struct {
	protocol string
	endpoint Endpoint
	security Security
	xhttp    XHTTP
}

func normalize(input Input) profile {
	return profile{
		protocol: input.Protocol,
		endpoint: selectEndpoint(input.Protocol, input.Endpoints),
		security: input.Security,
		xhttp:    input.XHTTP,
	}
}

func selectEndpoint(protocol string, endpoints Endpoints) Endpoint {
	switch protocol {
	case "ws":
		return endpoints.WebSocket
	case "grpc":
		return endpoints.GRPC
	case "tcp":
		return endpoints.TCP
	case "splithttp":
		return endpoints.SplitHTTP
	case "xhttp":
		return endpoints.XHTTP
	case "httpupgrade":
		return endpoints.HTTPUpgrade
	default:
		return endpoints.Fallback
	}
}

// Apply normalizes the input and projects it onto nodeInfo without changing
// panel identity, protocol authentication, listener port, or speed fields.
func Apply(nodeInfo *api.NodeInfo, input Input) {
	if nodeInfo == nil {
		return
	}
	p := normalize(input)
	nodeInfo.TransportProtocol = p.protocol
	nodeInfo.Host = p.endpoint.Host
	nodeInfo.Path = p.endpoint.Path
	nodeInfo.ServiceName = p.endpoint.ServiceName
	nodeInfo.Header = p.endpoint.Header
	nodeInfo.Headers = p.endpoint.Headers
	nodeInfo.EnableTLS = p.security.EnableTLS
	nodeInfo.EnableVless = p.security.EnableVless
	nodeInfo.EnableREALITY = p.security.EnableREALITY
	nodeInfo.VlessFlow = p.security.VlessFlow
	nodeInfo.REALITYConfig = p.security.REALITYConfig
	nodeInfo.XHTTPMode = p.xhttp.Mode
	nodeInfo.XHTTPExtra = p.xhttp.Extra
	nodeInfo.XPaddingBytes = p.xhttp.PaddingBytes
	nodeInfo.XPaddingObfsMode = p.xhttp.PaddingObfsMode
	nodeInfo.XPaddingKey = p.xhttp.PaddingKey
	nodeInfo.XPaddingHeader = p.xhttp.PaddingHeader
	nodeInfo.XPaddingPlacement = p.xhttp.PaddingPlacement
	nodeInfo.XPaddingMethod = p.xhttp.PaddingMethod
	nodeInfo.UplinkHTTPMethod = p.xhttp.UplinkHTTPMethod
	nodeInfo.SessionPlacement = p.xhttp.SessionPlacement
	nodeInfo.SessionKey = p.xhttp.SessionKey
	nodeInfo.SeqPlacement = p.xhttp.SeqPlacement
	nodeInfo.SeqKey = p.xhttp.SeqKey
	nodeInfo.UplinkDataPlacement = p.xhttp.UplinkDataPlacement
	nodeInfo.UplinkDataKey = p.xhttp.UplinkDataKey
	nodeInfo.UplinkChunkSize = p.xhttp.UplinkChunkSize
	nodeInfo.NoGRPCHeader = p.xhttp.NoGRPCHeader
	nodeInfo.NoSSEHeader = p.xhttp.NoSSEHeader
}
