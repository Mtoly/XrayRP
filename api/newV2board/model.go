package newV2board

import (
	"encoding/json"
	"strings"

	"github.com/Mtoly/XrayRP/api"
)

type serverConfig struct {
	shadowsocks
	v2ray
	trojan

	ServerPort int    `json:"server_port"`
	Obfs       string `json:"obfs"`
	Version    int    `json:"version"`
	// Hy2 uses `obfs-password` in the UniProxy response.
	ObfsPassword          string           `json:"obfs-password"`
	UpMbps                int              `json:"up_mbps"`
	DownMbps              int              `json:"down_mbps"`
	IgnoreClientBandwidth bool             `json:"ignore_client_bandwidth"`
	PortHopEnabled        bool             `json:"port_hop_enable"`
	PortHopPorts          string           `json:"port_hop_ports"`
	CongestionControl     string           `json:"congestion_control"`
	ZeroRTTHandshake      bool             `json:"zero_rtt_handshake"`
	Heartbeat             string           `json:"heartbeat"`
	AuthTimeout           string           `json:"auth_timeout"`
	PaddingScheme         []string         `json:"padding_scheme"`
	CustomOutbounds       []customOutbound `json:"custom_outbounds"`
	CustomRoutes          []customRoute    `json:"custom_routes"`
	CertConfig            *certConfig      `json:"cert_config"`
	BaseConfig            struct {
		PushInterval int `json:"push_interval"`
		PullInterval int `json:"pull_interval"`
	} `json:"base_config"`
	Routes []route `json:"routes"`
}

type shadowsocks struct {
	Cipher       string `json:"cipher"`
	Plugin       string `json:"plugin"`
	PluginOpts   string `json:"plugin_opts"`
	ObfsSettings struct {
		Path string `json:"path"`
		Host string `json:"host"`
	} `json:"obfs_settings"`
	ServerKey string `json:"server_key"`
}

type v2ray struct {
	Network         string `json:"network"`
	NetworkSettings struct {
		Path                string           `json:"path"`
		Host                string           `json:"host"`
		Headers             *json.RawMessage `json:"headers"`
		ServiceName         string           `json:"serviceName"`
		Header              *json.RawMessage `json:"header"`
		Mode                string           `json:"mode"`
		Extra               json.RawMessage  `json:"extra"`
		XPaddingBytes       *[2]int32        `json:"xPaddingBytes"`
		XPaddingObfsMode    bool             `json:"xPaddingObfsMode"`
		XPaddingKey         string           `json:"xPaddingKey"`
		XPaddingHeader      string           `json:"xPaddingHeader"`
		XPaddingPlacement   string           `json:"xPaddingPlacement"`
		XPaddingMethod      string           `json:"xPaddingMethod"`
		UplinkHTTPMethod    string           `json:"uplinkHTTPMethod"`
		SessionPlacement    string           `json:"sessionPlacement"`
		SessionKey          string           `json:"sessionKey"`
		SeqPlacement        string           `json:"seqPlacement"`
		SeqKey              string           `json:"seqKey"`
		UplinkDataPlacement string           `json:"uplinkDataPlacement"`
		UplinkDataKey       string           `json:"uplinkDataKey"`
		UplinkChunkSize     uint32           `json:"uplinkChunkSize"`
		NoGRPCHeader        bool             `json:"noGRPCHeader"`
		NoSSEHeader         bool             `json:"noSSEHeader"`
	} `json:"networkSettings"`
	VlessNetworkSettings struct {
		Path        string           `json:"path"`
		Host        string           `json:"host"`
		Headers     *json.RawMessage `json:"headers"`
		ServiceName string           `json:"serviceName"`
		Header      *json.RawMessage `json:"header"`
	} `json:"network_settings"`
	VlessFlow        string `json:"flow"`
	VlessTlsSettings struct {
		ServerPort string `json:"server_port"`
		Dest       string `json:"dest"`
		XVer       uint64 `json:"xver"`
		Sni        string `json:"server_name"`
		PrivateKey string `json:"private_key"`
		ShortId    string `json:"short_id"`
	} `json:"tls_settings"`
	Tls int `json:"tls"`
}

type trojan struct {
	Host       string `json:"host"`
	ServerName string `json:"server_name"`
}

type route struct {
	Id          int      `json:"id"`
	Match       []string `json:"match"`
	Action      string   `json:"action"`
	ActionValue string   `json:"action_value"`
}

type customOutbound struct {
	Type            string   `json:"type"`
	Tag             string   `json:"tag"`
	Outbounds       []string `json:"outbounds"`
	IncludeOutbound []string `json:"include_outbound"`
	ExcludeOutbound []string `json:"exclude_outbound"`
	Fallback        []string `json:"fallback"`
}

type customRoute struct {
	Domain   []string `json:"domain"`
	Outbound string   `json:"outbound"`
}

type certConfig struct {
	Provider string            `json:"provider"`
	Email    string            `json:"email"`
	DNSEnv   map[string]string `json:"dns_env"`
}

type user struct {
	Id          int    `json:"id"`
	Uuid        string `json:"uuid"`
	SpeedLimit  int    `json:"speed_limit"`
	DeviceLimit int    `json:"device_limit"`
}

func (s *serverConfig) BuildRoutePolicy() (*api.PanelRoutePolicy, error) {
	policy := &api.PanelRoutePolicy{}

	for _, r := range s.Routes {
		switch strings.ToLower(r.Action) {
		case "direct", "bypass":
			policy.HasDirectBypass = true
		}
	}

	for _, r := range s.CustomRoutes {
		if strings.EqualFold(r.Outbound, "direct") {
			policy.HasDirectBypass = true
			policy.DirectDomains = append(policy.DirectDomains, r.Domain...)
		}
	}

	for _, outbound := range s.CustomOutbounds {
		policy.Outbound.Candidates = append(policy.Outbound.Candidates, outbound.Outbounds...)
		policy.Outbound.Include = append(policy.Outbound.Include, outbound.IncludeOutbound...)
		policy.Outbound.Exclude = append(policy.Outbound.Exclude, outbound.ExcludeOutbound...)
		policy.Outbound.Fallback = append(policy.Outbound.Fallback, outbound.Fallback...)
	}

	return policy, nil
}
