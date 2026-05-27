package v2raysocks

import (
	"encoding/json"
	"testing"

	"github.com/bitly/go-simplejson"

	"github.com/Mtoly/XrayRP/api"
)

func TestEnrichTransportProfileWithSecurityTLS(t *testing.T) {
	inboundInfo, err := simplejson.NewJson([]byte(`{
		"protocol": "vmess",
		"streamSettings": {
			"security": "tls"
		}
	}`))
	if err != nil {
		t.Fatalf("parse inbound fixture: %v", err)
	}
	profile := transportProfile{TransportProtocol: "ws"}

	enrichTransportProfileWithSecurity(&profile, inboundInfo, "fallback-flow")
	enrichTransportProfileWithSecurity(nil, inboundInfo, "fallback-flow")
	enrichTransportProfileWithSecurity(&profile, nil, "fallback-flow")

	if !profile.EnableTLS {
		t.Fatal("expected TLS to be enabled")
	}
	if profile.EnableVless || profile.EnableREALITY {
		t.Fatalf("unexpected VLESS/REALITY flags: %#v", profile)
	}
	if profile.VlessFlow != "fallback-flow" {
		t.Fatalf("expected fallback VLESS flow, got %q", profile.VlessFlow)
	}
	if profile.REALITYConfig == nil {
		t.Fatal("expected empty REALITY config to preserve previous behavior")
	}
}

func TestEnrichTransportProfileWithSecurityRealityTCPUsesVision(t *testing.T) {
	inboundInfo, err := simplejson.NewJson([]byte(`{
		"protocol": "vless",
		"streamSettings": {
			"security": "reality",
			"realitySettings": {
				"dest": "example.com:443",
				"xver": 1,
				"serverNames": ["example.com"],
				"privateKey": "private-key",
				"minClientVer": "1.0.0",
				"maxClientVer": "2.0.0",
				"maxTimeDiff": 60,
				"shortIds": ["abcd"]
			}
		}
	}`))
	if err != nil {
		t.Fatalf("parse inbound fixture: %v", err)
	}
	profile := transportProfile{TransportProtocol: "tcp"}

	enrichTransportProfileWithSecurity(&profile, inboundInfo, "fallback-flow")

	if profile.EnableTLS || !profile.EnableVless || !profile.EnableREALITY {
		t.Fatalf("unexpected security flags: %#v", profile)
	}
	if profile.VlessFlow != "xtls-rprx-vision" {
		t.Fatalf("expected REALITY TCP to use vision flow, got %q", profile.VlessFlow)
	}
	if profile.REALITYConfig == nil {
		t.Fatal("expected REALITY config to be populated")
	}
	if profile.REALITYConfig.Dest != "example.com:443" || profile.REALITYConfig.ProxyProtocolVer != 1 {
		t.Fatalf("unexpected REALITY config: %#v", profile.REALITYConfig)
	}
	if len(profile.REALITYConfig.ServerNames) != 1 || profile.REALITYConfig.ServerNames[0] != "example.com" {
		t.Fatalf("unexpected REALITY server names: %#v", profile.REALITYConfig.ServerNames)
	}
	if profile.REALITYConfig.PrivateKey != "private-key" || profile.REALITYConfig.MaxTimeDiff != 60 {
		t.Fatalf("unexpected REALITY key/time config: %#v", profile.REALITYConfig)
	}
	if len(profile.REALITYConfig.ShortIds) != 1 || profile.REALITYConfig.ShortIds[0] != "abcd" {
		t.Fatalf("unexpected REALITY short ids: %#v", profile.REALITYConfig.ShortIds)
	}
}

func TestEnrichTransportProfileWithSecurityRealityGRPCClearsFlow(t *testing.T) {
	inboundInfo, err := simplejson.NewJson([]byte(`{
		"protocol": "vless",
		"streamSettings": {
			"security": "reality"
		}
	}`))
	if err != nil {
		t.Fatalf("parse inbound fixture: %v", err)
	}
	profile := transportProfile{TransportProtocol: "grpc"}

	enrichTransportProfileWithSecurity(&profile, inboundInfo, "fallback-flow")

	if !profile.EnableREALITY || profile.VlessFlow != "" {
		t.Fatalf("expected REALITY grpc to clear flow, got %#v", profile)
	}
}

func TestEnrichTransportProfileWithEndpoint(t *testing.T) {
	tests := []struct {
		name              string
		transportProtocol string
		fixture           string
		wantHost          string
		wantPath          string
		wantServiceName   string
		wantHeader        string
	}{
		{
			name:              "ws",
			transportProtocol: "ws",
			fixture: `{
				"streamSettings": {
					"wsSettings": {
						"path": "/ws",
						"headers": {"Host": "ws.example.com"}
					}
				}
			}`,
			wantHost: "ws.example.com",
			wantPath: "/ws",
		},
		{
			name:              "httpupgrade",
			transportProtocol: "httpupgrade",
			fixture: `{
				"streamSettings": {
					"httpupgradeSettings": {
						"Host": "upgrade.example.com",
						"path": "/upgrade"
					}
				}
			}`,
			wantHost: "upgrade.example.com",
			wantPath: "/upgrade",
		},
		{
			name:              "splithttp",
			transportProtocol: "splithttp",
			fixture: `{
				"streamSettings": {
					"splithttpSettings": {
						"Host": "split.example.com",
						"path": "/split"
					}
				}
			}`,
			wantHost: "split.example.com",
			wantPath: "/split",
		},
		{
			name:              "grpc",
			transportProtocol: "grpc",
			fixture: `{
				"streamSettings": {
					"grpcSettings": {
						"serviceName": "grpc-service"
					}
				}
			}`,
			wantServiceName: "grpc-service",
		},
		{
			name:              "tcp",
			transportProtocol: "tcp",
			fixture: `{
				"streamSettings": {
					"tcpSettings": {
						"header": {"type": "http"}
					}
				}
			}`,
			wantHeader: `{"type":"http"}`,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			inboundInfo, err := simplejson.NewJson([]byte(tt.fixture))
			if err != nil {
				t.Fatalf("parse inbound fixture: %v", err)
			}
			profile := transportProfile{}

			if err := enrichTransportProfileWithEndpoint(&profile, inboundInfo, tt.transportProtocol); err != nil {
				t.Fatalf("enrich endpoint: %v", err)
			}

			if profile.Host != tt.wantHost || profile.Path != tt.wantPath || profile.ServiceName != tt.wantServiceName {
				t.Fatalf("unexpected endpoint profile: %#v", profile)
			}
			if tt.wantHeader != "" && string(profile.Header) != tt.wantHeader {
				t.Fatalf("unexpected tcp header: %s", string(profile.Header))
			}
		})
	}
}

func TestEnrichTransportProfileWithEndpointXHTTPFallsBackToSplitHTTP(t *testing.T) {
	inboundInfo, err := simplejson.NewJson([]byte(`{
		"streamSettings": {
			"xhttpSettings": {},
			"splithttpSettings": {
				"Host": "split.example.com",
				"path": "/split"
			}
		}
	}`))
	if err != nil {
		t.Fatalf("parse inbound fixture: %v", err)
	}
	profile := transportProfile{}

	if err := enrichTransportProfileWithEndpoint(&profile, inboundInfo, "xhttp"); err != nil {
		t.Fatalf("enrich endpoint: %v", err)
	}

	if profile.Host != "split.example.com" || profile.Path != "/split" {
		t.Fatalf("expected XHTTP endpoint fallback to SplitHTTP, got %#v", profile)
	}
}

func TestEnrichTransportProfileWithEndpointIgnoresNilInputs(t *testing.T) {
	inboundInfo, err := simplejson.NewJson([]byte(`{"streamSettings": {}}`))
	if err != nil {
		t.Fatalf("parse inbound fixture: %v", err)
	}
	profile := transportProfile{Host: "existing"}

	if err := enrichTransportProfileWithEndpoint(nil, inboundInfo, "ws"); err != nil {
		t.Fatalf("nil profile should not error: %v", err)
	}
	if err := enrichTransportProfileWithEndpoint(&profile, nil, "ws"); err != nil {
		t.Fatalf("nil inbound should not error: %v", err)
	}

	if profile.Host != "existing" {
		t.Fatalf("expected nil inputs to leave profile unchanged, got %#v", profile)
	}
}

func TestEnrichTransportProfileWithXHTTPSettings(t *testing.T) {
	inboundInfo, err := simplejson.NewJson([]byte(`{
		"streamSettings": {
			"xhttpSettings": {
				"mode": "stream-one",
				"xPaddingObfsMode": true,
				"xPaddingKey": "x-padding-key",
				"xPaddingHeader": "x-padding-header",
				"xPaddingPlacement": "header",
				"xPaddingMethod": "random",
				"uplinkHTTPMethod": "POST",
				"sessionPlacement": "query",
				"sessionKey": "session-key",
				"seqPlacement": "path",
				"seqKey": "seq-key",
				"uplinkDataPlacement": "body",
				"uplinkDataKey": "data-key",
				"uplinkChunkSize": 4096,
				"noGRPCHeader": true,
				"noSSEHeader": true,
				"extra": {"scMaxEachPostBytes": "1000"}
			},
			"splithttpSettings": {
				"mode": "fallback"
			}
		}
	}`))
	if err != nil {
		t.Fatalf("parse inbound fixture: %v", err)
	}
	profile := transportProfile{}

	enrichTransportProfileWithXHTTPSettings(&profile, inboundInfo, "xhttp")
	enrichTransportProfileWithXHTTPSettings(nil, inboundInfo, "xhttp")
	enrichTransportProfileWithXHTTPSettings(&profile, nil, "xhttp")

	if profile.XHTTPMode != "stream-one" {
		t.Fatalf("expected xhttpSettings to be preferred, got mode %q", profile.XHTTPMode)
	}
	if !profile.XPaddingObfsMode || profile.XPaddingKey != "x-padding-key" || profile.XPaddingHeader != "x-padding-header" {
		t.Fatalf("unexpected padding fields: %#v", profile)
	}
	if profile.UplinkHTTPMethod != "POST" || profile.SessionPlacement != "query" || profile.SeqPlacement != "path" {
		t.Fatalf("unexpected placement fields: %#v", profile)
	}
	if profile.UplinkDataKey != "data-key" || profile.UplinkChunkSize != 4096 {
		t.Fatalf("unexpected uplink fields: %#v", profile)
	}
	if !profile.NoGRPCHeader || !profile.NoSSEHeader {
		t.Fatal("expected header suppression flags to be copied")
	}
	if string(profile.XHTTPExtra) != `{"scMaxEachPostBytes":"1000"}` {
		t.Fatalf("unexpected extra payload: %s", string(profile.XHTTPExtra))
	}
}

func TestEnrichTransportProfileWithXHTTPSettingsFallsBackToSplitHTTP(t *testing.T) {
	inboundInfo, err := simplejson.NewJson([]byte(`{
		"streamSettings": {
			"splithttpSettings": {
				"mode": "auto",
				"uplinkChunkSize": 1024
			}
		}
	}`))
	if err != nil {
		t.Fatalf("parse inbound fixture: %v", err)
	}
	profile := transportProfile{}

	enrichTransportProfileWithXHTTPSettings(&profile, inboundInfo, "xhttp")

	if profile.XHTTPMode != "auto" {
		t.Fatalf("expected splithttpSettings fallback, got mode %q", profile.XHTTPMode)
	}
	if profile.UplinkChunkSize != 1024 {
		t.Fatalf("unexpected fallback uplink chunk size: %d", profile.UplinkChunkSize)
	}
}

func TestEnrichTransportProfileWithXHTTPSettingsIgnoresOtherTransports(t *testing.T) {
	inboundInfo, err := simplejson.NewJson([]byte(`{
		"streamSettings": {
			"splithttpSettings": {
				"mode": "auto"
			}
		}
	}`))
	if err != nil {
		t.Fatalf("parse inbound fixture: %v", err)
	}
	profile := transportProfile{XHTTPMode: "existing"}

	enrichTransportProfileWithXHTTPSettings(&profile, inboundInfo, "ws")

	if profile.XHTTPMode != "existing" {
		t.Fatalf("expected non-XHTTP transport to be ignored, got mode %q", profile.XHTTPMode)
	}
}

func TestTransportProfileApplyToNodeInfo(t *testing.T) {
	header := json.RawMessage(`{"type":"http"}`)
	extra := json.RawMessage(`{"scMaxEachPostBytes":"1000"}`)
	reality := &api.REALITYConfig{
		Dest:             "example.com:443",
		ProxyProtocolVer: 1,
		ServerNames:      []string{"example.com"},
		PrivateKey:       "private-key",
		ShortIds:         []string{"abcd"},
	}
	profile := transportProfile{
		TransportProtocol:   "xhttp",
		EnableTLS:           true,
		EnableVless:         true,
		EnableREALITY:       true,
		VlessFlow:           "xtls-rprx-vision",
		Path:                "/xhttp",
		Host:                "host.example.com",
		ServiceName:         "grpc-service",
		Header:              header,
		REALITYConfig:       reality,
		XHTTPMode:           "stream-one",
		XHTTPExtra:          extra,
		XPaddingObfsMode:    true,
		XPaddingKey:         "padding-key",
		XPaddingHeader:      "padding-header",
		XPaddingPlacement:   "header",
		XPaddingMethod:      "random",
		UplinkHTTPMethod:    "POST",
		SessionPlacement:    "query",
		SessionKey:          "session-key",
		SeqPlacement:        "path",
		SeqKey:              "seq-key",
		UplinkDataPlacement: "body",
		UplinkDataKey:       "data-key",
		UplinkChunkSize:     2048,
		NoGRPCHeader:        true,
		NoSSEHeader:         true,
	}
	nodeInfo := &api.NodeInfo{NodeType: "V2ray", NodeID: 1, Port: 443}

	profile.applyToNodeInfo(nodeInfo)
	profile.applyToNodeInfo(nil)

	if nodeInfo.TransportProtocol != profile.TransportProtocol {
		t.Fatalf("unexpected transport protocol: %s", nodeInfo.TransportProtocol)
	}
	if !nodeInfo.EnableTLS || !nodeInfo.EnableVless || !nodeInfo.EnableREALITY {
		t.Fatalf("expected TLS, VLESS, and REALITY flags to be copied: %#v", nodeInfo)
	}
	if nodeInfo.VlessFlow != profile.VlessFlow {
		t.Fatalf("unexpected VLESS flow: %s", nodeInfo.VlessFlow)
	}
	if nodeInfo.Path != profile.Path || nodeInfo.Host != profile.Host || nodeInfo.ServiceName != profile.ServiceName {
		t.Fatalf("unexpected transport endpoint fields: path=%q host=%q service=%q", nodeInfo.Path, nodeInfo.Host, nodeInfo.ServiceName)
	}
	if string(nodeInfo.Header) != string(header) {
		t.Fatalf("unexpected header: %s", string(nodeInfo.Header))
	}
	if nodeInfo.REALITYConfig != reality {
		t.Fatal("expected REALITY config pointer to be copied")
	}
	if nodeInfo.XHTTPMode != profile.XHTTPMode || string(nodeInfo.XHTTPExtra) != string(extra) {
		t.Fatalf("unexpected XHTTP mode/extra: mode=%q extra=%s", nodeInfo.XHTTPMode, string(nodeInfo.XHTTPExtra))
	}
	if !nodeInfo.XPaddingObfsMode || nodeInfo.XPaddingKey != profile.XPaddingKey || nodeInfo.XPaddingHeader != profile.XPaddingHeader {
		t.Fatalf("unexpected XPadding fields: %#v", nodeInfo)
	}
	if nodeInfo.UplinkHTTPMethod != profile.UplinkHTTPMethod || nodeInfo.SessionPlacement != profile.SessionPlacement || nodeInfo.SeqPlacement != profile.SeqPlacement {
		t.Fatalf("unexpected placement fields: %#v", nodeInfo)
	}
	if nodeInfo.UplinkDataKey != profile.UplinkDataKey || nodeInfo.UplinkChunkSize != profile.UplinkChunkSize {
		t.Fatalf("unexpected uplink data fields: %#v", nodeInfo)
	}
	if !nodeInfo.NoGRPCHeader || !nodeInfo.NoSSEHeader {
		t.Fatal("expected header suppression flags to be copied")
	}
}
