package v2raysocks

import (
	"encoding/json"
	"reflect"
	"strings"
	"testing"

	"github.com/bitly/go-simplejson"

	"github.com/Mtoly/XrayRP/api"
)

func mustSimpleJSON(t *testing.T, raw string) *simplejson.Json {
	t.Helper()
	jsonData, err := simplejson.NewJson([]byte(raw))
	if err != nil {
		t.Fatalf("parse JSON fixture: %v", err)
	}
	return jsonData
}

func TestParseV2rayNodeResponseProjectsTransportFieldsAgainstLiteralOracle(t *testing.T) {
	payload := mustSimpleJSON(t, `{
		"inbounds": [{
			"port": 8443,
			"protocol": "vmess",
			"streamSettings": {
				"network": "xhttp",
				"security": "tls",
				"xhttpSettings": {
					"Host": "edge.example",
					"path": "/xhttp",
					"headers": {},
					"mode": "stream-one",
					"extra": {},
					"xPaddingBytes": [100, 200],
					"xPaddingObfsMode": true,
					"xPaddingKey": "padding-key",
					"xPaddingHeader": "padding-header",
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
					"noSSEHeader": true
				}
			}
		}]
	}`)
	client := New(&api.Config{
		NodeID:    17,
		NodeType:  "V2ray",
		VlessFlow: "fallback-flow",
	})
	node, err := client.ParseV2rayNodeResponse(payload)
	if err != nil {
		t.Fatal(err)
	}

	paddingBytes := [2]int32{100, 200}
	want := &api.NodeInfo{
		NodeType:            "V2ray",
		NodeID:              17,
		Port:                8443,
		TransportProtocol:   "xhttp",
		Host:                "edge.example",
		Path:                "/xhttp",
		EnableTLS:           true,
		VlessFlow:           "fallback-flow",
		Headers:             map[string]string{},
		REALITYConfig:       &api.REALITYConfig{},
		XHTTPMode:           "stream-one",
		XHTTPExtra:          json.RawMessage(`{}`),
		XPaddingBytes:       &paddingBytes,
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
		UplinkChunkSize:     4096,
		NoGRPCHeader:        true,
		NoSSEHeader:         true,
	}
	if !reflect.DeepEqual(node, want) {
		t.Fatalf("node info = %#v, want %#v", node, want)
	}
	if node.Headers == nil || node.XHTTPExtra == nil || node.XPaddingBytes == nil || node.REALITYConfig == nil {
		t.Fatalf("non-nil transport values became nil: %#v", node)
	}
}

func TestParseV2rayNodeResponseRejectsInvalidTransportFieldTypes(t *testing.T) {
	tests := []struct {
		name     string
		settings string
		wantErr  string
	}{
		{
			name:     "headers",
			settings: `"headers":{"X-Test":1}`,
			wantErr:  "decode transport headers",
		},
		{
			name:     "xPaddingBytes",
			settings: `"xPaddingBytes":"invalid"`,
			wantErr:  "decode xPaddingBytes",
		},
		{
			name:     "xPaddingBytes wrong length",
			settings: `"xPaddingBytes":[100]`,
			wantErr:  "decode xPaddingBytes",
		},
		{
			name:     "uplinkChunkSize overflow",
			settings: `"uplinkChunkSize":4294967296`,
			wantErr:  "decode uplinkChunkSize",
		},
		{
			name:     "uplinkChunkSize runtime overflow",
			settings: `"uplinkChunkSize":2147483648`,
			wantErr:  "decode uplinkChunkSize",
		},
	}

	client := New(&api.Config{NodeID: 17, NodeType: "V2ray"})
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			payload := mustSimpleJSON(t, `{
				"inbounds": [{
					"port": 8443,
					"protocol": "vmess",
					"streamSettings": {
						"network": "xhttp",
						"xhttpSettings": {`+tt.settings+`}
					}
				}]
			}`)
			_, err := client.ParseV2rayNodeResponse(payload)
			if err == nil || !strings.Contains(err.Error(), tt.wantErr) {
				t.Fatalf("error = %v, want %q", err, tt.wantErr)
			}
		})
	}
}

func TestParseV2rayNodeResponseKeepsUnknownTransportEndpointEmpty(t *testing.T) {
	payload := mustSimpleJSON(t, `{
		"inbounds": [{
			"port": 8443,
			"protocol": "vmess",
			"streamSettings": {"network": "unknown"}
		}]
	}`)
	node, err := New(&api.Config{
		NodeID:    17,
		NodeType:  "V2ray",
		VlessFlow: "fallback-flow",
	}).ParseV2rayNodeResponse(payload)
	if err != nil {
		t.Fatal(err)
	}
	if node.TransportProtocol != "unknown" || node.Host != "" || node.Path != "" ||
		node.ServiceName != "" || node.Header != nil || node.Headers != nil {
		t.Fatalf("unknown transport inherited endpoint state: %#v", node)
	}
}

func TestEnrichNodeInfoWithTransport(t *testing.T) {
	inboundInfo := mustSimpleJSON(t, `{
		"protocol": "vless",
		"streamSettings": {
			"network": "xhttp",
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
			},
			"xhttpSettings": {
				"Host": "xhttp.example.com",
				"path": "/xhttp",
				"mode": "stream-one",
				"uplinkChunkSize": 4096
			}
		}
	}`)

	nodeInfo := new(api.NodeInfo)
	if err := enrichNodeInfoWithTransport(nodeInfo, inboundInfo, "fallback-flow"); err != nil {
		t.Fatalf("enrich node info with transport: %v", err)
	}

	if nodeInfo.TransportProtocol != "xhttp" {
		t.Fatalf("unexpected transport protocol: %s", nodeInfo.TransportProtocol)
	}
	if !nodeInfo.EnableVless || !nodeInfo.EnableREALITY || nodeInfo.EnableTLS {
		t.Fatalf("unexpected security flags: %#v", nodeInfo)
	}
	if nodeInfo.VlessFlow != "fallback-flow" {
		t.Fatalf("expected fallback flow for non-tcp REALITY transport, got %q", nodeInfo.VlessFlow)
	}
	if nodeInfo.Host != "xhttp.example.com" || nodeInfo.Path != "/xhttp" {
		t.Fatalf("unexpected endpoint fields: %#v", nodeInfo)
	}
	if nodeInfo.XHTTPMode != "stream-one" || nodeInfo.UplinkChunkSize != 4096 {
		t.Fatalf("unexpected XHTTP fields: %#v", nodeInfo)
	}
	if nodeInfo.REALITYConfig == nil || nodeInfo.REALITYConfig.Dest != "example.com:443" {
		t.Fatalf("unexpected REALITY config: %#v", nodeInfo.REALITYConfig)
	}
}

func TestEnrichNodeInfoWithTransportIgnoresNilInputs(t *testing.T) {
	nodeInfo := &api.NodeInfo{TransportProtocol: "existing"}
	if err := enrichNodeInfoWithTransport(nodeInfo, nil, "fallback-flow"); err != nil {
		t.Fatalf("nil inbound should not error: %v", err)
	}
	if err := enrichNodeInfoWithTransport(nil, mustSimpleJSON(t, `{}`), "fallback-flow"); err != nil {
		t.Fatalf("nil node info should not error: %v", err)
	}
	if nodeInfo.TransportProtocol != "existing" {
		t.Fatalf("nil inbound changed node info: %#v", nodeInfo)
	}
}

func TestEnrichNodeInfoWithSecurityTLS(t *testing.T) {
	inboundInfo := mustSimpleJSON(t, `{
		"protocol": "vmess",
		"streamSettings": {
			"security": "tls"
		}
	}`)
	nodeInfo := &api.NodeInfo{TransportProtocol: "ws"}

	enrichNodeInfoWithSecurity(nodeInfo, inboundInfo, "fallback-flow")
	enrichNodeInfoWithSecurity(nil, inboundInfo, "fallback-flow")
	enrichNodeInfoWithSecurity(nodeInfo, nil, "fallback-flow")

	if !nodeInfo.EnableTLS {
		t.Fatal("expected TLS to be enabled")
	}
	if nodeInfo.EnableVless || nodeInfo.EnableREALITY {
		t.Fatalf("unexpected VLESS/REALITY flags: %#v", nodeInfo)
	}
	if nodeInfo.VlessFlow != "fallback-flow" {
		t.Fatalf("expected fallback VLESS flow, got %q", nodeInfo.VlessFlow)
	}
	if nodeInfo.REALITYConfig == nil {
		t.Fatal("expected empty REALITY config to preserve previous behavior")
	}
}

func TestEnrichNodeInfoWithSecurityRealityTCPUsesVision(t *testing.T) {
	inboundInfo := mustSimpleJSON(t, `{
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
	}`)
	nodeInfo := &api.NodeInfo{TransportProtocol: "tcp"}

	enrichNodeInfoWithSecurity(nodeInfo, inboundInfo, "fallback-flow")

	if nodeInfo.EnableTLS || !nodeInfo.EnableVless || !nodeInfo.EnableREALITY {
		t.Fatalf("unexpected security flags: %#v", nodeInfo)
	}
	if nodeInfo.VlessFlow != "xtls-rprx-vision" {
		t.Fatalf("expected REALITY TCP to use vision flow, got %q", nodeInfo.VlessFlow)
	}
	if nodeInfo.REALITYConfig == nil {
		t.Fatal("expected REALITY config to be populated")
	}
	if nodeInfo.REALITYConfig.Dest != "example.com:443" || nodeInfo.REALITYConfig.ProxyProtocolVer != 1 {
		t.Fatalf("unexpected REALITY config: %#v", nodeInfo.REALITYConfig)
	}
	if len(nodeInfo.REALITYConfig.ServerNames) != 1 || nodeInfo.REALITYConfig.ServerNames[0] != "example.com" {
		t.Fatalf("unexpected REALITY server names: %#v", nodeInfo.REALITYConfig.ServerNames)
	}
	if nodeInfo.REALITYConfig.PrivateKey != "private-key" || nodeInfo.REALITYConfig.MaxTimeDiff != 60 {
		t.Fatalf("unexpected REALITY key/time config: %#v", nodeInfo.REALITYConfig)
	}
	if len(nodeInfo.REALITYConfig.ShortIds) != 1 || nodeInfo.REALITYConfig.ShortIds[0] != "abcd" {
		t.Fatalf("unexpected REALITY short ids: %#v", nodeInfo.REALITYConfig.ShortIds)
	}
}

func TestEnrichNodeInfoWithSecurityRealityGRPCClearsFlow(t *testing.T) {
	inboundInfo := mustSimpleJSON(t, `{
		"protocol": "vless",
		"streamSettings": {
			"security": "reality"
		}
	}`)
	nodeInfo := &api.NodeInfo{TransportProtocol: "grpc"}

	enrichNodeInfoWithSecurity(nodeInfo, inboundInfo, "fallback-flow")

	if !nodeInfo.EnableREALITY || nodeInfo.VlessFlow != "" {
		t.Fatalf("expected REALITY grpc to clear flow, got %#v", nodeInfo)
	}
}

func TestEnrichNodeInfoWithEndpoint(t *testing.T) {
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
			inboundInfo := mustSimpleJSON(t, tt.fixture)
			nodeInfo := new(api.NodeInfo)

			if err := enrichNodeInfoWithEndpoint(nodeInfo, inboundInfo, tt.transportProtocol); err != nil {
				t.Fatalf("enrich endpoint: %v", err)
			}

			if nodeInfo.Host != tt.wantHost || nodeInfo.Path != tt.wantPath || nodeInfo.ServiceName != tt.wantServiceName {
				t.Fatalf("unexpected endpoint fields: %#v", nodeInfo)
			}
			if tt.wantHeader != "" && string(nodeInfo.Header) != tt.wantHeader {
				t.Fatalf("unexpected tcp header: %s", string(nodeInfo.Header))
			}
		})
	}
}

func TestEnrichNodeInfoWithEndpointXHTTPFallsBackToSplitHTTP(t *testing.T) {
	inboundInfo := mustSimpleJSON(t, `{
		"streamSettings": {
			"xhttpSettings": {},
			"splithttpSettings": {
				"Host": "split.example.com",
				"path": "/split",
				"headers": {"X-Split": "yes"}
			}
		}
	}`)
	nodeInfo := new(api.NodeInfo)

	if err := enrichNodeInfoWithEndpoint(nodeInfo, inboundInfo, "xhttp"); err != nil {
		t.Fatalf("enrich endpoint: %v", err)
	}

	if nodeInfo.Host != "split.example.com" || nodeInfo.Path != "/split" {
		t.Fatalf("expected XHTTP endpoint fallback to SplitHTTP, got %#v", nodeInfo)
	}
	if !reflect.DeepEqual(nodeInfo.Headers, map[string]string{"X-Split": "yes"}) {
		t.Fatalf("expected missing XHTTP headers to fall back to SplitHTTP, got %#v", nodeInfo.Headers)
	}
}

func TestEnrichNodeInfoWithEndpointXHTTPHeadersPreservePresenceSemantics(t *testing.T) {
	tests := []struct {
		name        string
		xhttpHeader string
		want        map[string]string
	}{
		{
			name:        "null falls back",
			xhttpHeader: `"headers": null`,
			want:        map[string]string{"X-Split": "yes"},
		},
		{
			name:        "explicit empty does not fall back",
			xhttpHeader: `"headers": {}`,
			want:        map[string]string{},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			inboundInfo := mustSimpleJSON(t, `{
				"streamSettings": {
					"xhttpSettings": {`+tt.xhttpHeader+`},
					"splithttpSettings": {
						"headers": {"X-Split": "yes"}
					}
				}
			}`)
			nodeInfo := new(api.NodeInfo)

			if err := enrichNodeInfoWithEndpoint(nodeInfo, inboundInfo, "xhttp"); err != nil {
				t.Fatalf("enrich endpoint: %v", err)
			}
			if !reflect.DeepEqual(nodeInfo.Headers, tt.want) {
				t.Fatalf("headers = %#v, want %#v", nodeInfo.Headers, tt.want)
			}
			if nodeInfo.Headers == nil {
				t.Fatal("present transport headers became nil")
			}
		})
	}
}

func TestEnrichNodeInfoWithEndpointIgnoresNilInputs(t *testing.T) {
	inboundInfo := mustSimpleJSON(t, `{"streamSettings": {}}`)
	nodeInfo := &api.NodeInfo{Host: "existing"}

	if err := enrichNodeInfoWithEndpoint(nil, inboundInfo, "ws"); err != nil {
		t.Fatalf("nil node info should not error: %v", err)
	}
	if err := enrichNodeInfoWithEndpoint(nodeInfo, nil, "ws"); err != nil {
		t.Fatalf("nil inbound should not error: %v", err)
	}

	if nodeInfo.Host != "existing" {
		t.Fatalf("expected nil inputs to leave node info unchanged, got %#v", nodeInfo)
	}
}

func TestEnrichNodeInfoWithXHTTPSettings(t *testing.T) {
	inboundInfo := mustSimpleJSON(t, `{
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
	}`)
	nodeInfo := new(api.NodeInfo)

	enrichNodeInfoWithXHTTPSettings(nodeInfo, inboundInfo, "xhttp")
	enrichNodeInfoWithXHTTPSettings(nil, inboundInfo, "xhttp")
	enrichNodeInfoWithXHTTPSettings(nodeInfo, nil, "xhttp")

	if nodeInfo.XHTTPMode != "stream-one" {
		t.Fatalf("expected xhttpSettings to be preferred, got mode %q", nodeInfo.XHTTPMode)
	}
	if !nodeInfo.XPaddingObfsMode || nodeInfo.XPaddingKey != "x-padding-key" || nodeInfo.XPaddingHeader != "x-padding-header" {
		t.Fatalf("unexpected padding fields: %#v", nodeInfo)
	}
	if nodeInfo.UplinkHTTPMethod != "POST" || nodeInfo.SessionPlacement != "query" || nodeInfo.SeqPlacement != "path" {
		t.Fatalf("unexpected placement fields: %#v", nodeInfo)
	}
	if nodeInfo.UplinkDataKey != "data-key" || nodeInfo.UplinkChunkSize != 4096 {
		t.Fatalf("unexpected uplink fields: %#v", nodeInfo)
	}
	if !nodeInfo.NoGRPCHeader || !nodeInfo.NoSSEHeader {
		t.Fatal("expected header suppression flags to be copied")
	}
	if string(nodeInfo.XHTTPExtra) != `{"scMaxEachPostBytes":"1000"}` {
		t.Fatalf("unexpected extra payload: %s", string(nodeInfo.XHTTPExtra))
	}
}

func TestEnrichNodeInfoWithXHTTPSettingsFallsBackToSplitHTTP(t *testing.T) {
	inboundInfo := mustSimpleJSON(t, `{
		"streamSettings": {
			"splithttpSettings": {
				"mode": "auto",
				"uplinkChunkSize": 1024
			}
		}
	}`)
	nodeInfo := new(api.NodeInfo)

	enrichNodeInfoWithXHTTPSettings(nodeInfo, inboundInfo, "xhttp")

	if nodeInfo.XHTTPMode != "auto" {
		t.Fatalf("expected splithttpSettings fallback, got mode %q", nodeInfo.XHTTPMode)
	}
	if nodeInfo.UplinkChunkSize != 1024 {
		t.Fatalf("unexpected fallback uplink chunk size: %d", nodeInfo.UplinkChunkSize)
	}
}

func TestEnrichNodeInfoWithXHTTPSettingsIgnoresOtherTransports(t *testing.T) {
	inboundInfo := mustSimpleJSON(t, `{
		"streamSettings": {
			"splithttpSettings": {
				"mode": "auto"
			}
		}
	}`)
	nodeInfo := &api.NodeInfo{XHTTPMode: "existing"}

	enrichNodeInfoWithXHTTPSettings(nodeInfo, inboundInfo, "ws")

	if nodeInfo.XHTTPMode != "existing" {
		t.Fatalf("expected non-XHTTP transport to be ignored, got mode %q", nodeInfo.XHTTPMode)
	}
}
