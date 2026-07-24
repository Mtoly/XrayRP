package v2raysocks

import (
	"testing"

	"github.com/bitly/go-simplejson"

	"github.com/Mtoly/XrayRP/api"
	"github.com/Mtoly/XrayRP/api/internal/transportprofile"
)

func mustSimpleJSON(t *testing.T, raw string) *simplejson.Json {
	t.Helper()
	jsonData, err := simplejson.NewJson([]byte(raw))
	if err != nil {
		t.Fatalf("parse JSON fixture: %v", err)
	}
	return jsonData
}

func TestDeriveTransportProfileFromInbound(t *testing.T) {
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

	profile, err := deriveTransportProfileFromInbound(inboundInfo, "fallback-flow")
	if err != nil {
		t.Fatalf("derive transport profile: %v", err)
	}

	if profile.Protocol != "xhttp" {
		t.Fatalf("unexpected transport protocol: %s", profile.Protocol)
	}
	if !profile.Security.EnableVless || !profile.Security.EnableREALITY || profile.Security.EnableTLS {
		t.Fatalf("unexpected security flags: %#v", profile)
	}
	if profile.Security.VlessFlow != "fallback-flow" {
		t.Fatalf("expected fallback flow for non-tcp REALITY transport, got %q", profile.Security.VlessFlow)
	}
	if profile.Endpoints.XHTTP.Host != "xhttp.example.com" || profile.Endpoints.XHTTP.Path != "/xhttp" {
		t.Fatalf("unexpected endpoint fields: %#v", profile)
	}
	if profile.XHTTP.Mode != "stream-one" || profile.XHTTP.UplinkChunkSize != 4096 {
		t.Fatalf("unexpected XHTTP fields: %#v", profile)
	}
	if profile.Security.REALITYConfig == nil || profile.Security.REALITYConfig.Dest != "example.com:443" {
		t.Fatalf("unexpected REALITY config: %#v", profile.Security.REALITYConfig)
	}
}

func TestDeriveTransportProfileFromInboundNil(t *testing.T) {
	profile, err := deriveTransportProfileFromInbound(nil, "fallback-flow")
	if err != nil {
		t.Fatalf("nil inbound should not error: %v", err)
	}
	if profile.Protocol != "" || profile.Security.EnableTLS || profile.Security.EnableVless || profile.Security.EnableREALITY || profile.Security.REALITYConfig != nil || len(profile.Endpoints.TCP.Header) != 0 {
		t.Fatalf("expected zero profile for nil inbound, got %#v", profile)
	}
}

func TestEnrichTransportProfileWithSecurityTLS(t *testing.T) {
	inboundInfo := mustSimpleJSON(t, `{
		"protocol": "vmess",
		"streamSettings": {
			"security": "tls"
		}
	}`)
	profile := transportprofile.Input{Protocol: "ws"}

	enrichTransportProfileWithSecurity(&profile, inboundInfo, "fallback-flow")
	enrichTransportProfileWithSecurity(nil, inboundInfo, "fallback-flow")
	enrichTransportProfileWithSecurity(&profile, nil, "fallback-flow")

	if !profile.Security.EnableTLS {
		t.Fatal("expected TLS to be enabled")
	}
	if profile.Security.EnableVless || profile.Security.EnableREALITY {
		t.Fatalf("unexpected VLESS/REALITY flags: %#v", profile)
	}
	if profile.Security.VlessFlow != "fallback-flow" {
		t.Fatalf("expected fallback VLESS flow, got %q", profile.Security.VlessFlow)
	}
	if profile.Security.REALITYConfig == nil {
		t.Fatal("expected empty REALITY config to preserve previous behavior")
	}
}

func TestEnrichTransportProfileWithSecurityRealityTCPUsesVision(t *testing.T) {
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
	profile := transportprofile.Input{Protocol: "tcp"}

	enrichTransportProfileWithSecurity(&profile, inboundInfo, "fallback-flow")

	if profile.Security.EnableTLS || !profile.Security.EnableVless || !profile.Security.EnableREALITY {
		t.Fatalf("unexpected security flags: %#v", profile)
	}
	if profile.Security.VlessFlow != "xtls-rprx-vision" {
		t.Fatalf("expected REALITY TCP to use vision flow, got %q", profile.Security.VlessFlow)
	}
	if profile.Security.REALITYConfig == nil {
		t.Fatal("expected REALITY config to be populated")
	}
	if profile.Security.REALITYConfig.Dest != "example.com:443" || profile.Security.REALITYConfig.ProxyProtocolVer != 1 {
		t.Fatalf("unexpected REALITY config: %#v", profile.Security.REALITYConfig)
	}
	if len(profile.Security.REALITYConfig.ServerNames) != 1 || profile.Security.REALITYConfig.ServerNames[0] != "example.com" {
		t.Fatalf("unexpected REALITY server names: %#v", profile.Security.REALITYConfig.ServerNames)
	}
	if profile.Security.REALITYConfig.PrivateKey != "private-key" || profile.Security.REALITYConfig.MaxTimeDiff != 60 {
		t.Fatalf("unexpected REALITY key/time config: %#v", profile.Security.REALITYConfig)
	}
	if len(profile.Security.REALITYConfig.ShortIds) != 1 || profile.Security.REALITYConfig.ShortIds[0] != "abcd" {
		t.Fatalf("unexpected REALITY short ids: %#v", profile.Security.REALITYConfig.ShortIds)
	}
}

func TestEnrichTransportProfileWithSecurityRealityGRPCClearsFlow(t *testing.T) {
	inboundInfo := mustSimpleJSON(t, `{
		"protocol": "vless",
		"streamSettings": {
			"security": "reality"
		}
	}`)
	profile := transportprofile.Input{Protocol: "grpc"}

	enrichTransportProfileWithSecurity(&profile, inboundInfo, "fallback-flow")

	if !profile.Security.EnableREALITY || profile.Security.VlessFlow != "" {
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
			inboundInfo := mustSimpleJSON(t, tt.fixture)
			profile := transportprofile.Input{Protocol: tt.transportProtocol}

			if err := enrichTransportProfileWithEndpoint(&profile, inboundInfo, tt.transportProtocol); err != nil {
				t.Fatalf("enrich endpoint: %v", err)
			}
			nodeInfo := new(api.NodeInfo)
			transportprofile.Apply(nodeInfo, profile)

			if nodeInfo.Host != tt.wantHost || nodeInfo.Path != tt.wantPath || nodeInfo.ServiceName != tt.wantServiceName {
				t.Fatalf("unexpected endpoint profile: %#v", profile)
			}
			if tt.wantHeader != "" && string(nodeInfo.Header) != tt.wantHeader {
				t.Fatalf("unexpected tcp header: %s", string(nodeInfo.Header))
			}
		})
	}
}

func TestEnrichTransportProfileWithEndpointXHTTPFallsBackToSplitHTTP(t *testing.T) {
	inboundInfo := mustSimpleJSON(t, `{
		"streamSettings": {
			"xhttpSettings": {},
			"splithttpSettings": {
				"Host": "split.example.com",
				"path": "/split"
			}
		}
	}`)
	profile := transportprofile.Input{Protocol: "xhttp"}

	if err := enrichTransportProfileWithEndpoint(&profile, inboundInfo, "xhttp"); err != nil {
		t.Fatalf("enrich endpoint: %v", err)
	}

	nodeInfo := new(api.NodeInfo)
	transportprofile.Apply(nodeInfo, profile)
	if nodeInfo.Host != "split.example.com" || nodeInfo.Path != "/split" {
		t.Fatalf("expected XHTTP endpoint fallback to SplitHTTP, got %#v", profile)
	}
}

func TestEnrichTransportProfileWithEndpointIgnoresNilInputs(t *testing.T) {
	inboundInfo := mustSimpleJSON(t, `{"streamSettings": {}}`)
	profile := transportprofile.Input{
		Endpoints: transportprofile.Endpoints{
			WebSocket: transportprofile.Endpoint{Host: "existing"},
		},
	}

	if err := enrichTransportProfileWithEndpoint(nil, inboundInfo, "ws"); err != nil {
		t.Fatalf("nil profile should not error: %v", err)
	}
	if err := enrichTransportProfileWithEndpoint(&profile, nil, "ws"); err != nil {
		t.Fatalf("nil inbound should not error: %v", err)
	}

	if profile.Endpoints.WebSocket.Host != "existing" {
		t.Fatalf("expected nil inputs to leave profile unchanged, got %#v", profile)
	}
}

func TestEnrichTransportProfileWithXHTTPSettings(t *testing.T) {
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
	profile := transportprofile.Input{}

	enrichTransportProfileWithXHTTPSettings(&profile, inboundInfo, "xhttp")
	enrichTransportProfileWithXHTTPSettings(nil, inboundInfo, "xhttp")
	enrichTransportProfileWithXHTTPSettings(&profile, nil, "xhttp")

	if profile.XHTTP.Mode != "stream-one" {
		t.Fatalf("expected xhttpSettings to be preferred, got mode %q", profile.XHTTP.Mode)
	}
	if !profile.XHTTP.PaddingObfsMode || profile.XHTTP.PaddingKey != "x-padding-key" || profile.XHTTP.PaddingHeader != "x-padding-header" {
		t.Fatalf("unexpected padding fields: %#v", profile)
	}
	if profile.XHTTP.UplinkHTTPMethod != "POST" || profile.XHTTP.SessionPlacement != "query" || profile.XHTTP.SeqPlacement != "path" {
		t.Fatalf("unexpected placement fields: %#v", profile)
	}
	if profile.XHTTP.UplinkDataKey != "data-key" || profile.XHTTP.UplinkChunkSize != 4096 {
		t.Fatalf("unexpected uplink fields: %#v", profile)
	}
	if !profile.XHTTP.NoGRPCHeader || !profile.XHTTP.NoSSEHeader {
		t.Fatal("expected header suppression flags to be copied")
	}
	if string(profile.XHTTP.Extra) != `{"scMaxEachPostBytes":"1000"}` {
		t.Fatalf("unexpected extra payload: %s", string(profile.XHTTP.Extra))
	}
}

func TestEnrichTransportProfileWithXHTTPSettingsFallsBackToSplitHTTP(t *testing.T) {
	inboundInfo := mustSimpleJSON(t, `{
		"streamSettings": {
			"splithttpSettings": {
				"mode": "auto",
				"uplinkChunkSize": 1024
			}
		}
	}`)
	profile := transportprofile.Input{}

	enrichTransportProfileWithXHTTPSettings(&profile, inboundInfo, "xhttp")

	if profile.XHTTP.Mode != "auto" {
		t.Fatalf("expected splithttpSettings fallback, got mode %q", profile.XHTTP.Mode)
	}
	if profile.XHTTP.UplinkChunkSize != 1024 {
		t.Fatalf("unexpected fallback uplink chunk size: %d", profile.XHTTP.UplinkChunkSize)
	}
}

func TestEnrichTransportProfileWithXHTTPSettingsIgnoresOtherTransports(t *testing.T) {
	inboundInfo := mustSimpleJSON(t, `{
		"streamSettings": {
			"splithttpSettings": {
				"mode": "auto"
			}
		}
	}`)
	profile := transportprofile.Input{XHTTP: transportprofile.XHTTP{Mode: "existing"}}

	enrichTransportProfileWithXHTTPSettings(&profile, inboundInfo, "ws")

	if profile.XHTTP.Mode != "existing" {
		t.Fatalf("expected non-XHTTP transport to be ignored, got mode %q", profile.XHTTP.Mode)
	}
}
