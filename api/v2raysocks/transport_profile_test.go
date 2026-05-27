package v2raysocks

import (
	"encoding/json"
	"testing"

	"github.com/bitly/go-simplejson"

	"github.com/Mtoly/XrayRP/api"
)

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
