package v2raysocks

import (
	"encoding/json"
	"testing"

	"github.com/Mtoly/XrayRP/api"
)

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
