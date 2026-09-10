package controller

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/bitly/go-simplejson"
	"github.com/xtls/xray-core/app/proxyman"
	"github.com/xtls/xray-core/common/session"
	"github.com/xtls/xray-core/features/outbound"
	"github.com/xtls/xray-core/infra/conf"
	xrayreality "github.com/xtls/xray-core/transport/internet/reality"
	"github.com/xtls/xray-core/transport/internet/splithttp"

	"github.com/Mtoly/XrayRP/api"
	"github.com/Mtoly/XrayRP/api/newV2board"
	"github.com/Mtoly/XrayRP/api/v2raysocks"
)

func TestXrayUpstreamCanaryPreservesXHTTPRealityRuntimeContract(t *testing.T) {
	node := parseXrayUpstreamCanaryNode(t, `{
		"inbounds": [{
			"port": 8443,
			"protocol": "vless",
			"streamSettings": {
				"network": "xhttp",
				"security": "reality",
				"realitySettings": {
					"dest": "origin.example:443",
					"xver": 1,
					"serverNames": ["origin.example"],
					"privateKey": "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
					"minClientVer": "1.2.3",
					"maxClientVer": "4.5.6",
					"maxTimeDiff": 60,
					"shortIds": ["abcd"]
				},
				"xhttpSettings": {
					"Host": "edge.example",
					"path": "/xhttp",
					"headers": {"X-Canary": "v26"},
					"mode": "stream-one",
					"extra": {"scMaxEachPostBytes": "1000"},
					"xPaddingBytes": [100, 200],
					"xPaddingObfsMode": true,
					"xPaddingKey": "padding-key",
					"xPaddingHeader": "padding-header",
					"xPaddingPlacement": "header",
					"xPaddingMethod": "tokenish",
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
	}`, "fallback-flow")

	if node.TransportProtocol != "xhttp" || !node.EnableREALITY || !node.EnableVless || node.VlessFlow != "fallback-flow" {
		t.Fatalf("parsed XHTTP REALITY node changed: %#v", node)
	}

	inbound, err := InboundBuilder(&Config{}, node, "xray-upstream-canary")
	if err != nil {
		t.Fatalf("build XHTTP REALITY inbound: %v", err)
	}
	receiverMessage, err := inbound.GetReceiverSettings().GetInstance()
	if err != nil {
		t.Fatalf("decode receiver settings: %v", err)
	}
	receiver, ok := receiverMessage.(*proxyman.ReceiverConfig)
	if !ok {
		t.Fatalf("receiver settings type = %T", receiverMessage)
	}
	stream := receiver.GetStreamSettings()
	if stream.GetSecurityType() != "xray.transport.internet.reality.Config" {
		t.Fatalf("security type = %q", stream.GetSecurityType())
	}

	securityMessage, err := stream.GetSecuritySettings()[0].GetInstance()
	if err != nil {
		t.Fatalf("decode REALITY settings: %v", err)
	}
	realityConfig, ok := securityMessage.(*xrayreality.Config)
	if !ok {
		t.Fatalf("REALITY settings type = %T", securityMessage)
	}
	privateKey, err := base64.RawURLEncoding.DecodeString("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA")
	if err != nil {
		t.Fatal(err)
	}
	shortID, err := hex.DecodeString("abcd000000000000")
	if err != nil {
		t.Fatal(err)
	}
	if realityConfig.GetDest() != "origin.example:443" || realityConfig.GetXver() != 1 ||
		!reflect.DeepEqual(realityConfig.GetServerNames(), []string{"origin.example"}) ||
		!bytes.Equal(realityConfig.GetPrivateKey(), privateKey) ||
		!bytes.Equal(realityConfig.GetMinClientVer(), []byte{1, 2, 3}) ||
		!bytes.Equal(realityConfig.GetMaxClientVer(), []byte{4, 5, 6}) ||
		realityConfig.GetMaxTimeDiff() != 60 || len(realityConfig.GetShortIds()) != 1 ||
		!bytes.Equal(realityConfig.GetShortIds()[0], shortID) {
		t.Fatalf("REALITY protobuf contract changed: %#v", realityConfig)
	}

	var xhttpConfig *splithttp.Config
	for _, transport := range stream.GetTransportSettings() {
		message, err := transport.GetSettings().GetInstance()
		if err != nil {
			t.Fatalf("decode transport %q: %v", transport.GetProtocolName(), err)
		}
		if typed, ok := message.(*splithttp.Config); ok {
			xhttpConfig = typed
			break
		}
	}
	if xhttpConfig == nil {
		t.Fatal("SplitHTTP protobuf for XHTTP was not emitted")
	}
	padding := xhttpConfig.GetXPaddingBytes()
	chunk := xhttpConfig.GetUplinkChunkSize()
	postBytes := xhttpConfig.GetScMaxEachPostBytes()
	if xhttpConfig.GetHost() != "edge.example" || xhttpConfig.GetPath() != "/xhttp" ||
		xhttpConfig.GetMode() != "stream-one" || !reflect.DeepEqual(xhttpConfig.GetHeaders(), map[string]string{"X-Canary": "v26"}) ||
		padding.GetFrom() != 100 || padding.GetTo() != 200 || !xhttpConfig.GetXPaddingObfsMode() ||
		xhttpConfig.GetXPaddingKey() != "padding-key" || xhttpConfig.GetXPaddingHeader() != "padding-header" ||
		xhttpConfig.GetXPaddingPlacement() != "header" || xhttpConfig.GetXPaddingMethod() != "tokenish" ||
		xhttpConfig.GetUplinkHTTPMethod() != "POST" || xhttpConfig.GetSessionIDPlacement() != "query" ||
		xhttpConfig.GetSessionIDKey() != "session-key" || xhttpConfig.GetSeqPlacement() != "path" ||
		xhttpConfig.GetSeqKey() != "seq-key" || xhttpConfig.GetUplinkDataPlacement() != "body" ||
		xhttpConfig.GetUplinkDataKey() != "data-key" || chunk.GetFrom() != 4096 || chunk.GetTo() != 4096 ||
		!xhttpConfig.GetNoGRPCHeader() || !xhttpConfig.GetNoSSEHeader() ||
		postBytes.GetFrom() != 1000 || postBytes.GetTo() != 1000 {
		t.Fatalf("XHTTP protobuf contract changed: %#v", xhttpConfig)
	}
}

func TestXrayUpstreamCanaryPreservesRealityFlowRules(t *testing.T) {
	tests := []struct {
		network     string
		settingsKey string
		wantFlow    string
	}{
		{network: "tcp", settingsKey: "tcpSettings", wantFlow: "xtls-rprx-vision"},
		{network: "grpc", settingsKey: "grpcSettings", wantFlow: ""},
		{network: "xhttp", settingsKey: "xhttpSettings", wantFlow: "fallback-flow"},
	}

	for _, tt := range tests {
		t.Run(tt.network, func(t *testing.T) {
			raw := fmt.Sprintf(`{
				"inbounds": [{
					"port": 443,
					"protocol": "vless",
					"streamSettings": {
						"network": %q,
						"security": "reality",
						"realitySettings": {},
						%q: {}
					}
				}]
			}`, tt.network, tt.settingsKey)
			node := parseXrayUpstreamCanaryNode(t, raw, "fallback-flow")
			if node.VlessFlow != tt.wantFlow {
				t.Fatalf("%s REALITY flow = %q, want %q", tt.network, node.VlessFlow, tt.wantFlow)
			}
		})
	}
}

func TestXrayUpstreamCanaryPreservesManagedRoutingAndSyncCoordinator(t *testing.T) {
	base := &fakeOutboundHandler{tag: "VLESS_10.0.0.1_443_1"}
	otherBase := &fakeOutboundHandler{tag: "VLESS_10.0.0.1_443_2"}
	otherManaged := &dataPathWrapper{Handler: otherBase, tag: otherBase.tag}
	direct := &fakeOutboundHandler{tag: "direct"}
	selector := runtimeRoutingSelector{
		baseTag:     base.tag,
		baseHandler: base,
		obm: &fakeOutboundManager{handlers: map[string]outbound.Handler{
			otherManaged.tag: otherManaged,
			direct.tag:       direct,
		}},
		routePolicy: newRoutingPolicyValue(&api.PanelRoutePolicy{Outbound: api.OutboundFilterPolicy{
			Candidates: []string{direct.tag},
		}}),
	}

	matching := selector.selectDispatch(session.ContextWithInbound(context.Background(), &session.Inbound{Tag: base.tag}))
	if matching.rejectReason != "" || matching.handler != direct || matching.managedHandoff {
		t.Fatalf("same-node routing contract changed: %#v", matching)
	}
	managed := selector.selectDispatch(session.ContextWithInbound(context.Background(), &session.Inbound{Tag: otherManaged.tag}))
	if managed.rejectReason != "" || managed.handler != otherManaged || !managed.managedHandoff {
		t.Fatalf("managed-node handoff contract changed: %#v", managed)
	}

	action, ok := syncActionFromWSEvent(newV2board.WSEventRoutesChanged, time.Unix(1, 0))
	if !ok || action.Type != syncActionTypeSyncRoutesAndOutbounds {
		t.Fatalf("route WebSocket event mapping changed: %#v, ok=%v", action, ok)
	}
	executor := newCoordinatorTestExecutor()
	coordinator := newSyncCoordinator(executor)
	t.Cleanup(coordinator.Stop)
	coordinator.Submit(action)
	waitForCoordinatorIdle(t, coordinator)
	if got, want := executor.Calls(), []syncActionType{syncActionTypeSyncRoutesAndOutbounds}; !reflect.DeepEqual(got, want) {
		t.Fatalf("WebSocket action bypassed or changed coordinator execution: got %v want %v", got, want)
	}
}

func TestXrayUpstreamCanaryPreservesReleaseBuildContract(t *testing.T) {
	workflowPath := filepath.Join("..", "..", ".github", "workflows", "release.yml")
	workflow, err := os.ReadFile(workflowPath)
	if err != nil {
		t.Fatalf("read release workflow: %v", err)
	}
	contents := string(workflow)
	for _, required := range []string{
		`uses: ./.github/workflows/test.yml`,
		`ref: ${{ needs.metadata.outputs.commit }}`,
		`CGO_ENABLED: "0"`,
		`go build -v -o build_assets/XrayR -tags with_quic -trimpath -ldflags "$ldflags" .`,
	} {
		if !strings.Contains(contents, required) {
			t.Fatalf("release workflow no longer contains required Xray canary contract %q", required)
		}
	}
}

func parseXrayUpstreamCanaryNode(t *testing.T, raw, fallbackFlow string) *api.NodeInfo {
	t.Helper()
	payload, err := simplejson.NewJson([]byte(raw))
	if err != nil {
		t.Fatalf("parse Xray canary fixture: %v", err)
	}
	node, err := v2raysocks.New(&api.Config{
		NodeID:    17,
		NodeType:  "V2ray",
		VlessFlow: fallbackFlow,
	}).ParseV2rayNodeResponse(payload)
	if err != nil {
		t.Fatalf("parse Xray canary node: %v", err)
	}
	return node
}

func TestMergeSplitHTTPExtraPreservesAdvancedFieldsAndExplicitOverrides(t *testing.T) {
	extra := json.RawMessage(`{
		"host":"extra.example",
		"path":"/extra",
		"mode":"packet-up",
		"headers":{"X-Extra":"yes"},
		"xPaddingMethod":"repeat-x",
		"sessionIDTable":"base64",
		"sessionIDLength":"20-24",
		"serverMaxHeaderBytes":4096,
		"scMaxEachPostBytes":"900-1000",
		"xmux":{"maxConcurrency":"4-8"}
	}`)
	explicit := &conf.SplitHTTPConfig{
		Host:           "explicit.example",
		Path:           "/explicit",
		Mode:           "stream-one",
		Headers:        map[string]string{"X-Explicit": "yes"},
		XPaddingMethod: "tokenish",
		Xmux: conf.XmuxConfig{
			HKeepAlivePeriod: 15,
		},
		Extra: extra,
	}

	merged, err := mergeSplitHTTPExtra(explicit)
	if err != nil {
		t.Fatalf("merge XHTTP extra: %v", err)
	}
	if merged.Extra != nil {
		t.Fatalf("merged extra = %s, want nil to prevent a second upstream replacement", merged.Extra)
	}
	if merged.Host != "explicit.example" || merged.Path != "/explicit" || merged.Mode != "stream-one" ||
		!reflect.DeepEqual(merged.Headers, map[string]string{"X-Explicit": "yes"}) ||
		merged.XPaddingMethod != "tokenish" {
		t.Fatalf("explicit XHTTP settings were not preserved: %#v", merged)
	}
	if merged.SessionIDTable != "base64" || merged.SessionIDLength.From != 20 || merged.SessionIDLength.To != 24 ||
		merged.ServerMaxHeaderBytes != 4096 || merged.ScMaxEachPostBytes.From != 900 || merged.ScMaxEachPostBytes.To != 1000 ||
		merged.Xmux.MaxConcurrency.From != 4 || merged.Xmux.MaxConcurrency.To != 8 || merged.Xmux.HKeepAlivePeriod != 15 {
		t.Fatalf("advanced XHTTP extra settings were not preserved: %#v", merged)
	}
}

func TestMergeSplitHTTPExtraRejectsInvalidJSONWithContext(t *testing.T) {
	_, err := mergeSplitHTTPExtra(&conf.SplitHTTPConfig{Extra: json.RawMessage(`{`)})
	if err == nil || !strings.Contains(err.Error(), "decode XHTTP extra") {
		t.Fatalf("error = %v, want contextual XHTTP extra decode error", err)
	}
}

func TestMergeSplitHTTPExtraLeavesConfigWithoutExtraUntouched(t *testing.T) {
	explicit := &conf.SplitHTTPConfig{Host: "edge.example", Path: "/xhttp"}
	merged, err := mergeSplitHTTPExtra(explicit)
	if err != nil {
		t.Fatalf("merge XHTTP config without extra: %v", err)
	}
	if merged != explicit {
		t.Fatalf("config without extra was copied or replaced: got %p want %p", merged, explicit)
	}
}
