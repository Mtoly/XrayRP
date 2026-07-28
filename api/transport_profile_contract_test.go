package api_test

import (
	"encoding/json"
	"reflect"
	"testing"

	"github.com/bitly/go-simplejson"
	"github.com/xtls/xray-core/app/proxyman"
	"github.com/xtls/xray-core/core"
	"github.com/xtls/xray-core/transport/internet/httpupgrade"
	"github.com/xtls/xray-core/transport/internet/splithttp"
	"google.golang.org/protobuf/proto"

	"github.com/Mtoly/XrayRP/api"
	"github.com/Mtoly/XrayRP/api/bunpanel"
	"github.com/Mtoly/XrayRP/api/v2raysocks"
	"github.com/Mtoly/XrayRP/service/controller"
)

type runtimeTransportOracle struct {
	kind               string
	host               string
	path               string
	mode               string
	headers            map[string]string
	paddingBytes       *[2]int32
	uplinkChunkSize    int32
	scMaxEachPostBytes int32
}

func assertRuntimeTransport(t *testing.T, inbound *core.InboundHandlerConfig, want runtimeTransportOracle) {
	t.Helper()
	if want.kind == "" {
		return
	}

	receiverSettings, err := inbound.ReceiverSettings.GetInstance()
	if err != nil {
		t.Fatalf("decode receiver settings: %v", err)
	}
	receiver, ok := receiverSettings.(*proxyman.ReceiverConfig)
	if !ok {
		t.Fatalf("receiver settings type = %T", receiverSettings)
	}

	for _, transport := range receiver.GetStreamSettings().GetTransportSettings() {
		settings, err := transport.GetSettings().GetInstance()
		if err != nil {
			t.Fatalf("decode %q transport settings: %v", transport.GetProtocolName(), err)
		}
		switch typed := settings.(type) {
		case *httpupgrade.Config:
			if want.kind != "httpupgrade" {
				continue
			}
			if typed.GetHost() != want.host || typed.GetPath() != want.path ||
				!reflect.DeepEqual(typed.GetHeader(), want.headers) {
				t.Fatalf("HTTP Upgrade runtime = %#v, want host=%q path=%q headers=%#v", typed, want.host, want.path, want.headers)
			}
			return
		case *splithttp.Config:
			if want.kind != "splithttp" {
				continue
			}
			if typed.GetHost() != want.host || typed.GetPath() != want.path || typed.GetMode() != want.mode ||
				!reflect.DeepEqual(typed.GetHeaders(), want.headers) {
				t.Fatalf("SplitHTTP runtime = %#v, want host=%q path=%q mode=%q headers=%#v", typed, want.host, want.path, want.mode, want.headers)
			}

			padding := typed.GetXPaddingBytes()
			if want.paddingBytes == nil {
				if padding.GetFrom() != 0 || padding.GetTo() != 0 {
					t.Fatalf("XPaddingBytes = %d-%d, want zero range", padding.GetFrom(), padding.GetTo())
				}
			} else if padding.GetFrom() != want.paddingBytes[0] || padding.GetTo() != want.paddingBytes[1] {
				t.Fatalf("XPaddingBytes = %d-%d, want %d-%d", padding.GetFrom(), padding.GetTo(), want.paddingBytes[0], want.paddingBytes[1])
			}

			chunkSize := typed.GetUplinkChunkSize()
			if chunkSize.GetFrom() != want.uplinkChunkSize || chunkSize.GetTo() != want.uplinkChunkSize {
				t.Fatalf("UplinkChunkSize = %d-%d, want %d", chunkSize.GetFrom(), chunkSize.GetTo(), want.uplinkChunkSize)
			}
			scMaxEachPostBytes := typed.GetScMaxEachPostBytes()
			if scMaxEachPostBytes.GetFrom() != want.scMaxEachPostBytes || scMaxEachPostBytes.GetTo() != want.scMaxEachPostBytes {
				t.Fatalf("ScMaxEachPostBytes = %d-%d, want %d", scMaxEachPostBytes.GetFrom(), scMaxEachPostBytes.GetTo(), want.scMaxEachPostBytes)
			}
			return
		}
	}

	t.Fatalf("%s transport settings not found", want.kind)
}

func TestTransportProfileAdaptersProduceEquivalentNodeInfoAndRuntime(t *testing.T) {
	tests := []struct {
		name       string
		vlessFlow  string
		v2raySocks string
		bun        bunpanel.Server
		runtime    runtimeTransportOracle
	}{
		{
			name:      "websocket TLS",
			vlessFlow: "fallback-flow",
			v2raySocks: `{
				"inbounds": [{
					"port": 8443,
					"protocol": "vmess",
					"streamSettings": {
						"network": "ws",
						"security": "tls",
						"wsSettings": {
							"path": "/socket",
							"headers": {"Host": "edge.example"}
						}
					}
				}]
			}`,
			bun: bunpanel.Server{
				Port:       8443,
				Network:    "ws",
				Security:   "tls",
				Flow:       "fallback-flow",
				WsSettings: json.RawMessage(`{"path":"/socket","headers":{"Host":"edge.example"}}`),
			},
		},
		{
			name:      "TCP header",
			vlessFlow: "fallback-flow",
			v2raySocks: `{
				"inbounds": [{
					"port": 8443,
					"protocol": "vmess",
					"streamSettings": {
						"network": "tcp",
						"tcpSettings": {"header": {"type": "http"}}
					}
				}]
			}`,
			bun: bunpanel.Server{
				Port:        8443,
				Network:     "tcp",
				Flow:        "fallback-flow",
				TcpSettings: json.RawMessage(`{"header":{"type":"http"}}`),
			},
		},
		{
			name:      "gRPC REALITY",
			vlessFlow: "fallback-flow",
			v2raySocks: `{
				"inbounds": [{
					"port": 8443,
					"protocol": "vless",
					"streamSettings": {
						"network": "grpc",
						"security": "reality",
						"realitySettings": {},
						"grpcSettings": {"serviceName": "grpc-service"}
					}
				}]
			}`,
			bun: bunpanel.Server{
				Port:         8443,
				Network:      "grpc",
				Security:     "reality",
				GrpcSettings: json.RawMessage(`{"serviceName":"grpc-service"}`),
			},
		},
		{
			name:      "SplitHTTP",
			vlessFlow: "fallback-flow",
			v2raySocks: `{
				"inbounds": [{
					"port": 8443,
					"protocol": "vmess",
					"streamSettings": {
						"network": "splithttp",
						"splithttpSettings": {
							"Host": "split.example",
							"path": "/split",
							"headers": {"X-Split": "yes"},
							"mode": "auto",
							"uplinkChunkSize": 2048
						}
					}
				}]
			}`,
			bun: bunpanel.Server{
				Port:              8443,
				Network:           "splithttp",
				Flow:              "fallback-flow",
				SplitHTTPSettings: json.RawMessage(`{"host":"split.example","path":"/split","headers":{"X-Split":"yes"},"mode":"auto","uplinkChunkSize":2048}`),
			},
			runtime: runtimeTransportOracle{
				kind:            "splithttp",
				host:            "split.example",
				path:            "/split",
				mode:            "auto",
				headers:         map[string]string{"X-Split": "yes"},
				uplinkChunkSize: 2048,
			},
		},
		{
			name:      "HTTP Upgrade",
			vlessFlow: "fallback-flow",
			v2raySocks: `{
				"inbounds": [{
					"port": 8443,
					"protocol": "vmess",
					"streamSettings": {
						"network": "httpupgrade",
						"httpupgradeSettings": {
							"Host": "upgrade.example",
							"path": "/upgrade",
							"headers": {"X-Upgrade": "yes"}
						}
					}
				}]
			}`,
			bun: bunpanel.Server{
				Port:                8443,
				Network:             "httpupgrade",
				Flow:                "fallback-flow",
				HttpUpgradeSettings: json.RawMessage(`{"host":"upgrade.example","path":"/upgrade","headers":{"X-Upgrade":"yes"}}`),
			},
			runtime: runtimeTransportOracle{
				kind:    "httpupgrade",
				host:    "upgrade.example",
				path:    "/upgrade",
				headers: map[string]string{"X-Upgrade": "yes"},
			},
		},
		{
			name:      "XHTTP legacy SplitHTTP settings",
			vlessFlow: "fallback-flow",
			v2raySocks: `{
				"inbounds": [{
					"port": 8443,
					"protocol": "vmess",
					"streamSettings": {
						"network": "xhttp",
						"splithttpSettings": {
							"Host": "legacy.example",
							"path": "/legacy",
							"headers": {"X-Legacy": "yes"},
							"mode": "auto",
							"xPaddingBytes": [20, 30],
							"uplinkChunkSize": 1024
						}
					}
				}]
			}`,
			bun: bunpanel.Server{
				Port:              8443,
				Network:           "xhttp",
				Flow:              "fallback-flow",
				SplitHTTPSettings: json.RawMessage(`{"host":"legacy.example","path":"/legacy","headers":{"X-Legacy":"yes"},"mode":"auto","xPaddingBytes":[20,30],"uplinkChunkSize":1024}`),
			},
			runtime: runtimeTransportOracle{
				kind:            "splithttp",
				host:            "legacy.example",
				path:            "/legacy",
				mode:            "auto",
				headers:         map[string]string{"X-Legacy": "yes"},
				paddingBytes:    &[2]int32{20, 30},
				uplinkChunkSize: 1024,
			},
		},
		{
			name:      "XHTTP REALITY",
			vlessFlow: "fallback-flow",
			v2raySocks: `{
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
							"minClientVer": "1.0.0",
							"maxClientVer": "2.0.0",
							"maxTimeDiff": 60,
							"shortIds": ["abcd"]
						},
						"xhttpSettings": {
							"Host": "edge.example",
							"path": "/xhttp",
							"headers": {"X-Test": "yes"},
							"mode": "stream-one",
							"extra": {"scMaxEachPostBytes": "1000"},
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
			}`,
			bun: bunpanel.Server{
				Port:     8443,
				Network:  "xhttp",
				Security: "reality",
				Flow:     "fallback-flow",
				RealitySettings: json.RawMessage(`{
					"dest":"origin.example:443",
					"proxyProtocolVer":1,
					"serverNames":["origin.example"],
					"privateKey":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
					"minClientVer":"1.0.0",
					"maxClientVer":"2.0.0",
					"maxTimeDiff":60,
					"shortIds":["abcd"]
				}`),
				XHTTPSettings: json.RawMessage(`{
					"host":"edge.example",
					"path":"/xhttp",
					"headers":{"X-Test":"yes"},
					"mode":"stream-one",
					"extra":{"scMaxEachPostBytes":"1000"},
					"xPaddingBytes":[100,200],
					"xPaddingObfsMode":true,
					"xPaddingKey":"padding-key",
					"xPaddingHeader":"padding-header",
					"xPaddingPlacement":"header",
					"xPaddingMethod":"random",
					"uplinkHTTPMethod":"POST",
					"sessionPlacement":"query",
					"sessionKey":"session-key",
					"seqPlacement":"path",
					"seqKey":"seq-key",
					"uplinkDataPlacement":"body",
					"uplinkDataKey":"data-key",
					"uplinkChunkSize":4096,
					"noGRPCHeader":true,
					"noSSEHeader":true
				}`),
			},
			runtime: runtimeTransportOracle{
				kind:               "splithttp",
				host:               "edge.example",
				path:               "/xhttp",
				mode:               "stream-one",
				scMaxEachPostBytes: 1000,
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			v2Payload, err := simplejson.NewJson([]byte(tt.v2raySocks))
			if err != nil {
				t.Fatalf("parse V2raySocks fixture: %v", err)
			}
			config := &api.Config{
				NodeID:    17,
				NodeType:  "V2ray",
				VlessFlow: tt.vlessFlow,
			}
			fromV2raySocks, err := v2raysocks.New(config).ParseV2rayNodeResponse(v2Payload)
			if err != nil {
				t.Fatalf("parse V2raySocks node: %v", err)
			}
			fromBunPanel, err := bunpanel.New(config).ParseNodeInfo(&tt.bun)
			if err != nil {
				t.Fatalf("parse BunPanel node: %v", err)
			}

			if !reflect.DeepEqual(fromV2raySocks, fromBunPanel) {
				t.Fatalf("equivalent payloads produced different node info:\nV2raySocks: %#v\nBunPanel:   %#v", fromV2raySocks, fromBunPanel)
			}

			fromV2raySocksRuntime, err := controller.InboundBuilder(&controller.Config{}, fromV2raySocks, "transport-contract")
			if err != nil {
				t.Fatalf("build V2raySocks runtime: %v", err)
			}
			fromBunPanelRuntime, err := controller.InboundBuilder(&controller.Config{}, fromBunPanel, "transport-contract")
			if err != nil {
				t.Fatalf("build BunPanel runtime: %v", err)
			}
			if !proto.Equal(fromV2raySocksRuntime, fromBunPanelRuntime) {
				t.Fatalf("equivalent payloads produced different Xray runtime configs:\nV2raySocks: %v\nBunPanel:   %v", fromV2raySocksRuntime, fromBunPanelRuntime)
			}
			assertRuntimeTransport(t, fromV2raySocksRuntime, tt.runtime)
			assertRuntimeTransport(t, fromBunPanelRuntime, tt.runtime)
		})
	}
}
