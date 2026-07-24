package api_test

import (
	"encoding/json"
	"reflect"
	"testing"

	"github.com/bitly/go-simplejson"

	"github.com/Mtoly/XrayRP/api"
	"github.com/Mtoly/XrayRP/api/bunpanel"
	"github.com/Mtoly/XrayRP/api/v2raysocks"
)

func TestTransportProfileAdaptersProduceEquivalentNodeInfo(t *testing.T) {
	tests := []struct {
		name       string
		vlessFlow  string
		v2raySocks string
		bun        bunpanel.Server
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
							"privateKey": "private-key",
							"minClientVer": "1.0.0",
							"maxClientVer": "2.0.0",
							"maxTimeDiff": 60,
							"shortIds": ["abcd"]
						},
						"xhttpSettings": {
							"Host": "edge.example",
							"path": "/xhttp",
							"mode": "stream-one",
							"extra": {"scMaxEachPostBytes": "1000"},
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
					"privateKey":"private-key",
					"minClientVer":"1.0.0",
					"maxClientVer":"2.0.0",
					"maxTimeDiff":60,
					"shortIds":["abcd"]
				}`),
				XHTTPSettings: json.RawMessage(`{
					"host":"edge.example",
					"path":"/xhttp",
					"mode":"stream-one",
					"extra":{"scMaxEachPostBytes":"1000"},
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
		})
	}
}
