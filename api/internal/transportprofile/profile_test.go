package transportprofile

import (
	"encoding/json"
	"reflect"
	"testing"

	"github.com/Mtoly/XrayRP/api"
)

func TestApplySelectsEndpointForTransport(t *testing.T) {
	endpoints := Endpoints{
		WebSocket:   Endpoint{Host: "ws.example", Path: "/ws"},
		GRPC:        Endpoint{ServiceName: "grpc-service"},
		TCP:         Endpoint{Header: json.RawMessage(`{"type":"http"}`)},
		SplitHTTP:   Endpoint{Host: "split.example", Path: "/split", Headers: map[string]string{"X-Split": "yes"}},
		XHTTP:       Endpoint{Host: "xhttp.example", Path: "/xhttp", Headers: map[string]string{"X-XHTTP": "yes"}},
		HTTPUpgrade: Endpoint{Host: "upgrade.example", Path: "/upgrade", Headers: map[string]string{"X-Upgrade": "yes"}},
		Fallback:    Endpoint{Host: "fallback.example", Path: "/fallback"},
	}
	tests := []struct {
		protocol string
		want     Endpoint
	}{
		{protocol: "ws", want: endpoints.WebSocket},
		{protocol: "grpc", want: endpoints.GRPC},
		{protocol: "tcp", want: endpoints.TCP},
		{protocol: "splithttp", want: endpoints.SplitHTTP},
		{protocol: "xhttp", want: endpoints.XHTTP},
		{protocol: "httpupgrade", want: endpoints.HTTPUpgrade},
		{protocol: "unknown", want: endpoints.Fallback},
	}

	for _, tt := range tests {
		t.Run(tt.protocol, func(t *testing.T) {
			node := &api.NodeInfo{}
			Apply(node, Input{Protocol: tt.protocol, Endpoints: endpoints})

			got := Endpoint{
				Host:        node.Host,
				Path:        node.Path,
				ServiceName: node.ServiceName,
				Header:      node.Header,
				Headers:     node.Headers,
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Fatalf("endpoint = %#v, want %#v", got, tt.want)
			}
		})
	}
}

func TestApplyProjectsResolvedTransportProfile(t *testing.T) {
	paddingBytes := [2]int32{100, 200}
	header := json.RawMessage(`{"type":"http"}`)
	extra := json.RawMessage(`{"scMaxEachPostBytes":"1000"}`)
	headers := map[string]string{"X-Test": "yes"}
	reality := &api.REALITYConfig{
		Dest:             "origin.example:443",
		ProxyProtocolVer: 1,
		ServerNames:      []string{"origin.example"},
		PrivateKey:       "private-key",
		ShortIds:         []string{"abcd"},
	}
	node := &api.NodeInfo{
		NodeType: "V2ray",
		NodeID:   17,
		Port:     8443,
	}

	Apply(node, Input{
		Protocol: "xhttp",
		Endpoints: Endpoints{
			XHTTP: Endpoint{
				Host:    "edge.example",
				Path:    "/xhttp",
				Header:  header,
				Headers: headers,
			},
		},
		Security: Security{
			EnableTLS:     true,
			EnableVless:   true,
			EnableREALITY: true,
			VlessFlow:     "xtls-rprx-vision",
			REALITYConfig: reality,
		},
		XHTTP: XHTTP{
			Mode:                "stream-one",
			Extra:               extra,
			PaddingBytes:        &paddingBytes,
			PaddingObfsMode:     true,
			PaddingKey:          "padding-key",
			PaddingHeader:       "padding-header",
			PaddingPlacement:    "header",
			PaddingMethod:       "random",
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
		},
	})
	Apply(nil, Input{})

	if node.NodeType != "V2ray" || node.NodeID != 17 || node.Port != 8443 {
		t.Fatalf("identity fields changed: %#v", node)
	}
	if node.TransportProtocol != "xhttp" || node.Host != "edge.example" || node.Path != "/xhttp" {
		t.Fatalf("unexpected transport endpoint: %#v", node)
	}
	if !node.EnableTLS || !node.EnableVless || !node.EnableREALITY || node.VlessFlow != "xtls-rprx-vision" {
		t.Fatalf("unexpected security projection: %#v", node)
	}
	if node.REALITYConfig != reality {
		t.Fatal("REALITY config pointer semantics changed")
	}
	if !reflect.DeepEqual(node.Header, header) || !reflect.DeepEqual(node.Headers, headers) {
		t.Fatalf("raw endpoint values changed: header=%s headers=%#v", node.Header, node.Headers)
	}
	if node.XHTTPMode != "stream-one" || !reflect.DeepEqual(node.XHTTPExtra, extra) || node.XPaddingBytes != &paddingBytes {
		t.Fatalf("unexpected XHTTP core fields: %#v", node)
	}
	if !node.XPaddingObfsMode || node.XPaddingKey != "padding-key" || node.XPaddingHeader != "padding-header" {
		t.Fatalf("unexpected padding fields: %#v", node)
	}
	if node.UplinkHTTPMethod != "POST" || node.SessionPlacement != "query" || node.SeqPlacement != "path" {
		t.Fatalf("unexpected placement fields: %#v", node)
	}
	if node.UplinkDataKey != "data-key" || node.UplinkChunkSize != 4096 || !node.NoGRPCHeader || !node.NoSSEHeader {
		t.Fatalf("unexpected uplink fields: %#v", node)
	}
}

func TestApplyPreservesNilAndNonNilEmptyTransportValues(t *testing.T) {
	emptyHeader := json.RawMessage{}
	emptyExtra := json.RawMessage{}
	emptyHeaders := map[string]string{}
	node := new(api.NodeInfo)

	Apply(node, Input{
		Protocol: "xhttp",
		Endpoints: Endpoints{
			XHTTP: Endpoint{
				Header:  emptyHeader,
				Headers: emptyHeaders,
			},
		},
		XHTTP: XHTTP{Extra: emptyExtra},
	})

	if node.Header == nil || node.XHTTPExtra == nil || node.Headers == nil {
		t.Fatalf("non-nil empty values became nil: header=%#v extra=%#v headers=%#v", node.Header, node.XHTTPExtra, node.Headers)
	}
	if len(node.Header) != 0 || len(node.XHTTPExtra) != 0 || len(node.Headers) != 0 {
		t.Fatalf("empty values gained content: header=%#v extra=%#v headers=%#v", node.Header, node.XHTTPExtra, node.Headers)
	}
}
