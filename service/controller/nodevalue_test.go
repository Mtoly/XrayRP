package controller

import (
	"encoding/json"
	"net"
	"reflect"
	"testing"

	"github.com/Mtoly/XrayRP/api"
	xraynet "github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/infra/conf"
)

func TestNodeValueOwnsAllMutableNodeInfo(t *testing.T) {
	source := testMutableNodeInfo(t)
	want := testMutableNodeInfo(t)

	value := normalizeNodeInfo(source)
	mutateNodeInfo(source)

	first := value.snapshot()
	if !reflect.DeepEqual(first, want) {
		t.Fatalf("normalized value changed with its source:\n got: %#v\nwant: %#v", first, want)
	}

	mutateNodeInfo(first)
	second := value.snapshot()
	if !reflect.DeepEqual(second, want) {
		t.Fatalf("normalized value changed through its snapshot:\n got: %#v\nwant: %#v", second, want)
	}
}

func TestNodeValuePreservesNilAndNonNilEmptyCollections(t *testing.T) {
	nilCollections := normalizeNodeInfo(&api.NodeInfo{})
	emptyStringList := conf.StringList(make([]string, 0))
	emptyCollections := normalizeNodeInfo(&api.NodeInfo{
		Header:      make(json.RawMessage, 0),
		HttpHeaders: make(map[string]*conf.StringList),
		Headers:     make(map[string]string),
		NameServerConfig: []*conf.NameServerConfig{{
			Domains:       make([]string, 0),
			ExpectedIPs:   emptyStringList,
			ExpectIPs:     conf.StringList(make([]string, 0)),
			UnexpectedIPs: conf.StringList(make([]string, 0)),
		}},
		REALITYConfig: &api.REALITYConfig{
			ServerNames: make([]string, 0),
			ShortIds:    make([]string, 0),
		},
		ServerNames:     make([]string, 0),
		ShortIds:        make([]string, 0),
		AnyTLSConfig:    &api.AnyTLSConfig{PaddingScheme: make([]string, 0)},
		TuicConfig:      &api.TuicConfig{ALPN: make([]string, 0)},
		Hysteria2Config: &api.Hysteria2Config{},
		RoutePolicy: &api.PanelRoutePolicy{
			DirectDomains: make([]string, 0),
			Outbound: api.OutboundFilterPolicy{
				Candidates: make([]string, 0),
				Include:    make([]string, 0),
				Exclude:    make([]string, 0),
				Fallback:   make([]string, 0),
			},
		},
		XHTTPExtra:            make(json.RawMessage, 0),
		XHTTPDownloadSettings: make(json.RawMessage, 0),
	})

	if nilCollections.equal(emptyCollections) {
		t.Fatal("nil and non-nil empty collections must remain observably different")
	}
	snapshot := emptyCollections.snapshot()
	if snapshot == nil || snapshot.Header == nil || snapshot.HttpHeaders == nil || snapshot.Headers == nil ||
		snapshot.NameServerConfig == nil || snapshot.NameServerConfig[0].Domains == nil ||
		snapshot.NameServerConfig[0].ExpectedIPs == nil || snapshot.NameServerConfig[0].ExpectIPs == nil ||
		snapshot.NameServerConfig[0].UnexpectedIPs == nil || snapshot.REALITYConfig.ServerNames == nil ||
		snapshot.REALITYConfig.ShortIds == nil || snapshot.ServerNames == nil || snapshot.ShortIds == nil ||
		snapshot.AnyTLSConfig.PaddingScheme == nil || snapshot.TuicConfig.ALPN == nil ||
		snapshot.RoutePolicy.DirectDomains == nil || snapshot.RoutePolicy.Outbound.Candidates == nil ||
		snapshot.RoutePolicy.Outbound.Include == nil || snapshot.RoutePolicy.Outbound.Exclude == nil ||
		snapshot.RoutePolicy.Outbound.Fallback == nil || snapshot.XHTTPExtra == nil ||
		snapshot.XHTTPDownloadSettings == nil {
		t.Fatalf("normalized snapshot collapsed non-nil empty collections: %#v", snapshot)
	}
}

func TestNodeValueEqualityPreservesRawCompatibilitySemantics(t *testing.T) {
	raw := &api.NodeInfo{
		NodeType:          "V2ray",
		TransportProtocol: "",
		Header:            json.RawMessage(`{"type":"none"}`),
	}
	value := normalizeNodeInfo(raw)
	if !value.equal(normalizeNodeInfo(value.snapshot())) {
		t.Fatal("equivalent raw node values must compare equal")
	}

	transportAlias := *raw
	transportAlias.TransportProtocol = "tcp"
	if value.equal(normalizeNodeInfo(&transportAlias)) {
		t.Fatal("transport aliases must not be globally canonicalized")
	}

	dormantChange := *raw
	dormantChange.Show = true
	if value.equal(normalizeNodeInfo(&dormantChange)) {
		t.Fatal("dormant compatibility fields must retain whole-value equality semantics")
	}
}

func TestNodeValueNilRemainsUnset(t *testing.T) {
	unset := normalizeNodeInfo(nil)
	if unset.isSet() || unset.snapshot() != nil {
		t.Fatalf("nil input became a set value: %#v", unset)
	}
	if !unset.equal(normalizeNodeInfo(nil)) {
		t.Fatal("two unset values must compare equal")
	}
	if unset.equal(normalizeNodeInfo(&api.NodeInfo{})) {
		t.Fatal("unset and an explicitly empty node must remain different")
	}
}

func TestNodeValueSnapshotPreservesAddressFamilyAndValue(t *testing.T) {
	tests := []struct {
		name    string
		address xraynet.Address
		family  xraynet.AddressFamily
	}{
		{name: "numeric domain", address: xraynet.DomainAddress("1.1.1.1"), family: xraynet.AddressFamilyDomain},
		{name: "IPv4", address: xraynet.IPAddress(net.IPv4(192, 0, 2, 1).To4()), family: xraynet.AddressFamilyIPv4},
		{name: "IPv6", address: xraynet.IPAddress(net.ParseIP("2001:db8::1")), family: xraynet.AddressFamilyIPv6},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			value := normalizeNodeInfo(&api.NodeInfo{
				NameServerConfig: []*conf.NameServerConfig{{
					Address: &conf.Address{Address: test.address},
				}},
			})
			snapshot := value.snapshot()
			got := snapshot.NameServerConfig[0].Address.Address
			if got.Family() != test.family || got.String() != test.address.String() {
				t.Fatalf("address = %q family %d, want %q family %d", got.String(), got.Family(), test.address.String(), test.family)
			}
		})
	}
}

func TestNodeValueEqualityPreservesCustomAddressConcreteTypes(t *testing.T) {
	first := normalizeNodeInfo(&api.NodeInfo{
		NameServerConfig: []*conf.NameServerConfig{{
			Address: &conf.Address{Address: customIPv4AddressA{192, 0, 2, 1}},
		}},
	})
	second := normalizeNodeInfo(&api.NodeInfo{
		NameServerConfig: []*conf.NameServerConfig{{
			Address: &conf.Address{Address: customIPv4AddressB{192, 0, 2, 1}},
		}},
	})

	if first.equal(second) {
		t.Fatal("custom address concrete types must remain observable to equality")
	}
	if first.equal(normalizeNodeInfo(&api.NodeInfo{
		NameServerConfig: []*conf.NameServerConfig{{
			Address: &conf.Address{Address: xraynet.IPAddress([]byte{192, 0, 2, 1})},
		}},
	})) {
		t.Fatal("custom and Xray built-in address concrete types must remain observable to equality")
	}
	if !first.equal(normalizeNodeInfo(&api.NodeInfo{
		NameServerConfig: []*conf.NameServerConfig{{
			Address: &conf.Address{Address: customIPv4AddressA{192, 0, 2, 1}},
		}},
	})) {
		t.Fatal("equal custom address concrete values must remain equal")
	}
}

func TestNodeValuePassesThroughAddressWithoutCloneContract(t *testing.T) {
	custom := &customUnknownAddress{text: "custom-address"}
	value := normalizeNodeInfo(&api.NodeInfo{
		NameServerConfig: []*conf.NameServerConfig{{
			Address: &conf.Address{Address: custom},
		}},
	})

	got := value.snapshot().NameServerConfig[0].Address.Address
	if got != custom {
		t.Fatalf("custom address without a clone contract was rewritten: got %#v want %#v", got, custom)
	}
}

func TestNodeRuntimeStateStoresNormalizedNodeValue(t *testing.T) {
	controller := &Controller{}
	source := testMutableNodeInfo(t)
	want := testMutableNodeInfo(t)

	controller.setNodeState(source, "node-tag")
	mutateNodeInfo(source)

	state := controller.runtimeStateSnapshot()
	if !state.node.isSet() {
		t.Fatal("Node runtime state did not retain the normalized node value")
	}
	if got := state.node.snapshot(); !reflect.DeepEqual(got, want) {
		t.Fatalf("Node runtime state stored a mutable compatibility value:\n got: %#v\nwant: %#v", got, want)
	}
}

type customIPv4AddressA [4]byte

func (address customIPv4AddressA) IP() net.IP {
	return net.IPv4(address[0], address[1], address[2], address[3]).To4()
}

func (customIPv4AddressA) Domain() string {
	panic("custom IPv4 address has no domain")
}

func (customIPv4AddressA) Family() xraynet.AddressFamily {
	return xraynet.AddressFamilyIPv4
}

func (address customIPv4AddressA) String() string {
	return address.IP().String()
}

type customIPv4AddressB [4]byte

func (address customIPv4AddressB) IP() net.IP {
	return net.IPv4(address[0], address[1], address[2], address[3]).To4()
}

func (customIPv4AddressB) Domain() string {
	panic("custom IPv4 address has no domain")
}

func (customIPv4AddressB) Family() xraynet.AddressFamily {
	return xraynet.AddressFamilyIPv4
}

func (address customIPv4AddressB) String() string {
	return address.IP().String()
}

type customUnknownAddress struct {
	text string
}

func (*customUnknownAddress) IP() net.IP {
	return nil
}

func (address *customUnknownAddress) Domain() string {
	return address.text
}

func (*customUnknownAddress) Family() xraynet.AddressFamily {
	return xraynet.AddressFamily(255)
}

func (address *customUnknownAddress) String() string {
	return address.text
}
