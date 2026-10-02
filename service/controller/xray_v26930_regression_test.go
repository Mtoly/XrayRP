package controller

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/xtls/xray-core/infra/conf"
	xrayudphop "github.com/xtls/xray-core/transport/internet/finalmask/udphop"
)

// v26.9.30 added MASQUE/XDRIVE to the transport registry and, in commit 8267cf95
// ("Transport: Refactor to be based on Finalmask's dialer & listener"), replaced
// MemoryStreamSettings.TcpmaskManager/UdpmaskManager with MemoryStreamSettings.FinalMask.
// XrayRP never touched the manager fields, so it compiles against both generations,
// but the transport/security name mapping it feeds through panel nodes has to keep
// resolving to the same upstream protocol names.
func TestXrayV26930TransportRegistryKeepsXrayRPConsumedProtocolsRegistered(t *testing.T) {
	mappings := []struct {
		panelName    string
		upstreamName string
	}{
		{panelName: "tcp", upstreamName: "tcp"},
		{panelName: "raw", upstreamName: "tcp"},
		{panelName: "xhttp", upstreamName: "splithttp"},
		{panelName: "splithttp", upstreamName: "splithttp"},
		{panelName: "kcp", upstreamName: "mkcp"},
		{panelName: "grpc", upstreamName: "grpc"},
		{panelName: "ws", upstreamName: "websocket"},
		{panelName: "websocket", upstreamName: "websocket"},
		{panelName: "httpupgrade", upstreamName: "httpupgrade"},
		{panelName: "hysteria", upstreamName: "hysteria"},
	}
	for _, mapping := range mappings {
		built, err := conf.TransportProtocol(mapping.panelName).Build()
		if err != nil {
			t.Fatalf("transport %q no longer builds against v26.9.30: %v", mapping.panelName, err)
		}
		if built != mapping.upstreamName {
			t.Fatalf("transport %q mapped to %q, want %q", mapping.panelName, built, mapping.upstreamName)
		}
	}

	for _, removed := range []string{"h2", "h3", "http", "quic"} {
		if built, err := conf.TransportProtocol(removed).Build(); err == nil {
			t.Fatalf("transport %q is expected to be reported as removed upstream, got %q", removed, built)
		}
	}
}

// v26.9.30 renamed udpHop's config fields and changed their protobuf field numbers
// (sockopt reserved, remoteIPs 7, remote_ports 8). XrayRP does not build Finalmask
// configs itself, but it must still be able to link the package and read the fields
// the XHTTP/Hysteria transport paths depend on.
func TestXrayV26930UDPHopFinalmaskContractRemainsLinkable(t *testing.T) {
	config := &xrayudphop.Config{
		Local:       true,
		Remote:      true,
		RemoteOnce:  false,
		IntervalMin: 30,
		IntervalMax: 60,
		RemoteIPs:   []string{"192.0.2.1", "192.0.2.2"},
		RemotePorts: []uint32{443, 8443},
	}
	if !config.GetLocal() || !config.GetRemote() || config.GetIntervalMin() != 30 || config.GetIntervalMax() != 60 {
		t.Fatalf("udpHop finalmask config contract changed: %#v", config)
	}
	if len(config.GetRemoteIPs()) != 2 || len(config.GetRemotePorts()) != 2 {
		t.Fatalf("udpHop finalmask remote address contract changed: %#v", config)
	}
}

// Commit 61cad5ec removed (*errors.Error).AtError/AtInfo/AtWarning/AtDebug from
// common/errors. XrayRP's adapter is expected to keep the call sites free of the
// removed attributes so the canary keeps compiling on the next upstream bump.
func TestXrayV26930RemovedErrorSeverityAttributesStayOutOfAdapters(t *testing.T) {
	roots := []string{
		filepath.Join("..", "..", "app", "mydispatcher"),
		filepath.Join("..", "..", "service", "controller"),
	}
	removed := []string{".AtError()", ".AtWarning()", ".AtInfo()", ".AtDebug()"}
	for _, root := range roots {
		entries, err := os.ReadDir(root)
		if err != nil {
			t.Fatalf("read %s: %v", root, err)
		}
		for _, entry := range entries {
			if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".go") || strings.HasSuffix(entry.Name(), "_test.go") {
				continue
			}
			contents, err := os.ReadFile(filepath.Join(root, entry.Name()))
			if err != nil {
				t.Fatalf("read %s: %v", entry.Name(), err)
			}
			for _, attribute := range removed {
				if strings.Contains(string(contents), attribute) {
					t.Fatalf("%s still calls the removed upstream attribute %s", entry.Name(), attribute)
				}
			}
		}
	}
}
