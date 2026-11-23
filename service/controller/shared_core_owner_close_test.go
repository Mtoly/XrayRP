package controller_test

// Regression coverage for a shared Xray core that serves several controllers.
// Xray assigns the global default outbound to the first registered handler and
// clears it when that handler is removed without promoting another one. These
// tests exercise the real controller lifecycle and a real loopback TLS origin:
// the remaining controller's clients must keep reaching the origin through
// their own managed outbound after the default owner is unbound.

import (
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/Mtoly/XrayRP/api"
	"github.com/Mtoly/XrayRP/service/controller"
	xnet "github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/core"
	"github.com/xtls/xray-core/features/outbound"
)

const sharedCoreTestUUID = "2c5f39cb-30b2-42e3-9940-0017e4ddb531"
const sharedCoreTestBody = "shared-core-owner-close-ok"

func sharedCorePanelNode(nodeID, port int) *realCorePanelClient {
	return &realCorePanelClient{
		node: api.NodeInfo{
			NodeID:            nodeID,
			NodeType:          "Vless",
			EnableVless:       true,
			TransportProtocol: "xhttp",
			Port:              uint32(port),
			RoutePolicy: &api.PanelRoutePolicy{
				Outbound: api.OutboundFilterPolicy{Candidates: []string{"local-origin"}},
			},
		},
		users: []api.UserInfo{{UID: 1, Email: "shared-core@example.test", UUID: sharedCoreTestUUID}},
	}
}

func sharedCoreStartController(t *testing.T, server *core.Instance, panel *realCorePanelClient) *controller.Controller {
	t.Helper()
	c := controller.New(server, panel, &controller.Config{
		ListenIP:        "127.0.0.1",
		SendIP:          "0.0.0.0",
		UpdatePeriodic:  3600,
		DisableGetRule:  true,
		DisableSniffing: true,
	}, "test")
	if err := c.Start(); err != nil {
		t.Fatalf("controller Start: %v", err)
	}
	t.Cleanup(func() { _ = c.Close() })
	return c
}

func sharedCoreDistinctPorts(t *testing.T, n int) []int {
	t.Helper()
	ports := make([]int, 0, n)
	for len(ports) < n {
		port := reserveLoopbackPort(t)
		duplicate := false
		for _, existing := range ports {
			if existing == port {
				duplicate = true
				break
			}
		}
		if !duplicate {
			ports = append(ports, port)
		}
	}
	return ports
}

func sharedCoreNodeTag(port, nodeID int) string {
	return fmt.Sprintf("VLESS_127.0.0.1_%d_%d", port, nodeID)
}

func sharedCoreDefaultTag(manager outbound.Manager) string {
	if handler := manager.GetDefaultHandler(); handler != nil {
		return handler.Tag()
	}
	return "<nil>"
}

func sharedCoreRegisteredTags(manager outbound.Manager) []string {
	var tags []string
	for _, handler := range manager.ListHandlers(context.Background()) {
		tags = append(tags, handler.Tag())
	}
	return tags
}

// sharedCoreTryHTTPS dials nodePort with a fresh VLESS/xhttp client and fetches
// the loopback TLS origin through the shared core. It returns the exact
// status/body on success or the exact transport error on failure.
func sharedCoreTryHTTPS(origin *httptest.Server, port int) (bool, string) {
	cfg := fmt.Sprintf(`{"log":{"loglevel":"none"},"outbounds":[{"protocol":"vless","settings":{"vnext":[{"address":"127.0.0.1","port":%d,"users":[{"id":"%s","encryption":"none"}]}]},"streamSettings":{"network":"xhttp","xhttpSettings":{"path":"/"}}}]}`, port, sharedCoreTestUUID)
	xclient, err := core.StartInstance("json", []byte(cfg))
	if err != nil {
		return false, "start vless client: " + err.Error()
	}
	defer xclient.Close()

	tr := origin.Client().Transport.(*http.Transport).Clone()
	tr.Proxy = nil
	tr.DialContext = func(ctx context.Context, network, addr string) (net.Conn, error) {
		dest, err := xnet.ParseDestination(network + ":" + addr)
		if err != nil {
			return nil, err
		}
		return core.Dial(ctx, xclient, dest)
	}
	tr.DisableKeepAlives = true
	defer tr.CloseIdleConnections()

	client := http.Client{Transport: tr, Timeout: 4 * time.Second}
	resp, err := client.Get(origin.URL)
	if err != nil {
		return false, err.Error()
	}
	defer resp.Body.Close()
	got, err := io.ReadAll(resp.Body)
	if err != nil {
		return false, fmt.Sprintf("read body: %v", err)
	}
	if resp.StatusCode != 200 || string(got) != sharedCoreTestBody {
		return false, fmt.Sprintf("status=%d body=%q", resp.StatusCode, got)
	}
	return true, fmt.Sprintf("status=%d body=%q", resp.StatusCode, got)
}

func sharedCoreOrigin(t *testing.T) *httptest.Server {
	t.Helper()
	origin := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, sharedCoreTestBody)
	}))
	t.Cleanup(origin.Close)
	return origin
}

func sharedCoreRequireWorks(t *testing.T, origin *httptest.Server, port int, label string) {
	t.Helper()
	ok, detail := sharedCoreTryHTTPS(origin, port)
	if !ok {
		t.Fatalf("%s: node on port %d unreachable through the shared core: %s", label, port, detail)
	}
	t.Logf("%s: node on port %d served the full HTTPS body (%s)", label, port, detail)
}

// TestSharedCoreDefaultOwnerCloseKeepsRemainingNodeServing covers the primary
// availability gap: the first controller owns the Xray default outbound. After
// it is closed, the remaining controller must keep serving through its own
// managed outbound. A custom outbound must never be promoted to default.
func TestSharedCoreDefaultOwnerCloseKeepsRemainingNodeServing(t *testing.T) {
	origin := sharedCoreOrigin(t)
	server := newRealControllerCore(t)
	manager := server.GetFeature(outbound.ManagerType()).(outbound.Manager)

	ports := sharedCoreDistinctPorts(t, 2)
	portA, portB := ports[0], ports[1]
	tagA := sharedCoreNodeTag(portA, 29)
	tagB := sharedCoreNodeTag(portB, 30)

	cA := sharedCoreStartController(t, server, sharedCorePanelNode(29, portA))
	// Register the custom outbound after the first controller so the first
	// node, not this fixture, becomes the default outbound.
	addVLESSGlobalEchoOutbound(t, server, "local-origin")
	sharedCoreStartController(t, server, sharedCorePanelNode(30, portB))

	ownerTag := sharedCoreDefaultTag(manager)
	t.Logf("setup owner_tag=%s registered=%v portA=%d portB=%d", ownerTag, sharedCoreRegisteredTags(manager), portA, portB)
	if ownerTag != tagA {
		t.Fatalf("setup: default outbound = %q, want the first controller tag %q", ownerTag, tagA)
	}

	sharedCoreRequireWorks(t, origin, portB, "baseline_remaining_node")

	if err := cA.Close(); err != nil {
		t.Fatalf("close default owner: %v", err)
	}
	postDefault := sharedCoreDefaultTag(manager)
	okAfterClose, detailAfterClose := sharedCoreTryHTTPS(origin, portB)
	t.Logf("after_owner_close default=%s registered=%v reachable=%v detail=%s", postDefault, sharedCoreRegisteredTags(manager), okAfterClose, detailAfterClose)
	if postDefault != tagB {
		t.Fatalf("after closing the default owner: default outbound = %q, want the remaining managed tag %q (custom local-origin must not be promoted)", postDefault, tagB)
	}
	if !okAfterClose {
		t.Fatalf("remaining node on port %d did not serve the full HTTPS body after owner close: %s", portB, detailAfterClose)
	}
}

// TestSharedCoreNonDefaultOwnerCloseKeepsDefault covers closing a controller
// that does not own the default outbound: ownership must not move.
func TestSharedCoreNonDefaultOwnerCloseKeepsDefault(t *testing.T) {
	origin := sharedCoreOrigin(t)
	server := newRealControllerCore(t)
	manager := server.GetFeature(outbound.ManagerType()).(outbound.Manager)

	ports := sharedCoreDistinctPorts(t, 2)
	portA, portB := ports[0], ports[1]
	tagA := sharedCoreNodeTag(portA, 29)
	tagB := sharedCoreNodeTag(portB, 30)

	sharedCoreStartController(t, server, sharedCorePanelNode(29, portA))
	addVLESSGlobalEchoOutbound(t, server, "local-origin")
	cB := sharedCoreStartController(t, server, sharedCorePanelNode(30, portB))

	if got := sharedCoreDefaultTag(manager); got != tagA {
		t.Fatalf("setup: default outbound = %q, want %q", got, tagA)
	}

	if err := cB.Close(); err != nil {
		t.Fatalf("close non-default controller: %v", err)
	}
	if got := sharedCoreDefaultTag(manager); got != tagA {
		t.Fatalf("after closing a non-default node: default outbound = %q, want unchanged %q", got, tagA)
	}
	if handler := manager.GetHandler(tagB); handler != nil {
		t.Fatalf("closed non-default node outbound %q is still registered", tagB)
	}
	sharedCoreRequireWorks(t, origin, portA, "default_owner_after_non_default_close")
}

// TestSharedCoreLastNodeCloseLeavesNoManagedDefault covers closing the only
// managed node: no handler remains to promote, and the custom outbound must
// not be selected as a replacement default.
func TestSharedCoreLastNodeCloseLeavesNoManagedDefault(t *testing.T) {
	server := newRealControllerCore(t)
	manager := server.GetFeature(outbound.ManagerType()).(outbound.Manager)

	portA := sharedCoreDistinctPorts(t, 1)[0]
	tagA := sharedCoreNodeTag(portA, 29)

	cA := sharedCoreStartController(t, server, sharedCorePanelNode(29, portA))
	addVLESSGlobalEchoOutbound(t, server, "local-origin")

	if got := sharedCoreDefaultTag(manager); got != tagA {
		t.Fatalf("setup: default outbound = %q, want %q", got, tagA)
	}

	if err := cA.Close(); err != nil {
		t.Fatalf("close last controller: %v", err)
	}
	if got := sharedCoreDefaultTag(manager); got != "<nil>" {
		t.Fatalf("after closing the last managed node: default outbound = %q, want no default (custom outbound must not be promoted)", got)
	}
	if handler := manager.GetHandler(tagA); handler != nil {
		t.Fatalf("closed last node outbound %q is still registered", tagA)
	}
	if handler := manager.GetHandler("local-origin"); handler == nil {
		t.Fatalf("custom outbound local-origin was removed while closing the managed node")
	}
}

// TestSharedCoreCustomOutboundDefaultIsNotReplaced covers a deployment with a
// custom outbound registered before any controller: it owns the default and
// closing a managed node must leave it in place.
func TestSharedCoreCustomOutboundDefaultIsNotReplaced(t *testing.T) {
	origin := sharedCoreOrigin(t)
	server := newRealControllerCore(t)
	manager := server.GetFeature(outbound.ManagerType()).(outbound.Manager)

	ports := sharedCoreDistinctPorts(t, 2)
	portA, portB := ports[0], ports[1]

	addVLESSGlobalEchoOutbound(t, server, "local-origin")
	cA := sharedCoreStartController(t, server, sharedCorePanelNode(29, portA))
	sharedCoreStartController(t, server, sharedCorePanelNode(30, portB))

	if got := sharedCoreDefaultTag(manager); got != "local-origin" {
		t.Fatalf("setup: default outbound = %q, want the custom local-origin", got)
	}

	if err := cA.Close(); err != nil {
		t.Fatalf("close managed node under custom default: %v", err)
	}
	if got := sharedCoreDefaultTag(manager); got != "local-origin" {
		t.Fatalf("after closing a managed node: default outbound = %q, want the custom local-origin unchanged", got)
	}
	sharedCoreRequireWorks(t, origin, portB, "remaining_node_under_custom_default")
}

// TestSharedCoreDefaultOwnerFailedReplaceRollbackKeepsNodesReachable covers a
// failed replacement of the default owner (occupied port) followed by rollback:
// the owner keeps the default and both nodes stay reachable.
func TestSharedCoreDefaultOwnerFailedReplaceRollbackKeepsNodesReachable(t *testing.T) {
	origin := sharedCoreOrigin(t)
	server := newRealControllerCore(t)
	manager := server.GetFeature(outbound.ManagerType()).(outbound.Manager)

	ports := sharedCoreDistinctPorts(t, 2)
	portA, portB := ports[0], ports[1]
	tagA := sharedCoreNodeTag(portA, 29)

	panelA := sharedCorePanelNode(29, portA)
	cA := sharedCoreStartController(t, server, panelA)
	addVLESSGlobalEchoOutbound(t, server, "local-origin")
	sharedCoreStartController(t, server, sharedCorePanelNode(30, portB))

	if got := sharedCoreDefaultTag(manager); got != tagA {
		t.Fatalf("setup: default outbound = %q, want %q", got, tagA)
	}

	occupied, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("reserve occupied port: %v", err)
	}
	defer occupied.Close()
	occupiedPort := occupied.Addr().(*net.TCPAddr).Port
	if occupiedPort == portA {
		t.Fatalf("setup: occupied port equals current owner port")
	}

	panelA.node.Port = uint32(occupiedPort)
	if err := cA.SyncNodeConfigForTest(context.Background()); err == nil {
		t.Fatalf("setup: occupied-port replacement unexpectedly succeeded")
	}
	panelA.node.Port = uint32(portA)

	if got := sharedCoreDefaultTag(manager); got != tagA {
		t.Fatalf("after failed replace rollback: default outbound = %q, want restored owner %q", got, tagA)
	}
	sharedCoreRequireWorks(t, origin, portA, "default_owner_after_rollback")
	sharedCoreRequireWorks(t, origin, portB, "other_node_after_rollback")
}
