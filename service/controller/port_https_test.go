package controller_test

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

func TestPortUpdatePreservesHTTPS(t *testing.T) {
	const id = "1b4e28ba-2fa1-11d2-883f-0016d3cca427"
	const body = "port-update-response"
	origin := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { fmt.Fprint(w, body) }))
	defer origin.Close()
	finalPort := reserveLoopbackPort(t)
	for _, hot := range []bool{true, false} {
		name := "cold"
		if hot {
			name = "hot"
		}
		t.Run(name, func(t *testing.T) {
			port := finalPort
			if hot {
				for port == finalPort {
					port = reserveLoopbackPort(t)
				}
			}
			server := newRealControllerCore(t)
			manager := server.GetFeature(outbound.ManagerType()).(outbound.Manager)
			panel := &realCorePanelClient{node: api.NodeInfo{
				NodeID: 29, NodeType: "Vless", EnableVless: true, TransportProtocol: "xhttp", Port: uint32(port),
				RoutePolicy: &api.PanelRoutePolicy{Outbound: api.OutboundFilterPolicy{Candidates: []string{"local-origin"}}},
			}, users: []api.UserInfo{{UID: 1, Email: "test@example.test", UUID: id}}}
			c := controller.New(server, panel, &controller.Config{ListenIP: "127.0.0.1", SendIP: "0.0.0.0", UpdatePeriodic: 3600, DisableGetRule: true, DisableSniffing: true}, "test")
			if err := c.Start(); err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() {
				if err := c.Close(); err != nil {
					t.Error(err)
				}
			})
			// Register after startup so the node, not the loopback fixture, is default.
			addVLESSGlobalEchoOutbound(t, server, "local-origin")
			check := func(t *testing.T, port int) {
				t.Helper()
				tag := "<nil>"
				if h := manager.GetDefaultHandler(); h != nil {
					tag = h.Tag()
				}
				var registered []string
				for _, h := range manager.ListHandlers(t.Context()) {
					registered = append(registered, h.Tag())
				}
				t.Logf("port=%d default=%s registered=%v", port, tag, registered)
				cfg := fmt.Sprintf(`{"log":{"loglevel":"none"},"outbounds":[{"protocol":"vless","settings":{"vnext":[{"address":"127.0.0.1","port":%d,"users":[{"id":"%s","encryption":"none"}]}]},"streamSettings":{"network":"xhttp","xhttpSettings":{"path":"/"}}}]}`, port, id)
				xclient, err := core.StartInstance("json", []byte(cfg))
				if err != nil {
					t.Fatal(err)
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
				client := http.Client{Transport: tr, Timeout: 3 * time.Second}
				resp, err := client.Get(origin.URL)
				if err != nil {
					t.Fatal(err)
				}
				defer resp.Body.Close()
				got, err := io.ReadAll(resp.Body)
				if err != nil || resp.StatusCode != 200 || string(got) != body {
					t.Fatalf("status=%d body=%q err=%v", resp.StatusCode, got, err)
				}
				t.Logf("verified HTTPS status=200 body=%q", got)
			}
			check(t, port)
			if hot {
				panel.node.Port = uint32(finalPort)
				if err := c.SyncPortForTest(t.Context()); err != nil {
					t.Fatal(err)
				}
				check(t, finalPort)
				t.Run("occupied_port", func(t *testing.T) {
					occupied, err := net.Listen("tcp4", "127.0.0.1:0")
					if err != nil {
						t.Fatal(err)
					}
					defer occupied.Close()
					panel.node.Port = uint32(occupied.Addr().(*net.TCPAddr).Port)
					if err := c.SyncPortForTest(t.Context()); err == nil {
						t.Fatal("occupied port accepted")
					}
					panel.node.Port = uint32(finalPort)
					check(t, finalPort)
				})
				t.Run("non_default_node", func(t *testing.T) {
					owner := manager.GetDefaultHandler()
					if owner == nil {
						t.Fatal("missing default before secondary node update")
					}
					secondary := &realCorePanelClient{node: panel.node, users: panel.users}
					secondary.node.NodeID = 30
					secondary.node.Port = uint32(reserveLoopbackPort(t))
					other := controller.New(server, secondary, &controller.Config{ListenIP: "127.0.0.1", SendIP: "0.0.0.0", UpdatePeriodic: 3600, DisableGetRule: true, DisableSniffing: true}, "test")
					if err := other.Start(); err != nil {
						t.Fatal(err)
					}
					t.Cleanup(func() {
						if err := other.Close(); err != nil {
							t.Error(err)
						}
					})
					secondary.node.Port = uint32(reserveLoopbackPort(t))
					if err := other.SyncPortForTest(t.Context()); err != nil {
						t.Fatal(err)
					}
					if manager.GetDefaultHandler() != owner {
						t.Fatal("secondary node replaced the default outbound")
					}
					check(t, int(secondary.node.Port))
				})
			}
		})
	}
}
