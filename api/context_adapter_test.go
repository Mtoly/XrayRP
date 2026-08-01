package api_test

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/Mtoly/XrayRP/api"
	"github.com/Mtoly/XrayRP/api/bunpanel"
	"github.com/Mtoly/XrayRP/api/gov2panel"
	"github.com/Mtoly/XrayRP/api/newV2board"
	"github.com/Mtoly/XrayRP/api/pmpanel"
	"github.com/Mtoly/XrayRP/api/proxypanel"
	"github.com/Mtoly/XrayRP/api/sspanel"
	"github.com/Mtoly/XrayRP/api/v2raysocks"
)

var (
	_ api.ContextPanelClient = (*bunpanel.APIClient)(nil)
	_ api.ContextPanelClient = (*gov2panel.APIClient)(nil)
	_ api.ContextPanelClient = (*newV2board.APIClient)(nil)
	_ api.ContextPanelClient = (*pmpanel.APIClient)(nil)
	_ api.ContextPanelClient = (*proxypanel.APIClient)(nil)
	_ api.ContextPanelClient = (*sspanel.APIClient)(nil)
	_ api.ContextPanelClient = (*v2raysocks.APIClient)(nil)
)

type nodeInfoClient interface {
	GetNodeInfo() (*api.NodeInfo, error)
}

func TestPanelAdaptersCancelInFlightRESTRequests(t *testing.T) {
	tests := []struct {
		name string
		new  func(string) nodeInfoClient
	}{
		{name: "BunPanel", new: func(host string) nodeInfoClient {
			return bunpanel.New(&api.Config{APIHost: host, NodeID: 1, NodeType: "V2ray"})
		}},
		{name: "GoV2Panel", new: func(host string) nodeInfoClient {
			return gov2panel.New(&api.Config{APIHost: host, NodeID: 1, NodeType: "V2ray"})
		}},
		{name: "NewV2board", new: func(host string) nodeInfoClient {
			return newV2board.New(&api.Config{APIHost: host, NodeID: 1, NodeType: "V2ray"})
		}},
		{name: "PMPanel", new: func(host string) nodeInfoClient {
			return pmpanel.New(&api.Config{APIHost: host, NodeID: 1, NodeType: "V2ray"})
		}},
		{name: "ProxyPanel", new: func(host string) nodeInfoClient {
			return proxypanel.New(&api.Config{APIHost: host, NodeID: 1, NodeType: "V2ray"})
		}},
		{name: "SSPanel", new: func(host string) nodeInfoClient {
			return sspanel.New(&api.Config{APIHost: host, NodeID: 1, NodeType: "V2ray", DisableCustomConfig: true})
		}},
		{name: "V2RaySocks", new: func(host string) nodeInfoClient {
			return v2raysocks.New(&api.Config{APIHost: host, NodeID: 1, NodeType: "V2ray"})
		}},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			entered := make(chan struct{}, 1)
			release := make(chan struct{})
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				select {
				case entered <- struct{}{}:
				default:
				}
				select {
				case <-r.Context().Done():
				case <-release:
				}
			}))
			defer func() {
				close(release)
				server.Close()
			}()

			client := test.new(server.URL)
			ctx, cancel := context.WithCancel(context.Background())
			result := make(chan error, 1)
			go func() {
				_, err := api.GetNodeInfoContext(ctx, client)
				result <- err
			}()

			select {
			case <-entered:
			case <-time.After(2 * time.Second):
				t.Fatal("request did not reach the test server")
			}
			cancel()

			select {
			case err := <-result:
				if !errors.Is(err, context.Canceled) {
					t.Fatalf("GetNodeInfoContext() error = %v, want context cancellation", err)
				}
			case <-time.After(2 * time.Second):
				t.Fatal("in-flight REST request ignored cancellation")
			}
		})
	}
}
