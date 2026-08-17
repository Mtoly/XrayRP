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
	_ api.ContextPanelClient          = (*bunpanel.APIClient)(nil)
	_ api.ContextPanelClient          = (*gov2panel.APIClient)(nil)
	_ api.ContextPanelClient          = (*newV2board.APIClient)(nil)
	_ api.ContextPanelClient          = (*pmpanel.APIClient)(nil)
	_ api.ContextPanelClient          = (*proxypanel.APIClient)(nil)
	_ api.ContextPanelClient          = (*sspanel.APIClient)(nil)
	_ api.ContextPanelClient          = (*v2raysocks.APIClient)(nil)
	_ api.NodeSnapshotProvider        = (*bunpanel.APIClient)(nil)
	_ api.NodeSnapshotProvider        = (*gov2panel.APIClient)(nil)
	_ api.NodeSnapshotProvider        = (*newV2board.APIClient)(nil)
	_ api.NodeSnapshotProvider        = (*pmpanel.APIClient)(nil)
	_ api.NodeSnapshotProvider        = (*proxypanel.APIClient)(nil)
	_ api.NodeSnapshotProvider        = (*sspanel.APIClient)(nil)
	_ api.NodeSnapshotProvider        = (*v2raysocks.APIClient)(nil)
	_ api.ContextNodeSnapshotProvider = (*bunpanel.APIClient)(nil)
	_ api.ContextNodeSnapshotProvider = (*gov2panel.APIClient)(nil)
	_ api.ContextNodeSnapshotProvider = (*newV2board.APIClient)(nil)
	_ api.ContextNodeSnapshotProvider = (*pmpanel.APIClient)(nil)
	_ api.ContextNodeSnapshotProvider = (*proxypanel.APIClient)(nil)
	_ api.ContextNodeSnapshotProvider = (*sspanel.APIClient)(nil)
	_ api.ContextNodeSnapshotProvider = (*v2raysocks.APIClient)(nil)
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

type snapshotContextClient struct {
	snapshot *api.NodeSnapshot
	entered  chan struct{}
	release  chan struct{}
}

func (client *snapshotContextClient) GetNodeInfo() (*api.NodeInfo, error) {
	return client.snapshot.ToNodeInfo(), nil
}

func (client *snapshotContextClient) GetNodeSnapshotContext(context.Context) (*api.NodeSnapshot, error) {
	if client.entered != nil {
		close(client.entered)
	}
	if client.release != nil {
		<-client.release
	}
	return client.snapshot, nil
}

func TestGetNodeSnapshotContextClonesContextualProviderResult(t *testing.T) {
	source := &api.NodeSnapshot{
		Port:   443,
		Header: []byte(`{"type":"http"}`),
		NameServers: []*api.NameServerSnapshot{{
			Address: "1.1.1.1",
		}},
	}
	client := &snapshotContextClient{snapshot: source}

	got, err := api.GetNodeSnapshotContext(context.Background(), client)
	if err != nil {
		t.Fatalf("GetNodeSnapshotContext() error = %v", err)
	}
	if got == source {
		t.Fatal("contextual provider result was returned without cloning")
	}
	got.Header[0] = '['
	got.NameServers[0].Address = "8.8.8.8"
	if string(source.Header) != `{"type":"http"}` || source.NameServers[0].Address != "1.1.1.1" {
		t.Fatalf("provider-owned snapshot changed through returned value: %#v", source)
	}
}

func TestGetNodeSnapshotContextChecksCancellationAfterContextualProviderReturns(t *testing.T) {
	client := &snapshotContextClient{
		snapshot: &api.NodeSnapshot{Port: 443},
		entered:  make(chan struct{}),
		release:  make(chan struct{}),
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	result := make(chan error, 1)
	go func() {
		_, err := api.GetNodeSnapshotContext(ctx, client)
		result <- err
	}()
	<-client.entered
	cancel()
	close(client.release)
	if err := <-result; !errors.Is(err, context.Canceled) {
		t.Fatalf("GetNodeSnapshotContext() error = %v, want context cancellation", err)
	}
}

type lateLegacyNodeClient struct {
	node    *api.NodeInfo
	entered chan struct{}
	release chan struct{}
}

func (client *lateLegacyNodeClient) GetNodeInfo() (*api.NodeInfo, error) {
	return client.node, nil
}

func (client *lateLegacyNodeClient) GetNodeInfoContext(context.Context) (*api.NodeInfo, error) {
	close(client.entered)
	<-client.release
	return client.node, nil
}

func TestGetNodeSnapshotContextChecksCancellationAfterLegacyProviderReturns(t *testing.T) {
	client := &lateLegacyNodeClient{
		node:    &api.NodeInfo{Port: 443},
		entered: make(chan struct{}),
		release: make(chan struct{}),
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	result := make(chan error, 1)
	go func() {
		_, err := api.GetNodeSnapshotContext(ctx, client)
		result <- err
	}()
	<-client.entered
	cancel()
	close(client.release)
	if err := <-result; !errors.Is(err, context.Canceled) {
		t.Fatalf("GetNodeSnapshotContext() legacy error = %v, want context cancellation", err)
	}
}
