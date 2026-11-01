package api_test

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"reflect"
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
	_ api.ContextPanelClient           = (*bunpanel.APIClient)(nil)
	_ api.ContextPanelClient           = (*gov2panel.APIClient)(nil)
	_ api.ContextPanelClient           = (*newV2board.APIClient)(nil)
	_ api.ContextPanelClient           = (*pmpanel.APIClient)(nil)
	_ api.ContextPanelClient           = (*proxypanel.APIClient)(nil)
	_ api.ContextPanelClient           = (*sspanel.APIClient)(nil)
	_ api.ContextPanelClient           = (*v2raysocks.APIClient)(nil)
	_ api.NodeSnapshotProvider         = (*bunpanel.APIClient)(nil)
	_ api.NodeSnapshotProvider         = (*gov2panel.APIClient)(nil)
	_ api.NodeSnapshotProvider         = (*newV2board.APIClient)(nil)
	_ api.NodeSnapshotProvider         = (*pmpanel.APIClient)(nil)
	_ api.NodeSnapshotProvider         = (*proxypanel.APIClient)(nil)
	_ api.NodeSnapshotProvider         = (*sspanel.APIClient)(nil)
	_ api.NodeSnapshotProvider         = (*v2raysocks.APIClient)(nil)
	_ api.ContextNodeSnapshotProvider  = (*bunpanel.APIClient)(nil)
	_ api.ContextNodeSnapshotProvider  = (*gov2panel.APIClient)(nil)
	_ api.ContextNodeSnapshotProvider  = (*newV2board.APIClient)(nil)
	_ api.ContextNodeSnapshotProvider  = (*pmpanel.APIClient)(nil)
	_ api.ContextNodeSnapshotProvider  = (*proxypanel.APIClient)(nil)
	_ api.ContextNodeSnapshotProvider  = (*sspanel.APIClient)(nil)
	_ api.ContextNodeSnapshotProvider  = (*v2raysocks.APIClient)(nil)
	_ api.AliveSnapshotProvider        = (*newV2board.APIClient)(nil)
	_ api.ContextAliveSnapshotProvider = (*newV2board.APIClient)(nil)
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

type aliveListClient struct {
	alive map[int][]string
	err   error
}

func (client aliveListClient) GetAliveList() (map[int][]string, error) {
	return client.alive, client.err
}

func TestGetAliveSnapshotContextClonesLegacyIPLists(t *testing.T) {
	source := map[int][]string{1: {"192.0.2.1"}, 2: {}, 3: nil}
	got, err := api.GetAliveSnapshotContext(context.Background(), aliveListClient{alive: source})
	if err != nil {
		t.Fatalf("GetAliveSnapshotContext() error = %v", err)
	}
	if got == nil || !reflect.DeepEqual(got.IPs, source) || got.Counts != nil {
		t.Fatalf("snapshot = %#v, want legacy IP lists without counts", got)
	}
	got.IPs[1][0] = "192.0.2.2"
	delete(got.IPs, 2)
	if source[1][0] != "192.0.2.1" || source[2] == nil {
		t.Fatalf("provider-owned IP list changed through returned snapshot: %#v", source)
	}
}

type aliveSnapshotClient struct {
	aliveListClient
	snapshot *api.AliveSnapshot
	err      error
}

func (client aliveSnapshotClient) GetAliveSnapshot() (*api.AliveSnapshot, error) {
	return client.snapshot, client.err
}

func TestGetAliveSnapshotContextPrefersTypedSnapshot(t *testing.T) {
	source := &api.AliveSnapshot{
		IPs:    map[int][]string{2: {"192.0.2.2"}},
		Counts: map[int]int{1: 3},
	}
	client := aliveSnapshotClient{
		aliveListClient: aliveListClient{err: errors.New("legacy capability must not be used")},
		snapshot:        source,
	}
	got, err := api.GetAliveSnapshotContext(nil, client)
	if err != nil {
		t.Fatalf("GetAliveSnapshotContext() error = %v", err)
	}
	if got == source || !reflect.DeepEqual(got, source) {
		t.Fatalf("snapshot = %#v, want detached %#v", got, source)
	}
	got.IPs[2][0] = "192.0.2.3"
	got.Counts[1] = 4
	if source.IPs[2][0] != "192.0.2.2" || source.Counts[1] != 3 {
		t.Fatalf("provider-owned snapshot changed through returned value: %#v", source)
	}
}

type aliveSnapshotContextClient struct {
	aliveSnapshotClient
	result *api.AliveSnapshot
	call   func(context.Context) error
}

func (client aliveSnapshotContextClient) GetAliveSnapshotContext(ctx context.Context) (*api.AliveSnapshot, error) {
	return client.result, client.call(ctx)
}

func TestGetAliveSnapshotContextPrefersContextualSnapshot(t *testing.T) {
	source := &api.AliveSnapshot{Counts: map[int]int{1: 2}}
	type contextKey struct{}
	ctx := context.WithValue(context.Background(), contextKey{}, "request")
	client := aliveSnapshotContextClient{
		aliveSnapshotClient: aliveSnapshotClient{err: errors.New("non-contextual capability must not be used")},
		result:              source,
		call: func(got context.Context) error {
			if got.Value(contextKey{}) != "request" {
				t.Fatal("request context was not forwarded")
			}
			return nil
		},
	}
	got, err := api.GetAliveSnapshotContext(ctx, client)
	if err != nil || !reflect.DeepEqual(got, source) {
		t.Fatalf("GetAliveSnapshotContext() = %#v, %v; want %#v, nil", got, err, source)
	}
	got.Counts[1] = 3
	if source.Counts[1] != 2 {
		t.Fatal("contextual provider result was not detached")
	}
}

type aliveListContextClient struct {
	aliveListClient
	call func(context.Context) (map[int][]string, error)
}

func (client aliveListContextClient) GetAliveListContext(ctx context.Context) (map[int][]string, error) {
	return client.call(ctx)
}

func TestGetAliveSnapshotContextFallsBackToContextualIPLists(t *testing.T) {
	client := aliveListContextClient{
		aliveListClient: aliveListClient{err: errors.New("non-contextual legacy capability must not be used")},
		call: func(context.Context) (map[int][]string, error) {
			return map[int][]string{1: {"192.0.2.1"}}, nil
		},
	}
	got, err := api.GetAliveSnapshotContext(context.Background(), client)
	want := &api.AliveSnapshot{IPs: map[int][]string{1: {"192.0.2.1"}}}
	if err != nil || !reflect.DeepEqual(got, want) {
		t.Fatalf("GetAliveSnapshotContext() = %#v, %v; want %#v, nil", got, err, want)
	}
}

func TestGetAliveSnapshotContextPreservesCapabilityOutcomes(t *testing.T) {
	providerErr := errors.New("panel unavailable")
	for _, test := range []struct {
		name     string
		provider any
		want     *api.AliveSnapshot
		wantErr  error
	}{
		{name: "unsupported", provider: struct{}{}, wantErr: api.ErrUnsupportedPanelFeature},
		{name: "legacy absent", provider: aliveListClient{}},
		{name: "legacy empty", provider: aliveListClient{alive: map[int][]string{}}, want: &api.AliveSnapshot{IPs: map[int][]string{}}},
		{name: "typed absent", provider: aliveSnapshotClient{}},
		{name: "typed empty", provider: aliveSnapshotClient{snapshot: &api.AliveSnapshot{}}, want: &api.AliveSnapshot{}},
		{name: "legacy error", provider: aliveListClient{alive: map[int][]string{1: {}}, err: providerErr}, wantErr: providerErr},
		{name: "typed error does not fall back", provider: aliveSnapshotClient{
			aliveListClient: aliveListClient{alive: map[int][]string{1: {"192.0.2.1"}}},
			snapshot:        &api.AliveSnapshot{Counts: map[int]int{1: 3}}, err: providerErr,
		}, wantErr: providerErr},
	} {
		t.Run(test.name, func(t *testing.T) {
			got, err := api.GetAliveSnapshotContext(context.Background(), test.provider)
			if !errors.Is(err, test.wantErr) || !reflect.DeepEqual(got, test.want) {
				t.Fatalf("GetAliveSnapshotContext() = %#v, %v; want %#v, %v", got, err, test.want, test.wantErr)
			}
		})
	}
}

func TestGetAliveSnapshotContextHonorsCancellation(t *testing.T) {
	t.Run("before provider call", func(t *testing.T) {
		ctx, cancel := context.WithCancel(context.Background())
		cancel()
		client := aliveSnapshotContextClient{call: func(context.Context) error {
			t.Fatal("canceled request reached provider")
			return nil
		}}
		got, err := api.GetAliveSnapshotContext(ctx, client)
		if got != nil || !errors.Is(err, context.Canceled) {
			t.Fatalf("GetAliveSnapshotContext() = %#v, %v; want nil, context.Canceled", got, err)
		}
	})
	for _, contextual := range []bool{false, true} {
		name := "contextual legacy list"
		if contextual {
			name = "contextual snapshot"
		}
		t.Run("after "+name+" provider returns", func(t *testing.T) {
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			var client any = aliveListContextClient{call: func(context.Context) (map[int][]string, error) {
				cancel()
				return map[int][]string{1: {"192.0.2.1"}}, nil
			}}
			if contextual {
				client = aliveSnapshotContextClient{
					result: &api.AliveSnapshot{Counts: map[int]int{1: 2}},
					call: func(context.Context) error {
						cancel()
						return nil
					},
				}
			}
			got, err := api.GetAliveSnapshotContext(ctx, client)
			if got != nil || !errors.Is(err, context.Canceled) {
				t.Fatalf("GetAliveSnapshotContext() = %#v, %v; want nil, context.Canceled", got, err)
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
