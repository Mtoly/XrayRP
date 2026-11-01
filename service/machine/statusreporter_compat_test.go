package machine

import (
	"context"
	"errors"
	"fmt"
	"reflect"
	"testing"

	"github.com/Mtoly/XrayRP/api"
)

var (
	_ func(PanelClient, int, any) PanelClient                = WrapAPIWithReporter
	_ func(PanelClient, int, NodeStatusReporter) PanelClient = WrapAPIWithStatusReporter
)

type legacyReportingAliveSnapshotStub struct {
	*statusReporterPanelClientStub
	snapshot      *api.AliveSnapshot
	snapshotErr   error
	snapshotCalls int
	contextValue  any
	call          func(context.Context) error
}

func (c *legacyReportingAliveSnapshotStub) GetAliveSnapshotContext(ctx context.Context) (*api.AliveSnapshot, error) {
	c.snapshotCalls++
	c.contextValue = ctx.Value(statusReporterAliveContextKey{})
	if c.call != nil {
		if err := c.call(ctx); err != nil {
			return c.snapshot, err
		}
	}
	return c.snapshot, c.snapshotErr
}

func TestLegacyReportingAPIForwardsTypedAliveSnapshot(t *testing.T) {
	sourceSnapshot := &api.AliveSnapshot{
		IPs:    map[int][]string{2: {"192.0.2.2"}},
		Counts: map[int]int{1: 3},
	}
	source := &legacyReportingAliveSnapshotStub{
		statusReporterPanelClientStub: &statusReporterPanelClientStub{},
		snapshot:                      sourceSnapshot,
	}
	wrapped := WrapAPIWithReporter(source, 9, &statusReporterStub{})
	snapshotProvider, ok := wrapped.(api.AliveSnapshotProvider)
	if !ok {
		t.Fatal("legacy reporting wrapper did not expose typed alive snapshots")
	}

	snapshot, err := snapshotProvider.GetAliveSnapshot()
	if err != nil {
		t.Fatalf("GetAliveSnapshot() error = %v", err)
	}
	if !reflect.DeepEqual(snapshot, sourceSnapshot) || snapshot == sourceSnapshot {
		t.Fatalf("GetAliveSnapshot() = %#v, want detached %#v", snapshot, sourceSnapshot)
	}
	if source.snapshotCalls != 1 || source.contextValue != nil {
		t.Fatalf("non-contextual call = calls:%d value:%v", source.snapshotCalls, source.contextValue)
	}
	snapshot.Counts[1] = 4
	if sourceSnapshot.Counts[1] != 3 {
		t.Fatal("legacy reporting wrapper leaked snapshot mutation to source")
	}

	ctx := context.WithValue(context.Background(), statusReporterAliveContextKey{}, "request")
	contextualProvider, ok := wrapped.(api.ContextAliveSnapshotProvider)
	if !ok {
		t.Fatal("legacy reporting wrapper did not expose contextual typed alive snapshots")
	}
	snapshot, err = contextualProvider.GetAliveSnapshotContext(ctx)
	if err != nil {
		t.Fatalf("GetAliveSnapshotContext() error = %v", err)
	}
	if source.snapshotCalls != 2 || source.contextValue != "request" {
		t.Fatalf("context forwarding = calls:%d value:%v", source.snapshotCalls, source.contextValue)
	}
	if !reflect.DeepEqual(snapshot, sourceSnapshot) || snapshot == sourceSnapshot {
		t.Fatalf("GetAliveSnapshotContext() = %#v, want detached %#v", snapshot, sourceSnapshot)
	}
}

func TestLegacyReportingAPIAliveSnapshotOutcomes(t *testing.T) {
	providerErr := errors.New("alive snapshot unavailable")
	t.Run("unsupported", func(t *testing.T) {
		wrapped := WrapAPIWithReporter(&statusReporterPanelClientStub{}, 9, &statusReporterStub{})
		snapshot, err := wrapped.(api.AliveSnapshotProvider).GetAliveSnapshot()
		if snapshot != nil || !errors.Is(err, api.ErrUnsupportedPanelFeature) {
			t.Fatalf("GetAliveSnapshot() = %#v, %v; want nil, unsupported", snapshot, err)
		}
	})
	t.Run("typed nil", func(t *testing.T) {
		source := &legacyReportingAliveSnapshotStub{
			statusReporterPanelClientStub: &statusReporterPanelClientStub{},
		}
		wrapped := WrapAPIWithReporter(source, 9, &statusReporterStub{})
		snapshot, err := wrapped.(api.AliveSnapshotProvider).GetAliveSnapshot()
		if snapshot != nil || err != nil {
			t.Fatalf("GetAliveSnapshot() = %#v, %v; want nil, nil", snapshot, err)
		}
	})
	t.Run("typed empty", func(t *testing.T) {
		source := &legacyReportingAliveSnapshotStub{
			statusReporterPanelClientStub: &statusReporterPanelClientStub{},
			snapshot:                      &api.AliveSnapshot{},
		}
		wrapped := WrapAPIWithReporter(source, 9, &statusReporterStub{})
		snapshot, err := wrapped.(api.AliveSnapshotProvider).GetAliveSnapshot()
		if err != nil || !reflect.DeepEqual(snapshot, &api.AliveSnapshot{}) {
			t.Fatalf("GetAliveSnapshot() = %#v, %v; want empty snapshot, nil", snapshot, err)
		}
	})
	t.Run("typed error", func(t *testing.T) {
		source := &legacyReportingAliveSnapshotStub{
			statusReporterPanelClientStub: &statusReporterPanelClientStub{},
			snapshot:                      &api.AliveSnapshot{Counts: map[int]int{1: 2}},
			snapshotErr:                   providerErr,
		}
		wrapped := WrapAPIWithReporter(source, 9, &statusReporterStub{})
		snapshot, err := wrapped.(api.AliveSnapshotProvider).GetAliveSnapshot()
		if snapshot != nil || !errors.Is(err, providerErr) || source.snapshotCalls != 1 {
			t.Fatalf("GetAliveSnapshot() = %#v, %v; calls:%d", snapshot, err, source.snapshotCalls)
		}
	})
	t.Run("canceled before provider", func(t *testing.T) {
		source := &legacyReportingAliveSnapshotStub{
			statusReporterPanelClientStub: &statusReporterPanelClientStub{},
			snapshot:                      &api.AliveSnapshot{Counts: map[int]int{1: 2}},
		}
		wrapped := WrapAPIWithReporter(source, 9, &statusReporterStub{})
		ctx, cancel := context.WithCancel(context.Background())
		cancel()
		snapshot, err := wrapped.(api.ContextAliveSnapshotProvider).GetAliveSnapshotContext(ctx)
		if snapshot != nil || !errors.Is(err, context.Canceled) || source.snapshotCalls != 0 {
			t.Fatalf("GetAliveSnapshotContext() = %#v, %v; calls:%d", snapshot, err, source.snapshotCalls)
		}
	})
	t.Run("canceled after provider returns", func(t *testing.T) {
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		source := &legacyReportingAliveSnapshotStub{
			statusReporterPanelClientStub: &statusReporterPanelClientStub{},
			snapshot:                      &api.AliveSnapshot{Counts: map[int]int{1: 2}},
			call: func(context.Context) error {
				cancel()
				return nil
			},
		}
		wrapped := WrapAPIWithReporter(source, 9, &statusReporterStub{})
		snapshot, err := wrapped.(api.ContextAliveSnapshotProvider).GetAliveSnapshotContext(ctx)
		if snapshot != nil || !errors.Is(err, context.Canceled) || source.snapshotCalls != 1 {
			t.Fatalf("GetAliveSnapshotContext() = %#v, %v; calls:%d", snapshot, err, source.snapshotCalls)
		}
	})
	t.Run("legacy list fallback", func(t *testing.T) {
		source := &statusReporterAliveCapableStub{
			statusReporterPanelClientStub: &statusReporterPanelClientStub{},
			aliveList: map[int][]string{
				1: {"192.0.2.1", "2001:db8::1"},
				2: {},
			},
		}
		wrapped := WrapAPIWithReporter(source, 9, &statusReporterStub{})
		snapshot, err := wrapped.(api.AliveSnapshotProvider).GetAliveSnapshot()
		want := &api.AliveSnapshot{IPs: source.aliveList}
		if err != nil || !reflect.DeepEqual(snapshot, want) {
			t.Fatalf("GetAliveSnapshot() = %#v, %v; want %#v, nil", snapshot, err, want)
		}
		snapshot.IPs[1][0] = "192.0.2.2"
		if source.aliveList[1][0] != "192.0.2.1" {
			t.Fatal("legacy list fallback leaked snapshot mutation to source")
		}
	})
}

func TestLegacyReporterWrapperPreservesPartialCapabilities(t *testing.T) {
	wsConfig := &api.WSConfig{NodeID: 9}
	client := &statusReporterWSCapableStub{
		statusReporterPanelClientStub: &statusReporterPanelClientStub{},
		wsConfig:                      wsConfig,
	}

	wrapped := WrapAPIWithReporter(client, 9, &statusReporterStub{})

	wsProvider, ok := wrapped.(api.WSCapable)
	if !ok || wsProvider.GetWSConfig() != wsConfig {
		t.Fatal("legacy reporter wrapper did not preserve websocket config capability")
	}
	if _, ok := wrapped.(api.WSEndpointDiscoverer); ok {
		t.Fatal("legacy reporter wrapper fabricated websocket endpoint capability")
	}

}
func TestLegacyReportingAPIExhaustivelyPreservesCapabilityMethodSets(t *testing.T) {
	source := &statusReporterAllCapableStub{
		statusReporterCertAliveCapableStub: &statusReporterCertAliveCapableStub{
			statusReporterPanelClientStub: &statusReporterPanelClientStub{},
		},
	}
	allCapabilities := panelCapabilities{
		wsConfig:   source,
		wsEndpoint: source,
		baseConfig: source,
		certConfig: source,
		aliveList:  source,
	}

	for mask := 0; mask < 1<<5; mask++ {
		t.Run(fmt.Sprintf("mask_%02d", mask), func(t *testing.T) {
			capabilities := allCapabilities
			capabilities.mask = mask
			wrapped := wrapReportingAPIWithCapabilities(
				&reportingAPI{PanelClient: &statusReporterPanelClientStub{}},
				capabilities,
			)

			assertCapability := func(name string, capabilityMask int, present bool) {
				t.Helper()
				want := mask&capabilityMask != 0
				if present != want {
					t.Fatalf("%s presence = %t, want %t for mask %05b", name, present, want, mask)
				}
			}
			_, hasWSConfig := wrapped.(api.WSCapable)
			assertCapability("websocket config", hasWSConfigCapability, hasWSConfig)
			_, hasWSEndpoint := wrapped.(api.WSEndpointDiscoverer)
			assertCapability("websocket endpoint", hasWSEndpointCapability, hasWSEndpoint)
			_, hasBaseConfig := wrapped.(api.BaseConfigProvider)
			assertCapability("base config", hasBaseConfigCapability, hasBaseConfig)
			_, hasCertConfig := wrapped.(api.CertConfigProvider)
			assertCapability("certificate config", hasCertConfigCapability, hasCertConfig)
			_, hasAliveList := wrapped.(api.AliveListProvider)
			assertCapability("alive list", hasAliveListCapability, hasAliveList)
		})
	}
}
