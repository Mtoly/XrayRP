package panel

import (
	"fmt"
	"reflect"
	"sort"
	"strings"
	"testing"

	"github.com/Mtoly/XrayRP/api"
)

func TestPanelAdapterRegistryPreservesStaticAliases(t *testing.T) {
	tests := []struct {
		panelType string
		wantType  string
	}{
		{panelType: "SSpanel", wantType: "*sspanel.APIClient"},
		{panelType: "SSPanel", wantType: "*sspanel.APIClient"},
		{panelType: "NewV2board", wantType: "*newV2board.APIClient"},
		{panelType: "V2board", wantType: "*newV2board.APIClient"},
		{panelType: "PMpanel", wantType: "*pmpanel.APIClient"},
		{panelType: "Proxypanel", wantType: "*proxypanel.APIClient"},
		{panelType: "V2RaySocks", wantType: "*v2raysocks.APIClient"},
		{panelType: "GoV2Panel", wantType: "*gov2panel.APIClient"},
		{panelType: "BunPanel", wantType: "*bunpanel.APIClient"},
	}

	registry := defaultPanelAdapterRegistry()
	for _, test := range tests {
		t.Run(test.panelType, func(t *testing.T) {
			factory, err := registry.staticFactory(test.panelType)
			if err != nil {
				t.Fatal(err)
			}
			if got := fmt.Sprintf("%T", factory(&api.Config{})); got != test.wantType {
				t.Fatalf("client type = %q, want %q", got, test.wantType)
			}
		})
	}
}

func TestPanelAdapterRegistryPreservesStaticExactMatchAndError(t *testing.T) {
	registry := defaultPanelAdapterRegistry()
	for _, panelType := range []string{"sspanel", "SSPANEL", " SSPanel ", "UnsupportedPanel"} {
		t.Run(panelType, func(t *testing.T) {
			_, err := registry.staticFactory(panelType)
			want := "unsupported panel type: " + panelType
			if err == nil || err.Error() != want {
				t.Fatalf("error = %v, want %q", err, want)
			}
		})
	}
}

func TestPanelAdapterRegistryPreservesMachineAliasesAndRawValidation(t *testing.T) {
	registry := defaultPanelAdapterRegistry()
	for _, panelType := range []string{"NewV2board", "V2board", " V2board "} {
		t.Run(panelType, func(t *testing.T) {
			factory, err := registry.machineFactory(panelType)
			if err != nil {
				t.Fatal(err)
			}
			if got := fmt.Sprintf("%T", factory(&api.Config{})); got != "*newV2board.APIClient" {
				t.Fatalf("client type = %q, want *newV2board.APIClient", got)
			}
		})
	}

	_, err := registry.machineFactory("SSPanel")
	if want := "unsupported panel type for machine mode: SSPanel"; err == nil || err.Error() != want {
		t.Fatalf("error = %v, want %q", err, want)
	}
	_, err = registry.machineFactory("   ")
	if want := "machine mode PanelType must not be empty"; err == nil || err.Error() != want {
		t.Fatalf("error = %v, want %q", err, want)
	}
}

func TestPanelAdapterRegistryMachineAdapterFactoryExposesNeutralCapabilities(t *testing.T) {
	registry := defaultPanelAdapterRegistry()
	factory, err := registry.machineAdapterFactory(" V2board ")
	if err != nil {
		t.Fatal(err)
	}

	adapter, err := factory(&api.Config{
		APIHost:   "https://panel.example.com",
		MachineID: 7,
		Key:       "machine-token",
		Timeout:   3,
	})
	if err != nil {
		t.Fatalf("machine adapter factory returned error: %v", err)
	}
	if adapter == nil {
		t.Fatal("machine adapter factory returned nil adapter")
	}
	if got := fmt.Sprintf("%T", adapter); got != "*newV2board.APIClient" {
		t.Fatalf("machine adapter type = %q, want *newV2board.APIClient", got)
	}
	if _, ok := adapter.(machineAdapter); !ok {
		t.Fatal("machine adapter does not expose the panel machine capability seam")
	}
}

func TestPanelAdapterRegistryMachineAdapterFactoryRejectsMissingCapabilities(t *testing.T) {
	registry := panelAdapterRegistry{
		registrations: []panelAdapterRegistration{{
			aliases:     []string{"MachineFixture"},
			machineMode: true,
			newClient: func(*api.Config) runtimePanelClient {
				return &runtimeRegistryTestAPI{}
			},
		}},
	}

	factory, err := registry.machineAdapterFactory("MachineFixture")
	if err != nil {
		t.Fatal(err)
	}
	_, err = factory(&api.Config{})
	if err == nil || err.Error() != "panel adapter MachineFixture does not implement machine capabilities" {
		t.Fatalf("error = %v, want missing capability error", err)
	}
}

type typedNilMachineAdapterClient struct {
	runtimeRegistryTestAPI
}

func (*typedNilMachineAdapterClient) DiscoverMachineNodes() (*api.MachineNodesResponse, error) {
	return nil, nil
}

func (*typedNilMachineAdapterClient) ReportMachineStatus(api.MachineStatus) error {
	return nil
}

func TestPanelAdapterRegistryMachineAdapterFactoryRejectsTypedNil(t *testing.T) {
	registry := panelAdapterRegistry{
		registrations: []panelAdapterRegistration{{
			aliases:     []string{"TypedNilFixture"},
			machineMode: true,
			newClient: func(*api.Config) runtimePanelClient {
				return (*typedNilMachineAdapterClient)(nil)
			},
		}},
	}

	factory, err := registry.machineAdapterFactory("TypedNilFixture")
	if err != nil {
		t.Fatal(err)
	}
	_, err = factory(&api.Config{})
	if err == nil || err.Error() != "panel adapter TypedNilFixture returned nil machine adapter" {
		t.Fatalf("error = %v, want typed-nil error", err)
	}
}

func TestPanelAdapterRegistryMachineAdapterFactoryPreservesUnsupportedErrors(t *testing.T) {
	registry := defaultPanelAdapterRegistry()
	for _, panelType := range []string{"SSPanel", "UnsupportedPanel", "   "} {
		t.Run(panelType, func(t *testing.T) {
			_, err := registry.machineAdapterFactory(panelType)
			var want string
			if strings.TrimSpace(panelType) == "" {
				want = "machine mode PanelType must not be empty"
			} else {
				want = "unsupported panel type for machine mode: " + panelType
			}
			if err == nil || err.Error() != want {
				t.Fatalf("error = %v, want %q", err, want)
			}
		})
	}
}

func TestPanelAdapterRegistryHasUniqueAliasesAndFactories(t *testing.T) {
	registry := defaultPanelAdapterRegistry()
	seen := make(map[string]struct{})
	gotMachineAliases := make([]string, 0, 2)
	for _, registration := range registry.registrations {
		if registration.newClient == nil {
			t.Fatalf("registration has nil factory: %#v", registration)
		}
		for _, alias := range registration.aliases {
			if _, exists := seen[alias]; exists {
				t.Fatalf("duplicate panel alias %q", alias)
			}
			seen[alias] = struct{}{}
			if registration.machineMode {
				gotMachineAliases = append(gotMachineAliases, alias)
			}
		}
	}
	sort.Strings(gotMachineAliases)
	wantMachineAliases := []string{"NewV2board", "V2board"}
	if fmt.Sprint(gotMachineAliases) != fmt.Sprint(wantMachineAliases) {
		t.Fatalf("machine aliases = %v, want %v", gotMachineAliases, wantMachineAliases)
	}

	wantAliases := map[string]bool{
		"SSpanel":    false,
		"SSPanel":    false,
		"NewV2board": true,
		"V2board":    true,
		"PMpanel":    false,
		"Proxypanel": false,
		"V2RaySocks": false,
		"GoV2Panel":  false,
		"BunPanel":   false,
	}
	if len(registry.registrations) != 7 {
		t.Fatalf("adapter registration count = %d, want 7", len(registry.registrations))
	}
	gotAliases := make(map[string]bool, len(seen))
	for _, registration := range registry.registrations {
		for _, alias := range registration.aliases {
			gotAliases[alias] = registration.machineMode
		}
	}
	if !reflect.DeepEqual(gotAliases, wantAliases) {
		t.Fatalf("adapter alias contract = %#v, want %#v", gotAliases, wantAliases)
	}
}
