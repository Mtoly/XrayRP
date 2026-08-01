package panel

import (
	"fmt"
	"reflect"
	"sort"
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
