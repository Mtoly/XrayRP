package panel

import (
	"fmt"
	"strings"
	"testing"

	"github.com/Mtoly/XrayRP/api"
	"github.com/Mtoly/XrayRP/service"
	"github.com/Mtoly/XrayRP/service/controller"
)

func TestRuntimeServiceRegistryPreservesAliasesAndControllerFallback(t *testing.T) {
	tests := []struct {
		name     string
		nodeType string
		want     runtimeNodeServiceKind
	}{
		{name: "hysteria2", nodeType: "Hysteria2", want: runtimeNodeServiceHysteria2},
		{name: "hysteria alias", nodeType: "Hysteria", want: runtimeNodeServiceHysteria2},
		{name: "hysteria case insensitive", nodeType: "hYsTeRiA2", want: runtimeNodeServiceHysteria2},
		{name: "tuic", nodeType: "Tuic", want: runtimeNodeServiceTuic},
		{name: "tuic case insensitive", nodeType: "TUIC", want: runtimeNodeServiceTuic},
		{name: "anytls", nodeType: "AnyTLS", want: runtimeNodeServiceAnyTLS},
		{name: "anytls case insensitive", nodeType: "anytls", want: runtimeNodeServiceAnyTLS},
		{name: "tuic with spaces falls back", nodeType: " Tuic ", want: runtimeNodeServiceController},
		{name: "unknown falls back", nodeType: "Unknown", want: runtimeNodeServiceController},
		{name: "vless falls back", nodeType: "Vless", want: runtimeNodeServiceController},
		{name: "empty falls back", nodeType: "", want: runtimeNodeServiceController},
	}

	registry := defaultRuntimeServiceRegistry()
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			want := test.want
			if specializedKind, specialized := specializedRuntimeServiceKind(test.nodeType); specialized {
				if _, included := registry.registration(specializedKind); !included {
					want = runtimeNodeServiceController
				}
			}
			if got := registry.resolve(test.nodeType).kind; got != want {
				t.Fatalf("kind = %q, want %q", got, want)
			}
		})
	}
}

func TestRuntimeServiceRegistryConstructsSpecializedServices(t *testing.T) {
	tests := []struct {
		nodeType string
		wantType string
	}{
		{nodeType: "Hysteria", wantType: "*hysteria2.Hysteria2Service"},
		{nodeType: "Tuic", wantType: "*tuic.TuicService"},
		{nodeType: "AnyTLS", wantType: "*anytls.AnyTLSService"},
	}

	registry := defaultRuntimeServiceRegistry()
	for _, test := range tests {
		t.Run(test.nodeType, func(t *testing.T) {
			runtimeService, err := registry.build(runtimeServiceConstruction{
				apiClient:        &runtimeRegistryTestAPI{clientInfo: api.ClientInfo{NodeType: test.nodeType}},
				controllerConfig: &controller.Config{},
			}, "")
			kind, _ := specializedRuntimeServiceKind(test.nodeType)
			if _, included := registry.registration(kind); !included {
				if err == nil {
					t.Fatalf("build succeeded for omitted node type %q", test.nodeType)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if got := fmt.Sprintf("%T", runtimeService); got != test.wantType {
				t.Fatalf("service type = %q, want %q", got, test.wantType)
			}
		})
	}
}

func TestRuntimeServiceRegistryPreservesDescribeAndFallbackPrecedence(t *testing.T) {
	registry := runtimeServiceRegistry{
		registrations: []runtimeServiceRegistration{{
			kind:             runtimeNodeServiceTuic,
			aliases:          []string{"Tuic"},
			supportsSharedWS: true,
			newService: func(runtimeServiceConstruction) service.Service {
				return &runtimeRegistryMarkerService{name: "tuic"}
			},
		}},
		controllerFallback: runtimeServiceRegistration{
			kind:             runtimeNodeServiceController,
			supportsSharedWS: true,
			newService: func(construction runtimeServiceConstruction) service.Service {
				name := "controller"
				if construction.wsEventRuntimeFactory != nil {
					name = "controller-ws"
				}
				return &runtimeRegistryMarkerService{name: name}
			},
		},
	}

	tests := []struct {
		name          string
		described     string
		fallback      string
		want          string
		withWSRuntime bool
	}{
		{name: "empty describe uses fallback", fallback: "Tuic", want: "tuic"},
		{name: "describe wins over fallback", described: "Vless", fallback: "Tuic", want: "controller"},
		{name: "whitespace describe does not use fallback", described: " ", fallback: "Tuic", want: "controller"},
		{name: "websocket keeps specialized service", described: "Tuic", fallback: "Tuic", want: "tuic", withWSRuntime: true},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			construction := runtimeServiceConstruction{
				apiClient: &runtimeRegistryTestAPI{clientInfo: api.ClientInfo{NodeType: test.described}},
			}
			if test.withWSRuntime {
				construction.wsEventRuntimeFactory = func(controller.WSEventSubmitter) (controller.WSRuntimeLifecycle, error) {
					return nil, nil
				}
			}
			built, err := registry.build(construction, test.fallback)
			if err != nil {
				t.Fatal(err)
			}
			marker, ok := built.(*runtimeRegistryMarkerService)
			if !ok || marker.name != test.want {
				t.Fatalf("service = %#v, want marker %q", built, test.want)
			}
		})
	}
}

func TestRuntimeServiceRegistryPreservesSharedWSEligibilityNormalization(t *testing.T) {
	registry := defaultRuntimeServiceRegistry()
	tests := []struct {
		nodeType string
		want     bool
	}{
		{nodeType: "Hysteria", want: true},
		{nodeType: " hYsTeRiA2 ", want: true},
		{nodeType: " TUIC ", want: true},
		{nodeType: " anytls ", want: true},
		{nodeType: "Vless", want: true},
		{nodeType: " vmess ", want: true},
		{nodeType: "Unknown", want: true},
	}

	for _, test := range tests {
		t.Run(test.nodeType, func(t *testing.T) {
			want := test.want
			if kind, specialized := specializedRuntimeServiceKind(strings.TrimSpace(test.nodeType)); specialized {
				_, want = registry.registration(kind)
			}
			if got := registry.supportsSharedWS(test.nodeType); got != want {
				t.Fatalf("supports shared WS = %v, want %v", got, want)
			}
		})
	}
}

func TestRuntimeServiceRegistryHasUniqueAliasesAndFactories(t *testing.T) {
	registry := defaultRuntimeServiceRegistry()
	if registry.controllerFallback.newService == nil {
		t.Fatal("controller fallback factory must not be nil")
	}
	seen := make(map[string]struct{})
	for _, registration := range registry.registrations {
		if registration.newService == nil {
			t.Fatalf("registration has nil factory: %#v", registration)
		}
		for _, alias := range registration.aliases {
			folded := strings.ToLower(alias)
			if _, exists := seen[folded]; exists {
				t.Fatalf("duplicate runtime alias %q", alias)
			}
			seen[folded] = struct{}{}
		}
	}
}

type runtimeRegistryTestAPI struct {
	clientInfo api.ClientInfo
}

func (a *runtimeRegistryTestAPI) Describe() api.ClientInfo { return a.clientInfo }
func (a *runtimeRegistryTestAPI) GetNodeInfo() (*api.NodeInfo, error) {
	return &api.NodeInfo{}, nil
}
func (a *runtimeRegistryTestAPI) GetUserList() (*[]api.UserInfo, error) {
	users := []api.UserInfo{}
	return &users, nil
}
func (a *runtimeRegistryTestAPI) GetNodeRule() (*[]api.DetectRule, error) {
	rules := []api.DetectRule{}
	return &rules, nil
}
func (a *runtimeRegistryTestAPI) ReportNodeStatus(*api.NodeStatus) error { return nil }
func (a *runtimeRegistryTestAPI) ReportNodeOnlineUsers(*[]api.OnlineUser) error {
	return nil
}
func (a *runtimeRegistryTestAPI) ReportUserTraffic(*[]api.UserTraffic) error {
	return nil
}
func (a *runtimeRegistryTestAPI) ReportIllegal(*[]api.DetectResult) error { return nil }

type runtimeRegistryMarkerService struct {
	name string
}

func (s *runtimeRegistryMarkerService) Start() error { return nil }
func (s *runtimeRegistryMarkerService) Close() error { return nil }
