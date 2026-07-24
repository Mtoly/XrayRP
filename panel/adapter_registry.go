package panel

import (
	"fmt"
	"strings"

	"github.com/Mtoly/XrayRP/api"
	"github.com/Mtoly/XrayRP/api/bunpanel"
	"github.com/Mtoly/XrayRP/api/gov2panel"
	"github.com/Mtoly/XrayRP/api/newV2board"
	"github.com/Mtoly/XrayRP/api/pmpanel"
	"github.com/Mtoly/XrayRP/api/proxypanel"
	"github.com/Mtoly/XrayRP/api/sspanel"
	"github.com/Mtoly/XrayRP/api/v2raysocks"
)

type runtimePanelClient interface {
	Describe() api.ClientInfo
	GetNodeInfo() (*api.NodeInfo, error)
	GetUserList() (*[]api.UserInfo, error)
	GetNodeRule() (*[]api.DetectRule, error)
	ReportNodeStatus(*api.NodeStatus) error
	ReportNodeOnlineUsers(*[]api.OnlineUser) error
	ReportUserTraffic(*[]api.UserTraffic) error
	ReportIllegal(*[]api.DetectResult) error
}

type panelClientFactory func(*api.Config) runtimePanelClient

type panelAdapterRegistration struct {
	aliases     []string
	newClient   panelClientFactory
	machineMode bool
}

type panelAdapterRegistry struct {
	registrations []panelAdapterRegistration
}

func defaultPanelAdapterRegistry() panelAdapterRegistry {
	return panelAdapterRegistry{
		registrations: []panelAdapterRegistration{
			{
				aliases: []string{"SSpanel", "SSPanel"},
				newClient: func(config *api.Config) runtimePanelClient {
					return sspanel.New(config)
				},
			},
			{
				aliases: []string{"NewV2board", "V2board"},
				newClient: func(config *api.Config) runtimePanelClient {
					return newV2board.New(config)
				},
				machineMode: true,
			},
			{
				aliases: []string{"PMpanel"},
				newClient: func(config *api.Config) runtimePanelClient {
					return pmpanel.New(config)
				},
			},
			{
				aliases: []string{"Proxypanel"},
				newClient: func(config *api.Config) runtimePanelClient {
					return proxypanel.New(config)
				},
			},
			{
				aliases: []string{"V2RaySocks"},
				newClient: func(config *api.Config) runtimePanelClient {
					return v2raysocks.New(config)
				},
			},
			{
				aliases: []string{"GoV2Panel"},
				newClient: func(config *api.Config) runtimePanelClient {
					return gov2panel.New(config)
				},
			},
			{
				aliases: []string{"BunPanel"},
				newClient: func(config *api.Config) runtimePanelClient {
					return bunpanel.New(config)
				},
			},
		},
	}
}

func (registry panelAdapterRegistry) staticFactory(panelType string) (panelClientFactory, error) {
	if registration, ok := registry.lookup(panelType); ok {
		return registration.newClient, nil
	}
	return nil, fmt.Errorf("unsupported panel type: %s", panelType)
}

func (registry panelAdapterRegistry) machineFactory(panelType string) (panelClientFactory, error) {
	normalizedPanelType := strings.TrimSpace(panelType)
	if normalizedPanelType == "" {
		return nil, fmt.Errorf("machine mode PanelType must not be empty")
	}
	if registration, ok := registry.lookup(normalizedPanelType); ok && registration.machineMode {
		return registration.newClient, nil
	}
	return nil, fmt.Errorf("unsupported panel type for machine mode: %s", panelType)
}

func (registry panelAdapterRegistry) lookup(panelType string) (panelAdapterRegistration, bool) {
	for _, registration := range registry.registrations {
		for _, alias := range registration.aliases {
			if panelType == alias {
				return registration, true
			}
		}
	}
	return panelAdapterRegistration{}, false
}
