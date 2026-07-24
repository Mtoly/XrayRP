package panel

import (
	"strings"

	"github.com/xtls/xray-core/core"

	"github.com/Mtoly/XrayRP/service"
	"github.com/Mtoly/XrayRP/service/anytls"
	"github.com/Mtoly/XrayRP/service/controller"
	"github.com/Mtoly/XrayRP/service/hysteria2"
	"github.com/Mtoly/XrayRP/service/tuic"
)

type runtimeNodeServiceKind string

const (
	runtimeNodeServiceController runtimeNodeServiceKind = "controller"
	runtimeNodeServiceHysteria2  runtimeNodeServiceKind = "hysteria2"
	runtimeNodeServiceTuic       runtimeNodeServiceKind = "tuic"
	runtimeNodeServiceAnyTLS     runtimeNodeServiceKind = "anytls"
)

type runtimeServiceConstruction struct {
	server                *core.Instance
	apiClient             runtimePanelClient
	controllerConfig      *controller.Config
	panelType             string
	wsEventRuntimeFactory controller.WSEventRuntimeFactory
}

type runtimeServiceFactory func(runtimeServiceConstruction) service.Service

type runtimeServiceRegistration struct {
	kind             runtimeNodeServiceKind
	aliases          []string
	newService       runtimeServiceFactory
	supportsSharedWS bool
}

type runtimeServiceRegistry struct {
	registrations      []runtimeServiceRegistration
	controllerFallback runtimeServiceRegistration
}

func defaultRuntimeServiceRegistry() runtimeServiceRegistry {
	return runtimeServiceRegistry{
		registrations: []runtimeServiceRegistration{
			{
				kind:    runtimeNodeServiceHysteria2,
				aliases: []string{"Hysteria2", "Hysteria"},
				newService: func(construction runtimeServiceConstruction) service.Service {
					return hysteria2.New(construction.apiClient, construction.controllerConfig)
				},
			},
			{
				kind:    runtimeNodeServiceTuic,
				aliases: []string{"Tuic"},
				newService: func(construction runtimeServiceConstruction) service.Service {
					return tuic.New(construction.apiClient, construction.controllerConfig)
				},
			},
			{
				kind:    runtimeNodeServiceAnyTLS,
				aliases: []string{"AnyTLS"},
				newService: func(construction runtimeServiceConstruction) service.Service {
					return anytls.New(construction.apiClient, construction.controllerConfig)
				},
			},
		},
		controllerFallback: runtimeServiceRegistration{
			kind:             runtimeNodeServiceController,
			supportsSharedWS: true,
			newService: func(construction runtimeServiceConstruction) service.Service {
				controllerService := controller.New(
					construction.server,
					construction.apiClient,
					construction.controllerConfig,
					construction.panelType,
				)
				if construction.wsEventRuntimeFactory != nil {
					controllerService.SetWSEventRuntimeFactory(construction.wsEventRuntimeFactory)
				}
				return controllerService
			},
		},
	}
}

func (registry runtimeServiceRegistry) build(construction runtimeServiceConstruction, fallbackNodeType string) service.Service {
	registration := registry.controllerFallback
	if construction.wsEventRuntimeFactory == nil {
		nodeType := construction.apiClient.Describe().NodeType
		if nodeType == "" {
			nodeType = fallbackNodeType
		}
		registration = registry.resolve(nodeType)
	}
	return registration.newService(construction)
}

func (registry runtimeServiceRegistry) supportsSharedWS(nodeType string) bool {
	return registry.resolve(strings.TrimSpace(nodeType)).supportsSharedWS
}

func (registry runtimeServiceRegistry) resolve(nodeType string) runtimeServiceRegistration {
	for _, registration := range registry.registrations {
		for _, alias := range registration.aliases {
			if strings.EqualFold(nodeType, alias) {
				return registration
			}
		}
	}
	return registry.controllerFallback
}
