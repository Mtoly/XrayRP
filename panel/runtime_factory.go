package panel

import (
	"fmt"
	"strings"

	"github.com/xtls/xray-core/core"

	"github.com/Mtoly/XrayRP/service"
	"github.com/Mtoly/XrayRP/service/controller"
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

var specializedRuntimeServiceRegistrations []runtimeServiceRegistration

func defaultRuntimeServiceRegistry() runtimeServiceRegistry {
	return runtimeServiceRegistry{
		registrations: append([]runtimeServiceRegistration(nil), specializedRuntimeServiceRegistrations...),
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

func (registry runtimeServiceRegistry) build(construction runtimeServiceConstruction, fallbackNodeType string) (service.Service, error) {
	registration := registry.controllerFallback
	nodeType := construction.apiClient.Describe().NodeType
	if nodeType == "" {
		nodeType = fallbackNodeType
	}
	if specializedKind, known := specializedRuntimeServiceKind(nodeType); known {
		var included bool
		registration, included = registry.registration(specializedKind)
		if !included {
			return nil, fmt.Errorf(
				"node type %q is not included in this build profile; select the required release profile",
				nodeType,
			)
		}
	}
	return registration.newService(construction), nil
}

func (registry runtimeServiceRegistry) supportsSharedWS(nodeType string) bool {
	normalized := strings.TrimSpace(nodeType)
	if kind, specialized := specializedRuntimeServiceKind(normalized); specialized {
		registration, included := registry.registration(kind)
		return included && registration.supportsSharedWS
	}
	return registry.resolve(normalized).supportsSharedWS
}

func (registry runtimeServiceRegistry) registration(kind runtimeNodeServiceKind) (runtimeServiceRegistration, bool) {
	for _, registration := range registry.registrations {
		if registration.kind == kind {
			return registration, true
		}
	}
	return runtimeServiceRegistration{}, false
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

func specializedRuntimeServiceKind(nodeType string) (runtimeNodeServiceKind, bool) {
	switch {
	case strings.EqualFold(nodeType, "Hysteria2"), strings.EqualFold(nodeType, "Hysteria"):
		return runtimeNodeServiceHysteria2, true
	case strings.EqualFold(nodeType, "Tuic"):
		return runtimeNodeServiceTuic, true
	case strings.EqualFold(nodeType, "AnyTLS"):
		return runtimeNodeServiceAnyTLS, true
	default:
		return "", false
	}
}
