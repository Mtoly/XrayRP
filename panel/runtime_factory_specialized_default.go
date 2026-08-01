package panel

import (
	"github.com/Mtoly/XrayRP/service"
	"github.com/Mtoly/XrayRP/service/anytls"
	"github.com/Mtoly/XrayRP/service/hysteria2"
	"github.com/Mtoly/XrayRP/service/tuic"
)

func init() {
	specializedRuntimeServiceRegistrations = append(
		specializedRuntimeServiceRegistrations,
		runtimeServiceRegistration{
			kind:             runtimeNodeServiceHysteria2,
			aliases:          []string{"Hysteria2", "Hysteria"},
			supportsSharedWS: true,
			newService: func(construction runtimeServiceConstruction) service.Service {
				return hysteria2.New(construction.apiClient, construction.controllerConfig)
			},
		},
		runtimeServiceRegistration{
			kind:             runtimeNodeServiceTuic,
			aliases:          []string{"Tuic"},
			supportsSharedWS: true,
			newService: func(construction runtimeServiceConstruction) service.Service {
				return tuic.New(construction.apiClient, construction.controllerConfig)
			},
		},
		runtimeServiceRegistration{
			kind:             runtimeNodeServiceAnyTLS,
			aliases:          []string{"AnyTLS"},
			supportsSharedWS: true,
			newService: func(construction runtimeServiceConstruction) service.Service {
				return anytls.New(construction.apiClient, construction.controllerConfig)
			},
		},
	)
}
