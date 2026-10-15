package panel

import (
	"errors"

	log "github.com/sirupsen/logrus"

	"github.com/Mtoly/XrayRP/api"
	"github.com/Mtoly/XrayRP/service/controller"
)

// materializeRuntimeCertConfig records the locally declared certificate basis
// and then merges the panel certificate snapshot over it. Sync uses the same
// merge rule through Config.MergePanelCertConfig.
func materializeRuntimeCertConfig(apiClient any, controllerConfig *controller.Config, logger *log.Entry) {
	controllerConfig.CaptureLocalCertConfig()
	provider, ok := apiClient.(api.CertConfigProvider)
	if !ok {
		return
	}
	panelCert, err := provider.GetXrayRCertConfig()
	if err != nil {
		if !errors.Is(err, api.ErrUnsupportedPanelFeature) {
			logger.Warnf("Failed to get XrayR cert config from panel: %v", err)
		}
		return
	}
	controllerConfig.CertConfig = controllerConfig.MergePanelCertConfig(panelCert)
}
