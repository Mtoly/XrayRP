package panel

import (
	"strings"

	log "github.com/sirupsen/logrus"

	"github.com/Mtoly/XrayRP/api"
	"github.com/Mtoly/XrayRP/common/mylego"
	"github.com/Mtoly/XrayRP/service/controller"
)

func materializeRuntimeCertConfig(apiClient api.API, controllerConfig *controller.Config, logger *log.Entry) {
	if panelCert, err := apiClient.GetXrayRCertConfig(); err != nil {
		logger.Warnf("Failed to get XrayR cert config from panel: %v", err)
	} else if err := mergeRuntimePanelCertConfig(controllerConfig, panelCert); err != nil {
		logger.Warnf("Failed to apply XrayR cert config from panel: %v", err)
	}
}

func mergeRuntimePanelCertConfig(controllerConfig *controller.Config, panelCert *api.XrayRCertConfig) error {
	if !panelCertHasConfig(panelCert) {
		return nil
	}
	if controllerConfig.CertConfig == nil {
		controllerConfig.CertConfig = &mylego.CertConfig{}
	}
	return applyPanelCertConfig(controllerConfig.CertConfig, panelCert)
}

func panelCertHasConfig(panelCert *api.XrayRCertConfig) bool {
	if panelCert == nil {
		return false
	}
	return strings.TrimSpace(panelCert.CertMode) != "" ||
		strings.TrimSpace(panelCert.CertDomain) != "" ||
		strings.TrimSpace(panelCert.CertFile) != "" ||
		strings.TrimSpace(panelCert.KeyFile) != "" ||
		strings.TrimSpace(panelCert.CertContent) != "" ||
		strings.TrimSpace(panelCert.KeyContent) != "" ||
		strings.TrimSpace(panelCert.Provider) != "" ||
		strings.TrimSpace(panelCert.Email) != "" ||
		len(panelCert.DNSEnv) > 0
}

func applyPanelCertConfig(certConfig *mylego.CertConfig, panelCert *api.XrayRCertConfig) error {
	if certConfig == nil {
		return nil
	}
	certMode := strings.ToLower(strings.TrimSpace(panelCert.CertMode))
	if certMode == "" {
		if strings.TrimSpace(panelCert.Provider) == "" && len(panelCert.DNSEnv) == 0 {
			return nil
		}
		certMode = "dns"
	}
	certConfig.CertMode = certMode

	if panelCert.CertDomain != "" {
		certConfig.CertDomain = panelCert.CertDomain
	}
	if panelCert.CertFile != "" {
		certConfig.CertFile = panelCert.CertFile
	}
	if panelCert.KeyFile != "" {
		certConfig.KeyFile = panelCert.KeyFile
	}
	if panelCert.Provider != "" {
		certConfig.Provider = panelCert.Provider
	}
	if panelCert.Email != "" {
		certConfig.Email = panelCert.Email
	}
	if len(panelCert.DNSEnv) > 0 {
		if certConfig.DNSEnv == nil {
			certConfig.DNSEnv = make(map[string]string)
		}
		for k, v := range panelCert.DNSEnv {
			certConfig.DNSEnv[k] = v
		}
	}
	if certMode == "content" {
		certConfig.CertContent = panelCert.CertContent
		certConfig.KeyContent = panelCert.KeyContent
	}
	return nil
}
