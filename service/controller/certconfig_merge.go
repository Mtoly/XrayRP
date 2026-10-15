package controller

import (
	"strings"

	"github.com/Mtoly/XrayRP/api"
	"github.com/Mtoly/XrayRP/common/mylego"
)

// CaptureLocalCertConfig records the certificate configuration as declared
// locally, before any panel snapshot is merged into it. Panel snapshots are
// always merged over this basis rather than over the applied certificate
// configuration, so a value supplied by an earlier snapshot does not persist
// after a later snapshot stops supplying it. It is idempotent and nil-safe: once
// captured, later calls keep the recorded basis instead of recapturing merged
// values, so both the panel materialize step and New may call it.
func (config *Config) CaptureLocalCertConfig() {
	if config == nil || config.localCertCaptured {
		return
	}
	config.localCertConfig = cloneCertConfig(config.CertConfig)
	config.localCertCaptured = true
}

// MergePanelCertConfig returns the effective certificate configuration produced
// by one panel snapshot over the local basis. Supplied panel values take
// precedence; omitted values fall back to the local basis; DNS credentials are
// merged per key. Content material is taken from the panel only in content
// mode, so private keys from earlier snapshots never leak into other modes.
// The basis is captured on first use if the caller has not captured it yet.
// The result shares no maps or pointers with the config or the snapshot.
func (config *Config) MergePanelCertConfig(panel *api.XrayRCertConfig) *mylego.CertConfig {
	if config == nil {
		return mergePanelCertConfig(nil, panel)
	}
	config.CaptureLocalCertConfig()
	return mergePanelCertConfig(config.localCertConfig, panel)
}

// mergePanelCertConfig applies one panel snapshot to an explicit local basis.
// The result shares no maps or pointers with either input.
func mergePanelCertConfig(local *mylego.CertConfig, panel *api.XrayRCertConfig) *mylego.CertConfig {
	merged := cloneCertConfig(local)
	if panel == nil {
		return merged
	}
	mode := normalizeCertMode(panel.CertMode, panel.Provider, panel.DNSEnv)
	if mode == "" {
		return merged
	}
	if merged == nil {
		merged = &mylego.CertConfig{}
	}
	merged.CertMode = mode
	if panel.CertDomain != "" {
		merged.CertDomain = panel.CertDomain
	}
	if panel.CertFile != "" {
		merged.CertFile = panel.CertFile
	}
	if panel.KeyFile != "" {
		merged.KeyFile = panel.KeyFile
	}
	if panel.Provider != "" {
		merged.Provider = panel.Provider
	}
	if panel.Email != "" {
		merged.Email = panel.Email
	}
	if len(panel.DNSEnv) > 0 {
		if merged.DNSEnv == nil {
			merged.DNSEnv = make(map[string]string, len(panel.DNSEnv))
		}
		for key, value := range panel.DNSEnv {
			merged.DNSEnv[key] = value
		}
	}
	if mode == "content" {
		merged.CertContent = panel.CertContent
		merged.KeyContent = panel.KeyContent
	}
	return merged
}

func certConfigEqual(current, next *mylego.CertConfig) bool {
	if current == nil || next == nil {
		return current == nil && next == nil
	}
	return current.CertMode == next.CertMode &&
		current.CertDomain == next.CertDomain &&
		current.CertFile == next.CertFile &&
		current.KeyFile == next.KeyFile &&
		current.CertContent == next.CertContent &&
		current.KeyContent == next.KeyContent &&
		current.Provider == next.Provider &&
		current.Email == next.Email &&
		current.RejectUnknownSni == next.RejectUnknownSni &&
		stringMapsEqual(current.DNSEnv, next.DNSEnv)
}

func stringMapsEqual(current, next map[string]string) bool {
	if len(current) != len(next) {
		return false
	}
	for key, value := range current {
		if nextValue, ok := next[key]; !ok || nextValue != value {
			return false
		}
	}
	return true
}

func normalizeCertMode(certMode, provider string, dnsEnv map[string]string) string {
	mode := strings.ToLower(strings.TrimSpace(certMode))
	if mode != "" {
		return mode
	}
	if strings.TrimSpace(provider) != "" || len(dnsEnv) > 0 {
		return "dns"
	}
	return ""
}
