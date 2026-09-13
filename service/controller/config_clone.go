package controller

import (
	"github.com/Mtoly/XrayRP/common/limiter"
	"github.com/Mtoly/XrayRP/common/mylego"
)

// Clone returns an independently owned copy of the controller configuration.
// The copy keeps nil versus non-nil collection semantics and detaches every
// pointer, slice, and map reachable from Config.
func (config *Config) Clone() *Config {
	if config == nil {
		return nil
	}

	cloned := *config
	cloned.CertConfig = cloneCertConfig(config.CertConfig)
	cloned.AutoSpeedLimitConfig = cloneAutoSpeedLimitConfig(config.AutoSpeedLimitConfig)
	cloned.GlobalDeviceLimitConfig = cloneGlobalDeviceLimitConfig(config.GlobalDeviceLimitConfig)
	cloned.FallBackConfigs = cloneFallBackConfigs(config.FallBackConfigs)
	cloned.REALITYConfigs = cloneLocalREALITYConfig(config.REALITYConfigs)
	cloned.WebSocketConfig = cloneWebSocketConfig(config.WebSocketConfig)
	cloned.TrustedXForwardedFor = cloneSlice(config.TrustedXForwardedFor)
	return &cloned
}

func cloneCertConfig(config *mylego.CertConfig) *mylego.CertConfig {
	if config == nil {
		return nil
	}
	cloned := *config
	cloned.DNSEnv = cloneStringMap(config.DNSEnv)
	return &cloned
}

func cloneAutoSpeedLimitConfig(config *AutoSpeedLimitConfig) *AutoSpeedLimitConfig {
	if config == nil {
		return nil
	}
	cloned := *config
	return &cloned
}

func cloneGlobalDeviceLimitConfig(config *limiter.GlobalDeviceLimitConfig) *limiter.GlobalDeviceLimitConfig {
	if config == nil {
		return nil
	}
	cloned := *config
	return &cloned
}

func cloneFallBackConfigs(configs []*FallBackConfig) []*FallBackConfig {
	if configs == nil {
		return nil
	}
	cloned := make([]*FallBackConfig, len(configs))
	for index, config := range configs {
		cloned[index] = cloneValue(config)
	}
	return cloned
}

func cloneLocalREALITYConfig(config *REALITYConfig) *REALITYConfig {
	if config == nil {
		return nil
	}
	cloned := *config
	cloned.ServerNames = cloneSlice(config.ServerNames)
	cloned.ShortIds = cloneSlice(config.ShortIds)
	return &cloned
}

func cloneWebSocketConfig(config *WebSocketConfig) *WebSocketConfig {
	if config == nil {
		return nil
	}
	cloned := *config
	return &cloned
}

func cloneStringMap(values map[string]string) map[string]string {
	if values == nil {
		return nil
	}
	cloned := make(map[string]string, len(values))
	for key, value := range values {
		cloned[key] = value
	}
	return cloned
}
