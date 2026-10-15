package controller

import (
	"testing"

	"github.com/xtls/xray-core/app/dispatcher"
	"github.com/xtls/xray-core/app/proxyman"
	"github.com/xtls/xray-core/app/stats"
	"github.com/xtls/xray-core/common/serial"
	"github.com/xtls/xray-core/core"
	"github.com/xtls/xray-core/infra/conf"

	"github.com/Mtoly/XrayRP/api"
	"github.com/Mtoly/XrayRP/app/mydispatcher"
	"github.com/Mtoly/XrayRP/common/mylego"
)

// newCertBasisTestCore starts the minimal core features that New requires.
func newCertBasisTestCore(t *testing.T) *core.Instance {
	t.Helper()
	policyConfig, err := (&conf.PolicyConfig{Levels: map[uint32]*conf.Policy{0: {
		StatsUserUplink:   true,
		StatsUserDownlink: true,
	}}}).Build()
	if err != nil {
		t.Fatal(err)
	}
	dnsConfig, err := (&conf.DNSConfig{}).Build()
	if err != nil {
		t.Fatal(err)
	}
	routeConfig, err := (&conf.RouterConfig{}).Build()
	if err != nil {
		t.Fatal(err)
	}
	server, err := core.New(&core.Config{App: []*serial.TypedMessage{
		serial.ToTypedMessage((&conf.LogConfig{LogLevel: "none"}).Build()),
		serial.ToTypedMessage(&dispatcher.Config{}),
		serial.ToTypedMessage(&mydispatcher.Config{}),
		serial.ToTypedMessage(&stats.Config{}),
		serial.ToTypedMessage(&proxyman.InboundConfig{}),
		serial.ToTypedMessage(&proxyman.OutboundConfig{}),
		serial.ToTypedMessage(policyConfig),
		serial.ToTypedMessage(dnsConfig),
		serial.ToTypedMessage(routeConfig),
	}})
	if err != nil {
		t.Fatal(err)
	}
	if err := server.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := server.Close(); err != nil {
			t.Errorf("core Close() error = %v", err)
		}
	})
	return server
}

// A caller that builds a controller directly, without the panel materialize
// step, must still keep the locally declared DNS credentials as fallback.
func TestNewCapturesLocalCertBasisWithoutMaterialize(t *testing.T) {
	server := newCertBasisTestCore(t)
	panelAPI := &fakeSyncApplyAPI{certConfig: &api.XrayRCertConfig{
		Provider: "cloudflare",
		Email:    "ops@example.com",
	}}
	config := &Config{
		ListenIP:       "127.0.0.1",
		UpdatePeriodic: 3600,
		DisableGetRule: true,
		CertConfig:     localDNSCertConfig(),
	}

	controller := New(server, panelAPI, config, "test")

	if controller.config.localCertConfig == nil || controller.config.localCertConfig.DNSEnv["CF_API_TOKEN"] != "local-token" {
		t.Fatalf("New did not capture the local certificate basis: %#v", controller.config.localCertConfig)
	}
	runCertConfigSync(t, controller)
	if got := controller.config.CertConfig.DNSEnv["CF_API_TOKEN"]; got != "local-token" {
		t.Fatalf("direct New lost local DNS credential after panel sync, DNSEnv = %#v", controller.config.CertConfig.DNSEnv)
	}
}

// Nil configuration is a supported state (accessors guard c.config == nil), so
// New must neither substitute a config nor panic while capturing the basis.
func TestNewKeepsNilConfigConvention(t *testing.T) {
	server := newCertBasisTestCore(t)
	controller := New(server, &fakeSyncApplyAPI{}, nil, "test")
	if controller.config != nil {
		t.Fatalf("New(nil) changed the nil configuration convention: %#v", controller.config)
	}
}

// Capturing twice must keep the first local basis even after the applied
// certificate configuration has been replaced by a merged snapshot.
func TestCaptureLocalCertConfigIsIdempotent(t *testing.T) {
	config := &Config{CertConfig: localDNSCertConfig()}
	config.CaptureLocalCertConfig()
	config.CertConfig = config.MergePanelCertConfig(&api.XrayRCertConfig{
		CertMode: "dns",
		DNSEnv:   map[string]string{"CF_API_TOKEN": "panel-token"},
	})
	config.CaptureLocalCertConfig()

	if got := config.localCertConfig.DNSEnv["CF_API_TOKEN"]; got != "local-token" {
		t.Fatalf("second Capture recaptured merged values, local basis DNSEnv = %#v", config.localCertConfig.DNSEnv)
	}
}

// A nil configuration must be safe to capture.
func TestCaptureLocalCertConfigNilReceiver(t *testing.T) {
	var config *Config
	config.CaptureLocalCertConfig()
}

// A capture of an absent certificate configuration is still a recorded basis,
// so later calls must not record a merged value as the local declaration.
func TestCaptureLocalCertConfigRecordsNilBasisOnce(t *testing.T) {
	config := &Config{}
	config.CaptureLocalCertConfig()
	config.CertConfig = &mylego.CertConfig{CertMode: "dns", DNSEnv: map[string]string{"CF_API_TOKEN": "panel-token"}}
	config.CaptureLocalCertConfig()

	if config.localCertConfig != nil {
		t.Fatalf("captured nil basis was replaced by merged config: %#v", config.localCertConfig)
	}
}
