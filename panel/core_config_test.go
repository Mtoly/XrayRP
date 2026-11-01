package panel

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/xtls/xray-core/app/dns"
	xraylog "github.com/xtls/xray-core/app/log"
	"github.com/xtls/xray-core/app/policy"
	"github.com/xtls/xray-core/app/router"
	"github.com/xtls/xray-core/common/serial"
	"github.com/xtls/xray-core/core"

	"github.com/Mtoly/XrayRP/app/mydispatcher"
)

func capturingCoreConfigBuilder(captured **core.Config, instance *core.Instance) coreConfigBuilder {
	return coreConfigBuilder{
		newInstance: func(config *core.Config) (*core.Instance, error) {
			*captured = config
			return instance, nil
		},
	}
}

func writeCoreConfigFixture(t *testing.T, name, contents string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), name)
	if err := os.WriteFile(path, []byte(contents), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestCoreConfigBuilderBuildsDefaultApplications(t *testing.T) {
	var captured *core.Config
	instance := new(core.Instance)
	builder := capturingCoreConfigBuilder(&captured, instance)

	got, err := builder.Build(&Config{})
	if err != nil {
		t.Fatal(err)
	}
	if got != instance {
		t.Fatalf("instance = %p, want %p", got, instance)
	}
	if captured == nil {
		t.Fatal("core config was not passed to instance construction")
	}

	wantTypes := []string{
		serial.GetMessageType(&xraylog.Config{}),
		"xray.app.dispatcher.Config",
		serial.GetMessageType(&mydispatcher.Config{}),
		"xray.app.stats.Config",
		"xray.app.proxyman.OutboundConfig",
		serial.GetMessageType(&policy.Config{}),
		serial.GetMessageType(&dns.Config{}),
		serial.GetMessageType(&router.Config{}),
		"xray.app.proxyman.InboundConfig",
	}
	gotTypes := make([]string, len(captured.App))
	for i, app := range captured.App {
		gotTypes[i] = app.Type
	}
	if !reflect.DeepEqual(gotTypes, wantTypes) {
		t.Fatalf("application types = %#v, want %#v", gotTypes, wantTypes)
	}
	if len(captured.Inbound) != 0 || len(captured.Outbound) != 0 {
		t.Fatalf("default config unexpectedly has custom handlers: in=%d out=%d", len(captured.Inbound), len(captured.Outbound))
	}

	logMessage, err := captured.App[0].GetInstance()
	if err != nil {
		t.Fatal(err)
	}
	logConfig := logMessage.(*xraylog.Config)
	if logConfig.ErrorLogType != xraylog.LogType_None || logConfig.AccessLogType != xraylog.LogType_None {
		t.Fatalf("unexpected default log config: %#v", logConfig)
	}

	policyMessage, err := captured.App[5].GetInstance()
	if err != nil {
		t.Fatal(err)
	}
	levelZero := policyMessage.(*policy.Config).Level[0]
	if levelZero == nil || levelZero.Timeout == nil || levelZero.Stats == nil || levelZero.Buffer == nil {
		t.Fatalf("incomplete default level-zero policy: %#v", levelZero)
	}
	if levelZero.Timeout.Handshake.Value != 4 || levelZero.Timeout.ConnectionIdle.Value != 30 ||
		levelZero.Timeout.UplinkOnly.Value != 2 || levelZero.Timeout.DownlinkOnly.Value != 4 {
		t.Fatalf("unexpected default timeouts: %#v", levelZero.Timeout)
	}
	if !levelZero.Stats.UserUplink || !levelZero.Stats.UserDownlink || levelZero.Buffer.Connection != 4*1024 {
		t.Fatalf("unexpected default stats/buffer policy: %#v", levelZero)
	}

	dnsMessage, err := captured.App[6].GetInstance()
	if err != nil {
		t.Fatal(err)
	}
	if got := dnsMessage.(*dns.Config); len(got.NameServer) != 0 || len(got.StaticHosts) != 0 {
		t.Fatalf("unexpected default DNS config: %#v", got)
	}
	routeMessage, err := captured.App[7].GetInstance()
	if err != nil {
		t.Fatal(err)
	}
	if got := routeMessage.(*router.Config); got.DomainStrategy != router.Config_AsIs || len(got.Rule) != 0 {
		t.Fatalf("unexpected default routing config: %#v", got)
	}
}

func TestCoreConfigBuilderPreservesCustomHandlers(t *testing.T) {
	inboundPath := writeCoreConfigFixture(t, "inbounds.json", `[
		{
			"tag": "custom-inbound",
			"listen": "127.0.0.1",
			"port": 12345,
			"protocol": "dokodemo-door",
			"settings": {
				"address": "127.0.0.1",
				"port": 80,
				"network": "tcp"
			}
		},
		{
			"tag": "custom-inbound-two",
			"listen": "127.0.0.1",
			"port": 12346,
			"protocol": "dokodemo-door",
			"settings": {
				"address": "127.0.0.1",
				"port": 81,
				"network": "tcp"
			}
		}
	]`)
	outboundPath := writeCoreConfigFixture(t, "outbounds.json", `[
		{
			"tag": "custom-outbound",
			"protocol": "freedom",
			"settings": {}
		},
		{
			"tag": "custom-outbound-two",
			"protocol": "freedom",
			"settings": {}
		}
	]`)
	var captured *core.Config
	builder := capturingCoreConfigBuilder(&captured, new(core.Instance))

	if _, err := builder.Build(&Config{
		InboundConfigPath:  inboundPath,
		OutboundConfigPath: outboundPath,
	}); err != nil {
		t.Fatal(err)
	}
	if len(captured.Inbound) != 2 {
		t.Fatalf("custom inbound count = %d, want 2", len(captured.Inbound))
	}
	gotInboundTags := []string{captured.Inbound[0].Tag, captured.Inbound[1].Tag}
	if !reflect.DeepEqual(gotInboundTags, []string{"custom-inbound", "custom-inbound-two"}) {
		t.Fatalf("custom inbound not preserved: %#v", captured.Inbound)
	}
	if len(captured.Outbound) != 2 {
		t.Fatalf("custom outbound count = %d, want 2", len(captured.Outbound))
	}
	gotOutboundTags := []string{captured.Outbound[0].Tag, captured.Outbound[1].Tag}
	if !reflect.DeepEqual(gotOutboundTags, []string{"custom-outbound", "custom-outbound-two"}) {
		t.Fatalf("custom outbound not preserved: %#v", captured.Outbound)
	}
}

func TestCoreConfigBuilderValidatesCustomOutboundTransportSecurity(t *testing.T) {
	for _, protocol := range []string{"vless", "trojan"} {
		for _, tt := range []struct {
			name    string
			address string
			tls     bool
			reject  bool
		}{
			{name: "loopback", address: "127.0.0.1"},
			{name: "private", address: "10.0.0.1"},
			{name: "link local", address: "169.254.0.1"},
			{name: "shared address space", address: "100.64.0.1", reject: true},
			{name: "benchmark range", address: "198.18.0.1", reject: true},
			{name: "documentation range", address: "192.0.2.1", reject: true},
			{name: "TLS documentation range", address: "192.0.2.1", tls: true},
		} {
			t.Run(protocol+"/"+tt.name, func(t *testing.T) {
				settings := fmt.Sprintf(`{"servers":[{"address":%q,"port":443,"password":"test-only"}]}`, tt.address)
				if protocol == "vless" {
					settings = fmt.Sprintf(`{"vnext":[{"address":%q,"port":443,"users":[{"id":"1b4e28ba-2fa1-11d2-883f-0016d3cca427","encryption":"none"}]}]}`, tt.address)
				}
				security := "none"
				if tt.tls {
					security = "tls"
				}
				path := writeCoreConfigFixture(t, "outbounds.json", fmt.Sprintf(
					`[{"tag":"custom-outbound","protocol":%q,"settings":%s,"streamSettings":{"security":%q}}]`,
					protocol, settings, security))
				var captured *core.Config
				builder := capturingCoreConfigBuilder(&captured, new(core.Instance))
				_, err := builder.Build(&Config{OutboundConfigPath: path})
				if tt.reject {
					if err == nil || !strings.Contains(err.Error(), "failed to understand outbound config") || !strings.Contains(err.Error(), "prohibited") {
						t.Fatalf("error = %v, want wrapped transport-security rejection", err)
					}
					if captured != nil {
						t.Fatal("rejected outbound reached instance construction")
					}
					return
				}
				if err != nil {
					t.Fatal(err)
				}
				if captured == nil || len(captured.Outbound) != 1 || captured.Outbound[0].Tag != "custom-outbound" {
					t.Fatalf("custom outbound was not preserved: %#v", captured)
				}
			})
		}
	}
}

func TestCoreConfigBuilderReportsFileAndJSONErrors(t *testing.T) {
	type pathSetter func(*Config, string)
	tests := []struct {
		name       string
		setPath    pathSetter
		wantRead   string
		wantDecode string
	}{
		{"DNS", func(c *Config, path string) { c.DnsConfigPath = path }, "failed to read DNS config file", "failed to unmarshal DNS config"},
		{"routing", func(c *Config, path string) { c.RouteConfigPath = path }, "failed to read routing config file", "failed to unmarshal routing config"},
		{"inbound", func(c *Config, path string) { c.InboundConfigPath = path }, "failed to read custom inbound config file", "failed to unmarshal custom inbound config"},
		{"outbound", func(c *Config, path string) { c.OutboundConfigPath = path }, "failed to read custom outbound config file", "failed to unmarshal custom outbound config"},
	}
	builder := coreConfigBuilder{
		newInstance: func(*core.Config) (*core.Instance, error) {
			t.Fatal("instance construction must not run after config errors")
			return nil, nil
		},
	}

	for _, tt := range tests {
		t.Run(tt.name+" read", func(t *testing.T) {
			config := new(Config)
			tt.setPath(config, filepath.Join(t.TempDir(), "missing.json"))
			_, err := builder.Build(config)
			if err == nil || !strings.Contains(err.Error(), tt.wantRead) {
				t.Fatalf("error = %v, want %q", err, tt.wantRead)
			}
		})
		t.Run(tt.name+" JSON", func(t *testing.T) {
			config := new(Config)
			tt.setPath(config, writeCoreConfigFixture(t, "malformed.json", `{`))
			_, err := builder.Build(config)
			if err == nil || !strings.Contains(err.Error(), tt.wantDecode) {
				t.Fatalf("error = %v, want %q", err, tt.wantDecode)
			}
		})
	}
}

func TestCoreConfigBuilderReportsXrayBuildErrors(t *testing.T) {
	tests := []struct {
		name    string
		path    string
		setPath func(*Config, string)
		want    string
	}{
		{
			name:    "DNS",
			path:    `{"clientIp":"not-an-ip"}`,
			setPath: func(c *Config, path string) { c.DnsConfigPath = path },
			want:    "failed to understand DNS config",
		},
		{
			name:    "routing",
			path:    `{"rules":[{"type":"field","ip":["not-an-ip"],"outboundTag":"direct"}]}`,
			setPath: func(c *Config, path string) { c.RouteConfigPath = path },
			want:    "failed to understand routing config",
		},
		{
			name:    "inbound",
			path:    `[{"tag":"broken","port":12345,"protocol":"missing-protocol","settings":{}}]`,
			setPath: func(c *Config, path string) { c.InboundConfigPath = path },
			want:    "failed to understand inbound config",
		},
		{
			name:    "outbound",
			path:    `[{"tag":"broken","protocol":"missing-protocol","settings":{}}]`,
			setPath: func(c *Config, path string) { c.OutboundConfigPath = path },
			want:    "failed to understand outbound config",
		},
	}
	builder := coreConfigBuilder{
		newInstance: func(*core.Config) (*core.Instance, error) {
			t.Fatal("instance construction must not run after build errors")
			return nil, nil
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			config := new(Config)
			tt.setPath(config, writeCoreConfigFixture(t, tt.name+".json", tt.path))
			_, err := builder.Build(config)
			if err == nil || !strings.Contains(err.Error(), tt.want) {
				t.Fatalf("error = %v, want %q", err, tt.want)
			}
		})
	}
}

func TestCoreConfigBuilderReportsInstanceConstructionError(t *testing.T) {
	buildErr := errors.New("build core instance")
	builder := coreConfigBuilder{
		newInstance: func(*core.Config) (*core.Instance, error) {
			return nil, buildErr
		},
	}

	_, err := builder.Build(&Config{})
	if !errors.Is(err, buildErr) || !strings.Contains(err.Error(), "failed to create instance") {
		t.Fatalf("error = %v, want wrapped instance error", err)
	}
}

type coreConfigStartProbe struct {
	starts int
}

func (*coreConfigStartProbe) Type() interface{} {
	return (*coreConfigStartProbe)(nil)
}

func (p *coreConfigStartProbe) Start() error {
	p.starts++
	return nil
}

func (*coreConfigStartProbe) Close() error {
	return nil
}

func TestCoreConfigBuilderDoesNotStartConstructedInstance(t *testing.T) {
	instance, err := core.New(&core.Config{})
	if err != nil {
		t.Fatal(err)
	}
	probe := new(coreConfigStartProbe)
	if err := instance.AddFeature(probe); err != nil {
		t.Fatal(err)
	}
	var captured *core.Config
	builder := capturingCoreConfigBuilder(&captured, instance)

	got, err := builder.Build(&Config{})
	if err != nil {
		t.Fatal(err)
	}
	if got != instance || captured == nil {
		t.Fatalf("unexpected construction result: instance=%p config=%#v", got, captured)
	}
	if probe.starts != 0 {
		t.Fatalf("configuration construction started core %d times", probe.starts)
	}
}
