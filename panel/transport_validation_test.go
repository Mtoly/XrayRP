package panel

import (
	"errors"
	"testing"

	"github.com/Mtoly/XrayRP/api"
	"github.com/Mtoly/XrayRP/service/controller"
)

func TestValidatePanelAPIHostTransport(t *testing.T) {
	tests := []struct {
		name    string
		host    string
		wantErr error
	}{
		{name: "remote HTTPS", host: "https://panel.example.com/base"},
		{name: "IPv4 loopback HTTP", host: "http://127.0.0.1:667"},
		{name: "IPv6 loopback HTTP", host: "http://[::1]:667"},
		{name: "localhost HTTP", host: "http://localhost:667"},
		{name: "localhost subdomain HTTP", host: "http://panel.localhost:667"},
		{name: "remote HTTP", host: "http://panel.example.com", wantErr: ErrRemotePanelRequiresHTTPS},
		{name: "private network HTTP", host: "http://192.168.1.20", wantErr: ErrRemotePanelRequiresHTTPS},
		{name: "relative host", host: "panel.example.com", wantErr: errors.New("invalid")},
		{name: "unsupported scheme", host: "ws://panel.example.com", wantErr: errors.New("invalid")},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validatePanelAPIHost(tt.host)
			if tt.wantErr == nil {
				if err != nil {
					t.Fatalf("validatePanelAPIHost(%q) error = %v", tt.host, err)
				}
				return
			}
			if err == nil {
				t.Fatalf("validatePanelAPIHost(%q) returned nil error", tt.host)
			}
			if errors.Is(tt.wantErr, ErrRemotePanelRequiresHTTPS) && !errors.Is(err, ErrRemotePanelRequiresHTTPS) {
				t.Fatalf("error = %v, want %v", err, ErrRemotePanelRequiresHTTPS)
			}
		})
	}
}

func TestRuntimeConfigRejectsRemoteHTTPPanelHosts(t *testing.T) {
	t.Run("static node", func(t *testing.T) {
		config := &Config{NodesConfig: []*NodesConfig{{
			PanelType: "SSPanel",
			ApiConfig: &api.Config{APIHost: "http://panel.example.com"},
		}}}
		err := ValidateRuntimeConfig(config)
		if !errors.Is(err, ErrRemotePanelRequiresHTTPS) {
			t.Fatalf("ValidateRuntimeConfig() error = %v, want %v", err, ErrRemotePanelRequiresHTTPS)
		}
	})

	t.Run("machine mode before websocket derivation", func(t *testing.T) {
		config := validMachineModeConfig()
		config.MachineConfig.ApiHost = "http://panel.example.com"
		config.MachineConfig.ControllerConfig = &controller.Config{
			WebSocketConfig: &controller.WebSocketConfig{Enable: true},
		}
		err := ValidateRuntimeConfig(config)
		if !errors.Is(err, ErrRemotePanelRequiresHTTPS) {
			t.Fatalf("ValidateRuntimeConfig() error = %v, want %v", err, ErrRemotePanelRequiresHTTPS)
		}
	})
}

func TestRuntimeConfigAllowsLoopbackHTTPPanelHost(t *testing.T) {
	config := &Config{NodesConfig: []*NodesConfig{{
		PanelType: "SSPanel",
		ApiConfig: &api.Config{APIHost: "http://127.0.0.1:667"},
	}}}
	if err := ValidateRuntimeConfig(config); err != nil {
		t.Fatalf("ValidateRuntimeConfig() error = %v", err)
	}
}
