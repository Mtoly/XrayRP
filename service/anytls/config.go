package anytls

import (
	"context"
	"fmt"
	"net/netip"
	"time"

	box "github.com/sagernet/sing-box"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing/common/json/badoption"

	"github.com/Mtoly/XrayRP/common/mylego"
	"github.com/Mtoly/XrayRP/service"
	"github.com/Mtoly/XrayRP/service/internal/singboxregistry"
)

func (s *AnyTLSService) buildSingBoxFor(spec runtimeBuildSpec) (*box.Box, string, error) {
	listenIP := s.config.ListenIP
	if listenIP == "" {
		listenIP = "0.0.0.0"
	}
	addr, err := netip.ParseAddr(listenIP)
	if err != nil {
		return nil, "", fmt.Errorf("invalid ListenIP %s: %w", listenIP, err)
	}
	port := spec.nodeInfo.Port
	if port == 0 {
		return nil, "", fmt.Errorf("invalid port 0")
	}
	if port > 65535 {
		return nil, "", fmt.Errorf("invalid port %d: must be between 1 and 65535", port)
	}

	ctx := context.Background()
	ctx = singboxregistry.WithFullRegistry(ctx)

	opts := option.Options{
		Log: &option.LogOptions{
			Level:     "warn",
			Timestamp: true,
		},
	}

	listen := option.ListenOptions{
		Listen:     (*badoption.Addr)(&addr),
		ListenPort: uint16(port),
	}

	tlsOpt, err := buildInboundTLSOptions(spec)
	if err != nil {
		return nil, "", err
	}

	padding := []string{}
	if spec.nodeInfo.AnyTLSConfig != nil && len(spec.nodeInfo.AnyTLSConfig.PaddingScheme) > 0 {
		padding = spec.nodeInfo.AnyTLSConfig.PaddingScheme
	}

	users := append([]option.AnyTLSUser(nil), spec.authUsers...)

	inOpts := &option.AnyTLSInboundOptions{
		ListenOptions: listen,
		Users:         users,
		PaddingScheme: padding,
		InboundTLSOptionsContainer: option.InboundTLSOptionsContainer{
			TLS: tlsOpt,
		},
	}

	opts.Inbounds = []option.Inbound{
		{
			Type:    "anytls",
			Tag:     spec.inboundTag,
			Options: inOpts,
		},
	}
	opts.Outbounds = []option.Outbound{
		{
			Type:    "direct",
			Tag:     "direct",
			Options: &option.DirectOutboundOptions{},
		},
	}

	boxInstance, err := box.New(box.Options{Context: ctx, Options: opts})
	if err != nil {
		return nil, "", err
	}

	tracker := &anyTLSTracker{svc: s}
	boxInstance.Router().AppendTracker(tracker)

	return boxInstance, spec.inboundTag, nil
}

func buildInboundTLSOptions(spec runtimeBuildSpec) (*option.InboundTLSOptions, error) {
	tlsOpt := &option.InboundTLSOptions{Enabled: true}
	if len(spec.certificatePEM) != 0 || len(spec.privateKeyPEM) != 0 {
		if len(spec.certificatePEM) == 0 || len(spec.privateKeyPEM) == 0 {
			return nil, fmt.Errorf("candidate certificate and private key must be provided together")
		}
		tlsOpt.Certificate = badoption.Listable[string]{string(spec.certificatePEM)}
		tlsOpt.Key = badoption.Listable[string]{string(spec.privateKeyPEM)}
		return tlsOpt, nil
	}

	certFile, keyFile, err := getOrIssueCert(spec.certConfig)
	if err != nil {
		return nil, err
	}
	tlsOpt.CertificatePath = certFile
	tlsOpt.KeyPath = keyFile
	return tlsOpt, nil
}

func getOrIssueCert(certConfig *mylego.CertConfig) (string, string, error) {
	if certConfig == nil {
		return "", "", fmt.Errorf("CertConfig is nil")
	}
	switch certConfig.CertMode {
	case "file":
		if certConfig.CertFile == "" || certConfig.KeyFile == "" {
			return "", "", fmt.Errorf("cert file path or key file path not exist")
		}
		return certConfig.CertFile, certConfig.KeyFile, nil
	case "content":
		return mylego.ContentCert(certConfig)
	case "dns":
		lego, err := mylego.New(certConfig)
		if err != nil {
			return "", "", err
		}
		return lego.DNSCert()
	case "http", "tls":
		lego, err := mylego.New(certConfig)
		if err != nil {
			return "", "", err
		}
		return lego.HTTPCert()
	default:
		return "", "", fmt.Errorf("unsupported certmode: %s", certConfig.CertMode)
	}
}

// certMonitor checks and renews the AnyTLS certificate when needed. When a
// renewal actually happens (ok == true), the AnyTLS sing-box instance is
// hot-reloaded so the new certificate is picked up without restarting the
// whole XrayR process.
func (s *AnyTLSService) certMonitor() error {
	ctx, cancel := service.WithDefaultTimeout(context.Background(), service.DefaultSyncTimeout)
	defer cancel()
	return s.certMonitorContext(ctx)
}

func (s *AnyTLSService) certMonitorContext(ctx context.Context) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if err := s.reloadMu.Lock(ctx); err != nil {
		return err
	}
	defer s.reloadMu.Unlock()
	if err := ctx.Err(); err != nil {
		return err
	}

	if s.beforeCertificateStateRead != nil {
		s.beforeCertificateStateRead()
	}
	if s.config == nil || s.config.CertConfig == nil {
		return nil
	}

	s.lifecycleMu.Lock()
	nodeInfo := s.nodeInfo
	s.lifecycleMu.Unlock()
	if nodeInfo == nil || !nodeInfo.EnableTLS {
		return nil
	}

	switch s.config.CertConfig.CertMode {
	case "dns", "http", "tls":
		s.lifecycleMu.Lock()
		if s.closed || s.state != stateRunning || s.box == nil || s.nodeInfo == nil {
			state := s.state
			s.lifecycleMu.Unlock()
			return fmt.Errorf("AnyTLS service cannot renew certificate from state %d", state)
		}
		s.state = stateReloading
		s.lifecycleMu.Unlock()
		defer func() {
			s.lifecycleMu.Lock()
			if s.state == stateReloading {
				s.state = stateRunning
			}
			s.lifecycleMu.Unlock()
		}()

		prepare := s.prepareRenewal
		if prepare == nil {
			prepare = defaultPrepareCertificateRenewal
		}
		renewal, err := prepare(s.config.CertConfig)
		if err != nil {
			return err
		}
		if renewal == nil {
			return fmt.Errorf("certificate renewal preparation returned nil")
		}
		if !renewal.Renewed() {
			return renewal.Rollback()
		}
		if s.logger != nil {
			s.logger.Infof("AnyTLS certificate renewed for %s, validating replacement runtime", s.config.CertConfig.CertDomain)
		}
		return s.reloadNodeWithCertificateLockedContext(ctx, nodeInfo, renewal)
	}

	return nil
}

func (s *AnyTLSService) certMonitorPeriodic() error {
	ctx, cancel := service.WithDefaultTimeout(context.Background(), service.DefaultSyncTimeout)
	defer cancel()
	return s.certMonitorPeriodicContext(ctx)
}

func (s *AnyTLSService) certMonitorPeriodicContext(ctx context.Context) error {
	if err := s.certMonitorContext(ctx); err != nil {
		s.health.RecordFailure(service.FailureStageCertificate, time.Now())
		if s.logger != nil {
			s.logger.Warn("certificate monitor failed; will retry")
		}
	} else {
		s.refreshCertificateExpiry()
	}
	return nil
}
