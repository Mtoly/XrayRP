package hysteria2

import (
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"time"

	"github.com/apernet/hysteria/core/v2/server"
	"github.com/apernet/hysteria/extras/v2/correctnet"
	"github.com/apernet/hysteria/extras/v2/obfs"

	"github.com/Mtoly/XrayRP/common/mylego"
	"github.com/Mtoly/XrayRP/service"
)

func (h *Hysteria2Service) buildServerConfigFor(spec serverBuildSpec) (*server.Config, error) {
	hy := spec.nodeInfo.Hysteria2Config
	if hy == nil {
		return nil, fmt.Errorf("Hysteria2Config is nil")
	}

	listenIP := h.config.ListenIP
	if listenIP == "" {
		listenIP = "0.0.0.0"
	}
	addr := fmt.Sprintf("%s:%d", listenIP, spec.nodeInfo.Port)

	udpAddr, err := net.ResolveUDPAddr("udp", addr)
	if err != nil {
		return nil, fmt.Errorf("resolve udp addr %s: %w", addr, err)
	}

	udpConn, err := correctnet.ListenUDP("udp", udpAddr)
	if err != nil {
		return nil, fmt.Errorf("listen udp %s: %w", addr, err)
	}

	var packetConn net.PacketConn = udpConn

	// Obfuscation
	obfsType := hy.Obfs
	if obfsType == "" {
		obfsType = "salamander"
	}
	switch obfsType {
	case "salamander":
		if hy.ObfsPassword == "" {
			udpConn.Close()
			return nil, fmt.Errorf("obfs_password is required when obfs is salamander")
		}
		packetConn, err = obfs.WrapPacketConnSalamander(udpConn, []byte(hy.ObfsPassword))
		if err != nil {
			udpConn.Close()
			return nil, fmt.Errorf("failed to create salamander obfuscator")
		}
	case "", "none", "plain":
		// no obfuscation
	default:
		udpConn.Close()
		return nil, fmt.Errorf("unsupported hysteria2 obfs: %s", hy.Obfs)
	}

	var cert tls.Certificate
	if len(spec.certificatePEM) != 0 || len(spec.privateKeyPEM) != 0 {
		if len(spec.certificatePEM) == 0 || len(spec.privateKeyPEM) == 0 {
			packetConn.Close()
			return nil, fmt.Errorf("candidate certificate and private key must be provided together")
		}
		cert, err = tls.X509KeyPair(spec.certificatePEM, spec.privateKeyPEM)
		if err != nil {
			packetConn.Close()
			return nil, fmt.Errorf("load candidate tls certificate: %w", err)
		}
	} else {
		certFile, keyFile, certErr := getOrIssueCert(spec.certConfig)
		if certErr != nil {
			packetConn.Close()
			return nil, certErr
		}
		cert, err = tls.LoadX509KeyPair(certFile, keyFile)
		if err != nil {
			packetConn.Close()
			return nil, fmt.Errorf("load tls cert: %w", err)
		}
	}

	bandwidth := server.BandwidthConfig{}
	if hy.UpMbps > 0 {
		bandwidth.MaxTx = uint64(hy.UpMbps) * 1000000 / 8
	}
	if hy.DownMbps > 0 {
		bandwidth.MaxRx = uint64(hy.DownMbps) * 1000000 / 8
	}

	cfg := &server.Config{
		TLSConfig: server.TLSConfig{
			Certificates: []tls.Certificate{cert},
		},
		QUICConfig: server.QUICConfig{},
		Conn:       packetConn,

		// Keep RequestHook nil as defense in depth. XrayRP does not need request
		// sniffing, and this keeps the affected parser outside the runtime path.
		RequestHook: nil,

		BandwidthConfig:       bandwidth,
		IgnoreClientBandwidth: hy.IgnoreClientBandwidth,
		Authenticator:         &hyAuthenticator{svc: h, authGate: spec.authGate},
		EventLogger:           &hyEventLogger{svc: h},
		TrafficLogger:         &hyTrafficLogger{svc: h, ctx: spec.trafficContext},
	}

	return cfg, nil
}

// getOrIssueCert mirrors controller.getCertFile but is local to the hysteria2
// package so we do not have to depend on unexported symbols.
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

// certMonitor checks and renews the certificate when needed.
func (h *Hysteria2Service) certMonitor() error {
	ctx, cancel := service.WithDefaultTimeout(context.Background(), service.DefaultSyncTimeout)
	defer cancel()
	return h.certMonitorContext(ctx)
}

func (h *Hysteria2Service) certMonitorContext(ctx context.Context) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if err := h.reloadMu.Lock(ctx); err != nil {
		return err
	}
	defer h.reloadMu.Unlock()
	if err := ctx.Err(); err != nil {
		return err
	}

	if h.beforeCertificateStateRead != nil {
		h.beforeCertificateStateRead()
	}
	if h.config == nil || h.config.CertConfig == nil {
		return nil
	}

	h.lifecycleMu.Lock()
	nodeInfo := h.nodeInfo
	h.lifecycleMu.Unlock()
	if nodeInfo == nil || !nodeInfo.EnableTLS {
		return nil
	}

	switch h.config.CertConfig.CertMode {
	case "dns", "http", "tls":
		h.lifecycleMu.Lock()
		if h.closed || h.state != stateRunning || h.server == nil || h.nodeInfo == nil {
			state := h.state
			h.lifecycleMu.Unlock()
			return fmt.Errorf("Hysteria2 service cannot renew certificate from state %d", state)
		}
		h.state = stateReloading
		h.lifecycleMu.Unlock()
		defer func() {
			h.lifecycleMu.Lock()
			if h.state == stateReloading {
				h.state = stateRunning
			}
			h.lifecycleMu.Unlock()
		}()

		prepare := h.prepareRenewal
		if prepare == nil {
			prepare = defaultPrepareCertificateRenewal
		}
		renewal, err := prepare(h.config.CertConfig)
		if err != nil {
			return err
		}
		if renewal == nil {
			return fmt.Errorf("certificate renewal preparation returned nil")
		}
		if !renewal.Renewed() {
			return renewal.Rollback()
		}
		if h.logger != nil {
			h.logger.Infof("Hysteria2 certificate renewed for %s, validating replacement runtime", h.config.CertConfig.CertDomain)
		}
		return h.reloadNodeWithCertificateLockedContext(ctx, nodeInfo, renewal)
	}

	return nil
}

func (h *Hysteria2Service) certMonitorPeriodic() error {
	ctx, cancel := service.WithDefaultTimeout(context.Background(), service.DefaultSyncTimeout)
	defer cancel()
	return h.certMonitorPeriodicContext(ctx)
}

func (h *Hysteria2Service) certMonitorPeriodicContext(ctx context.Context) error {
	if err := h.certMonitorContext(ctx); err != nil {
		h.health.RecordFailure(service.FailureStageCertificate, time.Now())
		if h.logger != nil {
			h.logger.Warn("certificate monitor failed; will retry")
		}
	} else {
		h.refreshCertificateExpiry()
	}
	return nil
}
