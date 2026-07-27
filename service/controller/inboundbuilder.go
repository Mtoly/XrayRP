// Package controller Package generate the InboundConfig used by add inbound
package controller

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strings"

	"github.com/sagernet/sing-shadowsocks/shadowaead_2022"
	C "github.com/sagernet/sing/common"
	"github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/core"
	"github.com/xtls/xray-core/infra/conf"

	"github.com/Mtoly/XrayRP/api"
	"github.com/Mtoly/XrayRP/common/mylego"
)

// InboundBuilderWithUsers is the compatibility adapter for callers that still
// provide api.NodeInfo. Internal controller paths call buildInboundWithUsers
// with the focused listener view.
func InboundBuilderWithUsers(config *Config, nodeInfo *api.NodeInfo, tag string, userInfo *[]api.UserInfo) (*core.InboundHandlerConfig, error) {
	return buildInboundWithUsers(config, normalizeNodeInfo(nodeInfo).inboundView().listener, tag, userInfo)
}

func buildInboundWithUsers(config *Config, node inboundListenerView, tag string, userInfo *[]api.UserInfo) (*core.InboundHandlerConfig, error) {
	inboundDetourConfig := &conf.InboundDetourConfig{}
	if config.ListenIP != "" {
		ipAddress := net.ParseAddress(config.ListenIP)
		inboundDetourConfig.ListenOn = &conf.Address{Address: ipAddress}
	}
	portList := &conf.PortList{
		Range: []conf.PortRange{{From: node.port, To: node.port}},
	}
	inboundDetourConfig.PortList = portList
	inboundDetourConfig.Tag = tag

	sniffingConfig := &conf.SniffingConfig{
		Enabled:      true,
		DestOverride: &conf.StringList{"http", "tls", "quic", "fakedns"},
	}
	if config.DisableSniffing {
		sniffingConfig.Enabled = false
	}
	inboundDetourConfig.SniffingConfig = sniffingConfig

	var proxySetting any
	var protocol string

	switch node.nodeType {
	case "Socks":
		protocol = "socks"
		accounts := make([]*conf.SocksAccount, 0, len(*userInfo))
		for _, u := range *userInfo {
			if u.UUID == "" {
				continue
			}
			accounts = append(accounts, &conf.SocksAccount{
				Username: u.UUID,
				Password: u.UUID,
			})
		}
		proxySetting = &conf.SocksServerConfig{
			AuthMethod: "password",
			Accounts:   accounts,
			UDP:        true,
		}
	case "HTTP":
		protocol = "http"
		accounts := make([]*conf.HTTPAccount, 0, len(*userInfo))
		for _, u := range *userInfo {
			if u.UUID == "" {
				continue
			}
			accounts = append(accounts, &conf.HTTPAccount{
				Username: u.UUID,
				Password: u.UUID,
			})
		}
		proxySetting = &conf.HTTPServerConfig{
			Accounts: accounts,
		}
	default:
		return nil, fmt.Errorf("InboundBuilderWithUsers only supports Socks and HTTP, got: %s", node.nodeType)
	}

	setting, err := json.Marshal(proxySetting)
	if err != nil {
		return nil, fmt.Errorf("marshal proxy %s config failed: %s", node.nodeType, err)
	}
	inboundDetourConfig.Protocol = protocol
	rawSetting := json.RawMessage(setting)
	inboundDetourConfig.Settings = &rawSetting

	// Build streamSettings (tcp only for socks/http)
	streamSetting := new(conf.StreamConfig)
	transportProtocol := conf.TransportProtocol("tcp")
	streamSetting.Network = &transportProtocol
	tcpSetting := &conf.TCPConfig{
		AcceptProxyProtocol: config.EnableProxyProtocol,
	}
	streamSetting.TCPSettings = tcpSetting

	// TLS for HTTP proxy (HTTPS)
	if node.enableTLS && config.CertConfig != nil && config.CertConfig.CertMode != "none" {
		streamSetting.Security = "tls"
		certificate, err := buildTLSCertificateConfig(config)
		if err != nil {
			return nil, err
		}
		tlsSettings := &conf.TLSConfig{
			RejectUnknownSNI: config.CertConfig.RejectUnknownSni,
		}
		tlsSettings.Certs = append(tlsSettings.Certs, certificate)
		streamSetting.TLSSettings = tlsSettings
	}

	inboundDetourConfig.StreamSetting = streamSetting
	return inboundDetourConfig.Build()
}

// InboundBuilder is the compatibility adapter for callers that still provide
// api.NodeInfo. Internal controller paths call buildInbound with a focused view.
func InboundBuilder(config *Config, nodeInfo *api.NodeInfo, tag string) (*core.InboundHandlerConfig, error) {
	return buildInbound(config, normalizeNodeInfo(nodeInfo).inboundView(), tag)
}

func buildInbound(config *Config, node inboundNodeView, tag string) (*core.InboundHandlerConfig, error) {
	inboundDetourConfig := &conf.InboundDetourConfig{}
	// Build Listen IP address
	if node.listener.nodeType == "Shadowsocks-Plugin" {
		// Shdowsocks listen in 127.0.0.1 for safety
		inboundDetourConfig.ListenOn = &conf.Address{Address: net.ParseAddress("127.0.0.1")}
	} else if config.ListenIP != "" {
		ipAddress := net.ParseAddress(config.ListenIP)
		inboundDetourConfig.ListenOn = &conf.Address{Address: ipAddress}
	}

	// Build Port
	portList := &conf.PortList{
		Range: []conf.PortRange{{From: node.listener.port, To: node.listener.port}},
	}
	inboundDetourConfig.PortList = portList
	// Build Tag
	inboundDetourConfig.Tag = tag
	// SniffingConfig
	sniffingConfig := &conf.SniffingConfig{
		Enabled:      true,
		DestOverride: &conf.StringList{"http", "tls", "quic", "fakedns"},
	}
	if config.DisableSniffing {
		sniffingConfig.Enabled = false
	}
	inboundDetourConfig.SniffingConfig = sniffingConfig

	var (
		protocol      string
		streamSetting *conf.StreamConfig
		setting       json.RawMessage
	)

	var proxySetting any
	// Build Protocol and Protocol setting
	switch node.listener.nodeType {
	case "V2ray", "Vmess", "Vless", "VLESS":
		//  Protocol selection is driven solely by NodeType
		useVless := node.enableVless || strings.EqualFold(node.listener.nodeType, "Vless") || strings.EqualFold(node.listener.nodeType, "VLESS")
		if useVless {
			protocol = "vless"
			if config.EnableFallback {
				fallbackConfigs, err := buildVlessFallbacks(config.FallBackConfigs)
				if err == nil {
					proxySetting = &conf.VLessInboundConfig{
						Decryption: "none",
						Fallbacks:  fallbackConfigs,
					}
				} else {
					return nil, err
				}
			} else {
				proxySetting = &conf.VLessInboundConfig{
					Decryption: "none",
				}
			}
		} else {
			protocol = "vmess"
			proxySetting = &conf.VMessInboundConfig{}
		}
	case "Trojan":
		protocol = "trojan"
		if config.EnableFallback {
			fallbackConfigs, err := buildTrojanFallbacks(config.FallBackConfigs)
			if err == nil {
				proxySetting = &conf.TrojanServerConfig{
					Fallbacks: fallbackConfigs,
				}
			} else {
				return nil, err
			}
		} else {
			proxySetting = &conf.TrojanServerConfig{}
		}
	case "Shadowsocks", "Shadowsocks-Plugin":
		protocol = "shadowsocks"
		cipher := strings.ToLower(node.cypherMethod)

		proxySetting = &conf.ShadowsocksServerConfig{
			Cipher:   cipher,
			Password: node.serverKey, // shadowsocks2022 shareKey
		}

		proxySetting, _ := proxySetting.(*conf.ShadowsocksServerConfig)
		b := make([]byte, 32)
		if _, err := rand.Read(b); err != nil {
			return nil, fmt.Errorf("failed to generate random password: %w", err)
		}
		randPasswd := hex.EncodeToString(b)
		if C.Contains(shadowaead_2022.List, cipher) {
			proxySetting.Users = append(proxySetting.Users, &conf.ShadowsocksUserConfig{
				Password: base64.StdEncoding.EncodeToString(b),
			})
		} else {
			proxySetting.Password = randPasswd
		}

		proxySetting.NetworkList = &conf.NetworkList{"tcp", "udp"}

	case "dokodemo-door":
		protocol = "dokodemo-door"
		proxySetting = struct {
			Host        string   `json:"address"`
			NetworkList []string `json:"network"`
		}{
			Host:        "v1.mux.cool",
			NetworkList: []string{"tcp", "udp"},
		}
	case "Socks":
		protocol = "socks"
		proxySetting = &conf.SocksServerConfig{
			AuthMethod: "password",
			Accounts:   []*conf.SocksAccount{}, // users managed via full rebuild
			UDP:        true,
		}
	case "HTTP":
		protocol = "http"
		proxySetting = &conf.HTTPServerConfig{
			Accounts: []*conf.HTTPAccount{}, // users managed via full rebuild
		}
	default:
		return nil, fmt.Errorf("unsupported node type: %s, Only support: Vmess, VLESS, Trojan, Shadowsocks, Shadowsocks-Plugin, Socks, and HTTP", node.listener.nodeType)
	}

	setting, err := json.Marshal(proxySetting)
	if err != nil {
		return nil, fmt.Errorf("marshal proxy %s config failed: %s", node.listener.nodeType, err)
	}
	inboundDetourConfig.Protocol = protocol
	inboundDetourConfig.Settings = &setting

	// Build streamSettings
	streamSetting = new(conf.StreamConfig)
	transportProtocol := conf.TransportProtocol(node.transport.protocol)
	networkType, err := transportProtocol.Build()
	if err != nil {
		return nil, fmt.Errorf("convert TransportProtocol failed: %s", err)
	}

	switch networkType {
	case "tcp":
		tcpSetting := &conf.TCPConfig{
			AcceptProxyProtocol: config.EnableProxyProtocol || node.transport.acceptProxyProtocol,
			HeaderConfig:        node.transport.header,
		}
		streamSetting.TCPSettings = tcpSetting
	case "websocket":
		headers := make(map[string]string)
		headers["Host"] = node.transport.host
		wsSettings := &conf.WebSocketConfig{
			AcceptProxyProtocol: config.EnableProxyProtocol || node.transport.acceptProxyProtocol,
			Host:                node.transport.host,
			Path:                node.transport.path,
			Headers:             headers,
		}
		streamSetting.WSSettings = wsSettings
	case "grpc":
		grpcSettings := &conf.GRPCConfig{
			ServiceName: node.transport.serviceName,
			Authority:   node.transport.authority,
		}
		streamSetting.GRPCSettings = grpcSettings
	case "httpupgrade":
		httpupgradeSettings := &conf.HttpUpgradeConfig{
			Headers:             node.transport.headers,
			Path:                node.transport.path,
			Host:                node.transport.host,
			AcceptProxyProtocol: config.EnableProxyProtocol || node.transport.acceptProxyProtocol,
		}
		streamSetting.HTTPUPGRADESettings = httpupgradeSettings
	case "splithttp", "xhttp":
		splithttpSetting := &conf.SplitHTTPConfig{
			Path:                node.transport.path,
			Host:                node.transport.host,
			Mode:                node.transport.xhttpMode,
			Extra:               node.transport.xhttpExtra,
			XPaddingObfsMode:    node.transport.xPaddingObfsMode,
			XPaddingKey:         node.transport.xPaddingKey,
			XPaddingHeader:      node.transport.xPaddingHeader,
			XPaddingPlacement:   node.transport.xPaddingPlacement,
			XPaddingMethod:      node.transport.xPaddingMethod,
			UplinkHTTPMethod:    node.transport.uplinkHTTPMethod,
			SessionPlacement:    node.transport.sessionPlacement,
			SessionKey:          node.transport.sessionKey,
			SeqPlacement:        node.transport.seqPlacement,
			SeqKey:              node.transport.seqKey,
			UplinkDataPlacement: node.transport.uplinkDataPlacement,
			UplinkDataKey:       node.transport.uplinkDataKey,
			UplinkChunkSize:     conf.Int32Range{From: int32(node.transport.uplinkChunkSize), To: int32(node.transport.uplinkChunkSize)},
			NoGRPCHeader:        node.transport.noGRPCHeader,
			NoSSEHeader:         node.transport.noSSEHeader,
			ScMaxBufferedPosts:  node.transport.scMaxBufferedPosts,
			Headers:             node.transport.headers,
		}
		if node.transport.xPaddingBytes.set {
			splithttpSetting.XPaddingBytes = conf.Int32Range{
				From: node.transport.xPaddingBytes.from,
				To:   node.transport.xPaddingBytes.to,
			}
		}
		if node.transport.scMaxEachPostBytes.set {
			splithttpSetting.ScMaxEachPostBytes = conf.Int32Range{
				From: node.transport.scMaxEachPostBytes.from,
				To:   node.transport.scMaxEachPostBytes.to,
			}
		}
		if node.transport.scMinPostsIntervalMS.set {
			splithttpSetting.ScMinPostsIntervalMs = conf.Int32Range{
				From: node.transport.scMinPostsIntervalMS.from,
				To:   node.transport.scMinPostsIntervalMS.to,
			}
		}
		if node.transport.scStreamUpServerSecs.set {
			splithttpSetting.ScStreamUpServerSecs = conf.Int32Range{
				From: node.transport.scStreamUpServerSecs.from,
				To:   node.transport.scStreamUpServerSecs.to,
			}
		}
		if node.transport.xmuxMaxConcurrency.set || node.transport.xmuxMaxConnections.set {
			splithttpSetting.Xmux = conf.XmuxConfig{
				HKeepAlivePeriod: node.transport.xmuxHKeepAlivePeriod,
			}
			if node.transport.xmuxMaxConcurrency.set {
				splithttpSetting.Xmux.MaxConcurrency = conf.Int32Range{
					From: node.transport.xmuxMaxConcurrency.from,
					To:   node.transport.xmuxMaxConcurrency.to,
				}
			}
			if node.transport.xmuxMaxConnections.set {
				splithttpSetting.Xmux.MaxConnections = conf.Int32Range{
					From: node.transport.xmuxMaxConnections.from,
					To:   node.transport.xmuxMaxConnections.to,
				}
			}
			if node.transport.xmuxCMaxReuseTimes.set {
				splithttpSetting.Xmux.CMaxReuseTimes = conf.Int32Range{
					From: node.transport.xmuxCMaxReuseTimes.from,
					To:   node.transport.xmuxCMaxReuseTimes.to,
				}
			}
			if node.transport.xmuxHMaxRequestTimes.set {
				splithttpSetting.Xmux.HMaxRequestTimes = conf.Int32Range{
					From: node.transport.xmuxHMaxRequestTimes.from,
					To:   node.transport.xmuxHMaxRequestTimes.to,
				}
			}
			if node.transport.xmuxHMaxReusableSecs.set {
				splithttpSetting.Xmux.HMaxReusableSecs = conf.Int32Range{
					From: node.transport.xmuxHMaxReusableSecs.from,
					To:   node.transport.xmuxHMaxReusableSecs.to,
				}
			}
		}
		streamSetting.SplitHTTPSettings = splithttpSetting
	}
	streamSetting.Network = &transportProtocol

	// Build TLS and REALITY settings
	var isREALITY bool
	// Prefer panel-provided REALITY settings, but fall back to config.yml when
	// the panel marks the node as REALITY without sending full REALITY opts.
	if node.enableReality {
		if node.reality.set {
			r := node.reality
			if r.dest != "" && r.privateKey != "" {
				isREALITY = true
				streamSetting.Security = "reality"
				streamSetting.REALITYSettings = &conf.REALITYConfig{
					Dest:         []byte(`"` + r.dest + `"`),
					Xver:         r.proxyProtocolVer,
					ServerNames:  r.serverNames,
					PrivateKey:   r.privateKey,
					MinClientVer: r.minClientVer,
					MaxClientVer: r.maxClientVer,
					MaxTimeDiff:  r.maxTimeDiff,
					ShortIds:     r.shortIDs,
				}
			}
		}

		if !isREALITY && !config.DisableLocalREALITYConfig && config.EnableREALITY && config.REALITYConfigs != nil {
			r := config.REALITYConfigs
			if r.Dest != "" && r.PrivateKey != "" {
				isREALITY = true
				streamSetting.Security = "reality"
				streamSetting.REALITYSettings = &conf.REALITYConfig{
					Show:         r.Show,
					Dest:         []byte(`"` + r.Dest + `"`),
					Xver:         r.ProxyProtocolVer,
					ServerNames:  r.ServerNames,
					PrivateKey:   r.PrivateKey,
					MinClientVer: r.MinClientVer,
					MaxClientVer: r.MaxClientVer,
					MaxTimeDiff:  r.MaxTimeDiff,
					ShortIds:     r.ShortIds,
				}
			}
		}
	}

	if !isREALITY && node.listener.enableTLS && config.CertConfig != nil && config.CertConfig.CertMode != "none" {
		streamSetting.Security = "tls"
		certificate, err := buildTLSCertificateConfig(config)
		if err != nil {
			return nil, err
		}
		tlsSettings := &conf.TLSConfig{
			RejectUnknownSNI: config.CertConfig.RejectUnknownSni,
		}
		tlsSettings.Certs = append(tlsSettings.Certs, certificate)
		streamSetting.TLSSettings = tlsSettings
	}

	// Support ProxyProtocol for any transport protocol
	if networkType != "tcp" && networkType != "ws" && (config.EnableProxyProtocol || node.transport.acceptProxyProtocol) {
		sockoptConfig := &conf.SocketConfig{
			AcceptProxyProtocol: config.EnableProxyProtocol || node.transport.acceptProxyProtocol,
		}
		streamSetting.SocketSettings = sockoptConfig
	}
	inboundDetourConfig.StreamSetting = streamSetting

	return inboundDetourConfig.Build()
}

func buildTLSCertificateConfig(config *Config) (*conf.TLSCertConfig, error) {
	if config == nil || config.CertConfig == nil {
		return nil, errors.New("certificate config is nil")
	}
	certConfig := config.CertConfig
	certificate := &conf.TLSCertConfig{OcspStapling: 3600}
	if certConfig.CertMode == "content" {
		if strings.TrimSpace(certConfig.CertContent) == "" || strings.TrimSpace(certConfig.KeyContent) == "" {
			return nil, errors.New("cert_mode content requires both cert_content and key_content")
		}
		certificate.CertStr = []string{certConfig.CertContent}
		certificate.KeyStr = []string{certConfig.KeyContent}
		return certificate, nil
	}
	certFile, keyFile, err := getCertFile(certConfig)
	if err != nil {
		return nil, err
	}
	certificate.CertFile = certFile
	certificate.KeyFile = keyFile
	return certificate, nil
}

func getCertFile(certConfig *mylego.CertConfig) (certFile string, keyFile string, err error) {
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
		certPath, keyPath, err := lego.DNSCert()
		if err != nil {
			return "", "", err
		}
		return certPath, keyPath, err
	case "http", "tls":
		lego, err := mylego.New(certConfig)
		if err != nil {
			return "", "", err
		}
		certPath, keyPath, err := lego.HTTPCert()
		if err != nil {
			return "", "", err
		}
		return certPath, keyPath, err
	default:
		return "", "", fmt.Errorf("unsupported certmode: %s", certConfig.CertMode)
	}
}

func buildVlessFallbacks(fallbackConfigs []*FallBackConfig) ([]*conf.VLessInboundFallback, error) {
	if fallbackConfigs == nil {
		return nil, fmt.Errorf("you must provide FallBackConfigs")
	}

	vlessFallBacks := make([]*conf.VLessInboundFallback, len(fallbackConfigs))
	for i, c := range fallbackConfigs {

		if c.Dest == "" {
			return nil, fmt.Errorf("dest is required for fallback failed")
		}

		var dest json.RawMessage
		dest, err := json.Marshal(c.Dest)
		if err != nil {
			return nil, fmt.Errorf("marshal dest %s config failed: %s", dest, err)
		}
		vlessFallBacks[i] = &conf.VLessInboundFallback{
			Name: c.SNI,
			Alpn: c.Alpn,
			Path: c.Path,
			Dest: dest,
			Xver: c.ProxyProtocolVer,
		}
	}
	return vlessFallBacks, nil
}

func buildTrojanFallbacks(fallbackConfigs []*FallBackConfig) ([]*conf.TrojanInboundFallback, error) {
	if fallbackConfigs == nil {
		return nil, fmt.Errorf("you must provide FallBackConfigs")
	}

	trojanFallBacks := make([]*conf.TrojanInboundFallback, len(fallbackConfigs))
	for i, c := range fallbackConfigs {

		if c.Dest == "" {
			return nil, fmt.Errorf("dest is required for fallback failed")
		}

		var dest json.RawMessage
		dest, err := json.Marshal(c.Dest)
		if err != nil {
			return nil, fmt.Errorf("marshal dest %s config failed: %s", dest, err)
		}
		trojanFallBacks[i] = &conf.TrojanInboundFallback{
			Name: c.SNI,
			Alpn: c.Alpn,
			Path: c.Path,
			Dest: dest,
			Xver: c.ProxyProtocolVer,
		}
	}
	return trojanFallBacks, nil
}
