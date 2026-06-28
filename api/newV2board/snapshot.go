package newV2board

import (
	"encoding/json"
	"fmt"
	"strings"

	log "github.com/sirupsen/logrus"

	"github.com/Mtoly/XrayRP/api"
	"github.com/Mtoly/XrayRP/common"
)

const legacyUniProxyConfigPath = "/api/v1/server/UniProxy/config"
const xboardConfigPath = "/api/v2/server/config"

func (c *APIClient) configPath() string {
	if c != nil && c.MachineID > 0 {
		return xboardConfigPath
	}
	return legacyUniProxyConfigPath
}

func (c *APIClient) cachedUniProxySnapshot() (*serverConfig, bool) {
	value := c.resp.Load()
	if value == nil {
		return nil, false
	}
	snapshot, ok := value.(*serverConfig)
	if !ok || snapshot == nil {
		return nil, false
	}
	return snapshot, true
}

func (c *APIClient) storeUniProxySnapshot(snapshot *serverConfig) {
	if snapshot == nil {
		return
	}
	c.resp.Store(snapshot)
}

type normalizedUniProxySnapshot struct {
	raw      *serverConfig
	nodeType string
}

func normalizeUniProxySnapshot(snapshot *serverConfig, nodeType string) *normalizedUniProxySnapshot {
	if snapshot == nil {
		return nil
	}
	return &normalizedUniProxySnapshot{
		raw:      snapshot,
		nodeType: canonicalNodeType(nodeType),
	}
}

func (s *normalizedUniProxySnapshot) certConfig() *api.XrayRCertConfig {
	if s == nil || s.raw == nil || s.raw.CertConfig == nil {
		return nil
	}
	return &api.XrayRCertConfig{
		CertMode:    s.raw.CertConfig.CertMode,
		CertDomain:  s.raw.CertConfig.Domain,
		CertFile:    s.raw.CertConfig.CertFile,
		KeyFile:     s.raw.CertConfig.KeyFile,
		CertContent: s.raw.CertConfig.CertContent,
		KeyContent:  s.raw.CertConfig.KeyContent,
		Provider:    s.raw.CertConfig.Provider,
		Email:       s.raw.CertConfig.Email,
		DNSEnv:      s.raw.CertConfig.DNSEnv,
	}
}

func (s *normalizedUniProxySnapshot) baseConfig() *api.BaseConfig {
	if s == nil || s.raw == nil || (s.raw.BaseConfig.PushInterval <= 0 && s.raw.BaseConfig.PullInterval <= 0) {
		return nil
	}
	baseConfig := s.raw.BaseConfig
	return &baseConfig
}

func (s *normalizedUniProxySnapshot) rules(localRules []api.DetectRule) (*[]api.DetectRule, error) {
	if s == nil || s.raw == nil {
		return nil, fmt.Errorf("UniProxy snapshot unavailable before deriving rules")
	}

	ruleList := append([]api.DetectRule(nil), localRules...)
	for i := range s.raw.Routes {
		if s.raw.Routes[i].Action == "block" {
			pattern, err := common.SafeCompileRegex(strings.Join(s.raw.Routes[i].Match, "|"))
			if err != nil {
				log.Printf("Invalid route rule regex (index=%d): %s, skipping", i, err)
				continue
			}
			ruleList = append(ruleList, api.DetectRule{
				ID:      i,
				Pattern: pattern,
			})
		}
	}

	return &ruleList, nil
}

func (s *normalizedUniProxySnapshot) enrichNodeInfo(nodeInfo *api.NodeInfo) {
	if s == nil || s.raw == nil || nodeInfo == nil {
		return
	}
	nodeInfo.NameServerConfig = s.raw.parseDNSConfig()
	attachRoutePolicy(s.raw, nodeInfo)
}

func certConfigFromUniProxySnapshot(snapshot *serverConfig) *api.XrayRCertConfig {
	return normalizeUniProxySnapshot(snapshot, "").certConfig()
}

func baseConfigFromUniProxySnapshot(snapshot *serverConfig) *api.BaseConfig {
	return normalizeUniProxySnapshot(snapshot, "").baseConfig()
}

func (c *APIClient) GetBaseConfig() *api.BaseConfig {
	snapshot, ok := c.cachedUniProxySnapshot()
	if !ok {
		return nil
	}
	return baseConfigFromUniProxySnapshot(snapshot)
}

func rulesFromUniProxySnapshot(snapshot *serverConfig, localRules []api.DetectRule) (*[]api.DetectRule, error) {
	return normalizeUniProxySnapshot(snapshot, "").rules(localRules)
}

func nodeInfoUnsupportedTypeError(nodeType string) error {
	switch nodeType {
	case "Naive", "naive":
		return fmt.Errorf("node type 'naive' (NaïveProxy) is not supported by xray-core backend, please use a dedicated NaïveProxy backend")
	case "Mieru", "mieru":
		return fmt.Errorf("node type 'mieru' is not supported by xray-core backend, please use a dedicated Mieru backend")
	default:
		return fmt.Errorf("unsupported node type: %s", nodeType)
	}
}

func enrichNodeInfoFromUniProxySnapshot(snapshot *serverConfig, nodeInfo *api.NodeInfo) {
	normalizeUniProxySnapshot(snapshot, "").enrichNodeInfo(nodeInfo)
}

func canonicalNodeType(nodeType string) string {
	switch strings.ToLower(strings.TrimSpace(nodeType)) {
	case "vless":
		return "Vless"
	case "vmess", "v2ray":
		return "Vmess"
	case "trojan":
		return "Trojan"
	case "shadowsocks":
		return "Shadowsocks"
	case "hysteria", "hysteria2":
		return "Hysteria2"
	case "tuic":
		return "Tuic"
	case "anytls":
		return "AnyTLS"
	case "socks":
		return "Socks"
	case "http":
		return "HTTP"
	default:
		return strings.TrimSpace(nodeType)
	}
}

func (c *APIClient) nodeInfoFromUniProxySnapshot(snapshot *serverConfig) (*api.NodeInfo, error) {
	normalized := normalizeUniProxySnapshot(snapshot, c.NodeType)
	if normalized == nil {
		return nil, fmt.Errorf("UniProxy snapshot unavailable before deriving node info")
	}

	nodeType := normalized.nodeType
	var (
		nodeInfo *api.NodeInfo
		err      error
	)

	snapshot = normalized.raw
	switch nodeType {
	case "V2ray", "Vmess", "Vless":
		nodeInfo, err = c.parseV2rayNodeResponse(snapshot)
	case "Trojan":
		nodeInfo, err = c.parseTrojanNodeResponse(snapshot)
	case "Shadowsocks":
		nodeInfo, err = c.parseSSNodeResponse(snapshot)
	case "Hysteria2":
		nodeInfo, err = c.parseHysteria2NodeResponse(snapshot)
	case "Tuic":
		nodeInfo, err = c.parseTuicNodeResponse(snapshot)
	case "AnyTLS":
		nodeInfo, err = c.parseAnyTLSNodeResponse(snapshot)
	case "Socks":
		nodeInfo, err = c.parseSocksNodeResponse(snapshot)
	case "HTTP":
		nodeInfo, err = c.parseHTTPNodeResponse(snapshot)
	default:
		return nil, nodeInfoUnsupportedTypeError(c.NodeType)
	}
	if err != nil {
		return nil, err
	}
	nodeInfo.NodeType = nodeType
	normalized.enrichNodeInfo(nodeInfo)
	return nodeInfo, nil
}

func (c *APIClient) fetchUniProxySnapshot(useETag bool) (*serverConfig, error) {
	path := c.configPath()
	req := c.client.R().ForceContentType("application/json")
	if useETag {
		req.SetHeader("If-None-Match", c.eTags["node"])
	}

	res, err := req.Get(path)
	if useETag && res != nil && res.StatusCode() == 304 {
		return nil, fmt.Errorf(api.NodeNotModified)
	}

	if useETag && res != nil {
		if etag := res.Header().Get("Etag"); etag != "" && etag != c.eTags["node"] {
			c.eTags["node"] = etag
		}
	}

	cfgResp, err := c.parseResponse(res, path, err)
	if err != nil {
		return nil, err
	}

	snapshot := new(serverConfig)
	b, _ := cfgResp.Encode()
	if err := json.Unmarshal(b, snapshot); err != nil {
		return nil, err
	}

	c.storeUniProxySnapshot(snapshot)
	return snapshot, nil
}
