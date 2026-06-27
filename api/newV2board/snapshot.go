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

func certConfigFromUniProxySnapshot(snapshot *serverConfig) *api.XrayRCertConfig {
	if snapshot == nil || snapshot.CertConfig == nil {
		return nil
	}
	return &api.XrayRCertConfig{
		CertMode:    snapshot.CertConfig.CertMode,
		CertDomain:  snapshot.CertConfig.Domain,
		CertFile:    snapshot.CertConfig.CertFile,
		KeyFile:     snapshot.CertConfig.KeyFile,
		CertContent: snapshot.CertConfig.CertContent,
		KeyContent:  snapshot.CertConfig.KeyContent,
		Provider:    snapshot.CertConfig.Provider,
		Email:       snapshot.CertConfig.Email,
		DNSEnv:      snapshot.CertConfig.DNSEnv,
	}
}

func baseConfigFromUniProxySnapshot(snapshot *serverConfig) *api.BaseConfig {
	if snapshot == nil || (snapshot.BaseConfig.PushInterval <= 0 && snapshot.BaseConfig.PullInterval <= 0) {
		return nil
	}
	baseConfig := snapshot.BaseConfig
	return &baseConfig
}

func (c *APIClient) GetBaseConfig() *api.BaseConfig {
	snapshot, ok := c.cachedUniProxySnapshot()
	if !ok {
		return nil
	}
	return baseConfigFromUniProxySnapshot(snapshot)
}

func rulesFromUniProxySnapshot(snapshot *serverConfig, localRules []api.DetectRule) (*[]api.DetectRule, error) {
	if snapshot == nil {
		return nil, fmt.Errorf("UniProxy snapshot unavailable before deriving rules")
	}

	ruleList := append([]api.DetectRule(nil), localRules...)
	for i := range snapshot.Routes {
		if snapshot.Routes[i].Action == "block" {
			pattern, err := common.SafeCompileRegex(strings.Join(snapshot.Routes[i].Match, "|"))
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
	if snapshot == nil || nodeInfo == nil {
		return
	}
	nodeInfo.NameServerConfig = snapshot.parseDNSConfig()
	attachRoutePolicy(snapshot, nodeInfo)
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
	if snapshot == nil {
		return nil, fmt.Errorf("UniProxy snapshot unavailable before deriving node info")
	}

	nodeType := canonicalNodeType(c.NodeType)
	var (
		nodeInfo *api.NodeInfo
		err      error
	)

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
	enrichNodeInfoFromUniProxySnapshot(snapshot, nodeInfo)
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
