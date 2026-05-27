package newV2board

import (
	"encoding/json"
	"fmt"
	"strings"

	log "github.com/sirupsen/logrus"

	"github.com/Mtoly/XrayRP/api"
	"github.com/Mtoly/XrayRP/common"
)

const uniProxyConfigPath = "/api/v1/server/UniProxy/config"

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
		Provider: snapshot.CertConfig.Provider,
		Email:    snapshot.CertConfig.Email,
		DNSEnv:   snapshot.CertConfig.DNSEnv,
	}
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

func (c *APIClient) nodeInfoFromUniProxySnapshot(snapshot *serverConfig) (*api.NodeInfo, error) {
	if snapshot == nil {
		return nil, fmt.Errorf("UniProxy snapshot unavailable before deriving node info")
	}

	switch c.NodeType {
	case "V2ray", "Vmess", "Vless":
		return c.parseV2rayNodeResponse(snapshot)
	case "Trojan":
		return c.parseTrojanNodeResponse(snapshot)
	case "Shadowsocks":
		return c.parseSSNodeResponse(snapshot)
	case "Hysteria2", "hysteria2", "Hysteria", "hysteria":
		return c.parseHysteria2NodeResponse(snapshot)
	case "Tuic", "tuic":
		return c.parseTuicNodeResponse(snapshot)
	case "AnyTLS", "anytls":
		return c.parseAnyTLSNodeResponse(snapshot)
	case "Socks", "socks":
		return c.parseSocksNodeResponse(snapshot)
	case "HTTP", "http":
		return c.parseHTTPNodeResponse(snapshot)
	default:
		return nil, nodeInfoUnsupportedTypeError(c.NodeType)
	}
}

func (c *APIClient) fetchUniProxySnapshot(useETag bool) (*serverConfig, error) {
	req := c.client.R().ForceContentType("application/json")
	if useETag {
		req.SetHeader("If-None-Match", c.eTags["node"])
	}

	res, err := req.Get(uniProxyConfigPath)
	if useETag && res != nil && res.StatusCode() == 304 {
		return nil, fmt.Errorf(api.NodeNotModified)
	}

	if useETag && res != nil {
		if etag := res.Header().Get("Etag"); etag != "" && etag != c.eTags["node"] {
			c.eTags["node"] = etag
		}
	}

	cfgResp, err := c.parseResponse(res, uniProxyConfigPath, err)
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
