package newV2board

import (
	"encoding/json"
	"fmt"

	"github.com/Mtoly/XrayRP/api"
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
