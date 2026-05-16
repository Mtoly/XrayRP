package newV2board

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/Mtoly/XrayRP/api"
)

func TestGetXrayRCertConfigFetchesConfigWhenCacheEmpty(t *testing.T) {
	payload := `{
		"server_port": 443,
		"network": "tcp",
		"routes": [],
		"cert_config": {
			"provider": "alidns",
			"email": "ops@example.com",
			"dns_env": {
				"ALICLOUD_ACCESS_KEY": "ak",
				"ALICLOUD_SECRET_KEY": "sk"
			}
		}
	}`
	requestHeaders := make([]string, 0, 2)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requestHeaders = append(requestHeaders, r.Header.Get("If-None-Match"))
		if r.Header.Get("If-None-Match") != "" {
			w.WriteHeader(http.StatusNotModified)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Etag", "etag-1")
		_, _ = w.Write([]byte(payload))
	}))
	defer server.Close()

	client := New(&api.Config{APIHost: server.URL, NodeID: 1, NodeType: "V2ray"})

	cert, err := client.GetXrayRCertConfig()
	if err != nil {
		t.Fatalf("GetXrayRCertConfig returned error: %v", err)
	}
	if cert == nil {
		t.Fatal("expected cert config, got nil")
	}
	if cert.Provider != "alidns" || cert.Email != "ops@example.com" {
		t.Fatalf("unexpected cert config: %#v", cert)
	}
	if cert.DNSEnv["ALICLOUD_ACCESS_KEY"] != "ak" || cert.DNSEnv["ALICLOUD_SECRET_KEY"] != "sk" {
		t.Fatalf("unexpected cert env: %#v", cert.DNSEnv)
	}
	if len(requestHeaders) != 1 || requestHeaders[0] != "" {
		t.Fatalf("expected cert fetch without If-None-Match, got %#v", requestHeaders)
	}

	nodeInfo, err := client.GetNodeInfo()
	if err != nil {
		t.Fatalf("GetNodeInfo after cert fetch returned error: %v", err)
	}
	if nodeInfo == nil || nodeInfo.Port != 443 {
		t.Fatalf("unexpected node info after cert fetch: %#v", nodeInfo)
	}
	if len(requestHeaders) != 2 || requestHeaders[1] != "" {
		t.Fatalf("expected GetNodeInfo to avoid primed If-None-Match after cert fetch, got %#v", requestHeaders)
	}
}

func TestGetAliveListNormalizesAliveIPs(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"alive":{"1":["1.2.3.4_1","5.6.7.8_1"],"2":["9.9.9.9_1"]}}`))
	}))
	defer server.Close()

	client := New(&api.Config{APIHost: server.URL, NodeID: 1, NodeType: "V2ray"})
	alive, err := client.GetAliveList()
	if err != nil {
		t.Fatalf("GetAliveList returned error: %v", err)
	}
	if len(alive[1]) != 2 || alive[1][0] != "1.2.3.4" || alive[1][1] != "5.6.7.8" {
		t.Fatalf("unexpected normalized alive list for uid 1: %#v", alive[1])
	}
	if len(alive[2]) != 1 || alive[2][0] != "9.9.9.9" {
		t.Fatalf("unexpected normalized alive list for uid 2: %#v", alive[2])
	}
}

func TestParseV2rayNodeResponsePreservesRealityAndVlessFlow(t *testing.T) {
	cfg := &serverConfig{}
	cfg.ServerPort = 443
	cfg.Network = "tcp"
	cfg.Tls = 2
	cfg.VlessFlow = "xtls-rprx-vision"
	cfg.VlessTlsSettings.Dest = "origin.example.com"
	cfg.VlessTlsSettings.ServerPort = "8443"
	cfg.VlessTlsSettings.XVer = 1
	cfg.VlessTlsSettings.Sni = "panel.example.com"
	cfg.VlessTlsSettings.PrivateKey = "private-key"
	cfg.VlessTlsSettings.ShortId = "abcd"

	client := &APIClient{NodeID: 1, NodeType: "V2ray", EnableVless: true}
	nodeInfo, err := client.parseV2rayNodeResponse(cfg)
	if err != nil {
		t.Fatalf("parseV2rayNodeResponse returned error: %v", err)
	}
	if !nodeInfo.EnableREALITY {
		t.Fatal("expected EnableREALITY to be true")
	}
	if nodeInfo.REALITYConfig == nil {
		t.Fatal("expected REALITYConfig to be populated")
	}
	if nodeInfo.REALITYConfig.Dest != "origin.example.com:8443" {
		t.Fatalf("unexpected REALITY dest: %s", nodeInfo.REALITYConfig.Dest)
	}
	if len(nodeInfo.REALITYConfig.ShortIds) != 1 || nodeInfo.REALITYConfig.ShortIds[0] != "abcd" {
		t.Fatalf("unexpected REALITY short ids: %#v", nodeInfo.REALITYConfig.ShortIds)
	}
	if !nodeInfo.EnableVless {
		t.Fatal("expected EnableVless to be true")
	}
	if nodeInfo.VlessFlow != "xtls-rprx-vision" {
		t.Fatalf("unexpected VlessFlow: %s", nodeInfo.VlessFlow)
	}
}
