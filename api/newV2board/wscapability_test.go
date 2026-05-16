package newV2board_test

import (
	"testing"

	"github.com/Mtoly/XrayRP/api"
	"github.com/Mtoly/XrayRP/api/bunpanel"
	"github.com/Mtoly/XrayRP/api/newV2board"
)

type stubAdapter struct{}

var _ api.API = stubAdapter{}

func (stubAdapter) GetNodeInfo() (*api.NodeInfo, error)               { return nil, nil }
func (stubAdapter) GetXrayRCertConfig() (*api.XrayRCertConfig, error) { return nil, nil }
func (stubAdapter) GetUserList() (*[]api.UserInfo, error)             { return nil, nil }
func (stubAdapter) GetAliveList() (map[int][]string, error)           { return nil, nil }
func (stubAdapter) ReportNodeStatus(*api.NodeStatus) error            { return nil }
func (stubAdapter) ReportNodeOnlineUsers(*[]api.OnlineUser) error     { return nil }
func (stubAdapter) ReportUserTraffic(*[]api.UserTraffic) error        { return nil }
func (stubAdapter) Describe() api.ClientInfo                          { return api.ClientInfo{} }
func (stubAdapter) GetNodeRule() (*[]api.DetectRule, error)           { return nil, nil }
func (stubAdapter) ReportIllegal(*[]api.DetectResult) error           { return nil }
func (stubAdapter) Debug()                                            {}

func TestWSCapNewV2boardOptIn(t *testing.T) {
	var client api.API = newV2board.New(&api.Config{
		APIHost:  "https://panel.example.com",
		Key:      "secret-token",
		NodeID:   7,
		NodeType: "V2ray",
	})

	capable, ok := client.(api.WSCapable)
	if !ok {
		t.Fatal("expected newV2board adapter to opt into api.WSCapable")
	}

	wsConfig := capable.GetWSConfig()
	if wsConfig == nil {
		t.Fatal("expected websocket config payload, got nil")
	}
	if wsConfig.APIHost != "https://panel.example.com" {
		t.Fatalf("unexpected ws config APIHost: got %q", wsConfig.APIHost)
	}
	if wsConfig.Key != "secret-token" {
		t.Fatalf("unexpected ws config Key: got %q", wsConfig.Key)
	}
	if wsConfig.NodeID != 7 {
		t.Fatalf("unexpected ws config NodeID: got %d", wsConfig.NodeID)
	}
	if wsConfig.NodeType != "V2ray" {
		t.Fatalf("unexpected ws config NodeType: got %q", wsConfig.NodeType)
	}
}

func TestWSCapOtherAdaptersRemainUnaffected(t *testing.T) {
	var client api.API = bunpanel.New(&api.Config{
		APIHost:  "https://panel.example.com",
		Key:      "secret-token",
		NodeID:   1,
		NodeType: "V2ray",
	})

	if _, ok := client.(api.WSCapable); ok {
		t.Fatal("expected bunpanel adapter to remain non-ws-capable")
	}
}

func TestWSCapBaseAPIContractRemainsOptional(t *testing.T) {
	var client api.API = stubAdapter{}

	if _, ok := client.(api.WSCapable); ok {
		t.Fatal("expected base api.API implementations to remain valid without ws capability")
	}
}
