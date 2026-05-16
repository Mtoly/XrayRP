package v2raysocks_test

import (
	"os"
	"testing"

	"github.com/Mtoly/XrayRP/api"
	"github.com/Mtoly/XrayRP/api/v2raysocks"
)

func requireV2RaySocksIntegration(t *testing.T) {
	t.Helper()
	if os.Getenv("XRAYRP_RUN_V2RAYSOCKS_INTEGRATION") != "1" {
		t.Skip("skipping v2raysocks integration test; set XRAYRP_RUN_V2RAYSOCKS_INTEGRATION=1 to enable")
	}
}

func CreateClient() api.API {
	apiConfig := &api.Config{
		APIHost:  "https://127.0.0.1/",
		Key:      "123456789",
		NodeID:   280002,
		NodeType: "V2ray",
	}
	client := v2raysocks.New(apiConfig)
	return client
}

func TestGetV2rayNodeinfo(t *testing.T) {
	requireV2RaySocksIntegration(t)
	client := CreateClient()
	client.Debug()
	nodeInfo, err := client.GetNodeInfo()
	if err != nil {
		t.Error(err)
	}
	t.Log(nodeInfo)
}

func TestGetSSNodeinfo(t *testing.T) {
	requireV2RaySocksIntegration(t)
	apiConfig := &api.Config{
		APIHost:  "https://127.0.0.1/",
		Key:      "123456789",
		NodeID:   280009,
		NodeType: "Shadowsocks",
	}
	client := v2raysocks.New(apiConfig)
	nodeInfo, err := client.GetNodeInfo()
	if err != nil {
		t.Error(err)
	}
	t.Log(nodeInfo)
}

func TestGetTrojanNodeinfo(t *testing.T) {
	requireV2RaySocksIntegration(t)
	apiConfig := &api.Config{
		APIHost:  "https://127.0.0.1/",
		Key:      "123456789",
		NodeID:   280008,
		NodeType: "Trojan",
	}
	client := v2raysocks.New(apiConfig)
	nodeInfo, err := client.GetNodeInfo()
	if err != nil {
		t.Error(err)
	}
	t.Log(nodeInfo)
}

func TestGetUserList(t *testing.T) {
	requireV2RaySocksIntegration(t)
	client := CreateClient()

	userList, err := client.GetUserList()
	if err != nil {
		t.Error(err)
		return
	}
	if userList == nil {
		t.Fatal("expected user list, got nil")
	}

	t.Log(userList)
}

func TestReportReportUserTraffic(t *testing.T) {
	requireV2RaySocksIntegration(t)
	client := CreateClient()
	userList, err := client.GetUserList()
	if err != nil {
		t.Error(err)
		return
	}
	if userList == nil {
		t.Fatal("expected user list, got nil")
	}
	generalUserTraffic := make([]api.UserTraffic, len(*userList))
	for i, userInfo := range *userList {
		generalUserTraffic[i] = api.UserTraffic{
			UID:      userInfo.UID,
			Upload:   114514,
			Download: 114514,
		}
	}
	// client.Debug()
	err = client.ReportUserTraffic(&generalUserTraffic)
	if err != nil {
		t.Error(err)
	}
}

func TestGetNodeRule(t *testing.T) {
	requireV2RaySocksIntegration(t)
	client := CreateClient()
	client.Debug()
	ruleList, err := client.GetNodeRule()
	if err != nil {
		t.Error(err)
	}

	t.Log(ruleList)
}
