package gov2panel_test

import (
	"os"
	"testing"

	"github.com/Mtoly/XrayRP/api"
	"github.com/Mtoly/XrayRP/api/gov2panel"
	"github.com/gogf/gf/v2/encoding/gjson"
	"github.com/gogf/gf/v2/util/gconv"
)

func requireGov2panelIntegration(t *testing.T) {
	t.Helper()
	if os.Getenv("XRAYRP_RUN_GOV2PANEL_INTEGRATION") != "1" {
		t.Skip("skipping gov2panel integration test; set XRAYRP_RUN_GOV2PANEL_INTEGRATION=1 to enable")
	}
}

func CreateClient() api.API {
	apiConfig := &api.Config{
		APIHost:  "http://localhost:8080",
		Key:      "123456",
		NodeID:   90,
		NodeType: "V2ray",
	}
	client := gov2panel.New(apiConfig)
	return client
}

func TestGetNodeInfo(t *testing.T) {
	requireGov2panelIntegration(t)
	client := CreateClient()
	nodeInfo, err := client.GetNodeInfo()
	if err != nil {
		t.Error(err)
	}
	if nodeInfo == nil {
		t.Fatal("expected node info, got nil")
	}

	nodeInfoJson := gjson.New(nodeInfo)
	t.Log(nodeInfoJson.String())
	t.Log(nodeInfoJson.String())
}

func TestGetUserList(t *testing.T) {
	requireGov2panelIntegration(t)
	client := CreateClient()

	userList, err := client.GetUserList()
	if err != nil {
		t.Error(err)
		return
	}
	if userList == nil {
		t.Fatal("expected user list, got nil")
	}

	t.Log(len(*userList))
	t.Log(userList)
}

func TestReportReportUserTraffic(t *testing.T) {
	requireGov2panelIntegration(t)
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
	generalUserTraffic := make([]api.UserTraffic, len(*userList))
	for i, userInfo := range *userList {
		generalUserTraffic[i] = api.UserTraffic{
			UID:      userInfo.UID,
			Upload:   1073741824,
			Download: 1073741824,
		}
	}

	t.Log(gconv.String(generalUserTraffic))
	client = CreateClient()
	err = client.ReportUserTraffic(&generalUserTraffic)
	if err != nil {
		t.Error(err)
	}
}

func TestGetNodeRule(t *testing.T) {
	requireGov2panelIntegration(t)
	client := CreateClient()
	client.Debug()

	ruleList, err := client.GetNodeRule()
	if err != nil {
		t.Error(err)
	}

	t.Log(ruleList)
}
