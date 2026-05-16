package controller

import (
	"errors"
	"testing"

	"github.com/sirupsen/logrus/hooks/test"

	"github.com/Mtoly/XrayRP/api"
)

type fakeIllegalAPI struct {
	reportIllegalErr error
}

func (f *fakeIllegalAPI) GetNodeInfo() (*api.NodeInfo, error)                    { return nil, nil }
func (f *fakeIllegalAPI) GetXrayRCertConfig() (*api.XrayRCertConfig, error)      { return nil, nil }
func (f *fakeIllegalAPI) GetUserList() (*[]api.UserInfo, error)                  { return nil, nil }
func (f *fakeIllegalAPI) GetAliveList() (map[int][]string, error)                { return nil, nil }
func (f *fakeIllegalAPI) ReportNodeStatus(*api.NodeStatus) error                 { return nil }
func (f *fakeIllegalAPI) ReportNodeOnlineUsers(*[]api.OnlineUser) error          { return nil }
func (f *fakeIllegalAPI) ReportUserTraffic(*[]api.UserTraffic) error             { return nil }
func (f *fakeIllegalAPI) Describe() api.ClientInfo                               { return api.ClientInfo{} }
func (f *fakeIllegalAPI) GetNodeRule() (*[]api.DetectRule, error)                { return nil, nil }
func (f *fakeIllegalAPI) ReportIllegal(*[]api.DetectResult) error                { return f.reportIllegalErr }
func (f *fakeIllegalAPI) Debug()                                                 {}

func TestPushIllegalResultsLogsFailure(t *testing.T) {
	logger, hook := test.NewNullLogger()
	c := &Controller{
		apiClient: &fakeIllegalAPI{reportIllegalErr: api.ErrUnsupportedPanelFeature},
		logger:    logger.WithField("module", "controller-test"),
	}

	detectResults := []api.DetectResult{{UID: 1, RuleID: 2, IP: "1.2.3.4"}}
	err := c.pushIllegalResults(&detectResults)
	if !errors.Is(err, api.ErrUnsupportedPanelFeature) {
		t.Fatalf("expected ErrUnsupportedPanelFeature, got %v", err)
	}

	entries := hook.AllEntries()
	if len(entries) == 0 {
		t.Fatal("expected at least one log entry")
	}
	if entries[len(entries)-1].Message != "Report illegal results failed" {
		t.Fatalf("unexpected log message: %s", entries[len(entries)-1].Message)
	}
}
