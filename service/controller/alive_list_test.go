package controller

import (
	"bytes"
	"errors"
	"strings"
	"testing"

	log "github.com/sirupsen/logrus"

	"github.com/Mtoly/XrayRP/api"
	"github.com/Mtoly/XrayRP/app/mydispatcher"
	"github.com/Mtoly/XrayRP/common/limiter"
)

type aliveListTestAPI struct {
	panelClientWithoutDebug
	alive map[int][]string
	err   error
}

func (a aliveListTestAPI) GetAliveList() (map[int][]string, error) {
	return a.alive, a.err
}

func TestSyncAliveListFromPanelClassifiesCapabilityOutcomes(t *testing.T) {
	tests := []struct {
		name       string
		alive      map[int][]string
		err        error
		wantOnline []api.OnlineUser
		wantLog    string
		wantNoLog  string
	}{
		{
			name:       "unsupported preserves last known good",
			err:        errors.Join(errors.New("wrapped capability outcome"), api.ErrUnsupportedPanelFeature),
			wantOnline: []api.OnlineUser{{UID: 1, IP: "192.0.2.1"}},
			wantNoLog:  api.ErrUnsupportedPanelFeature.Error(),
		},
		{
			name:       "failed preserves last known good and logs",
			err:        errors.New("panel unavailable"),
			wantOnline: []api.OnlineUser{{UID: 1, IP: "192.0.2.1"}},
			wantLog:    "panel unavailable",
		},
		{
			name:       "absent snapshot preserves last known good",
			alive:      nil,
			wantOnline: []api.OnlineUser{{UID: 1, IP: "192.0.2.1"}},
		},
		{
			name:       "authoritative empty snapshot clears old state",
			alive:      map[int][]string{},
			wantOnline: []api.OnlineUser{},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			panelLimiter := limiter.New()
			users := []api.UserInfo{{UID: 1, Email: "one@example.com"}}
			if err := panelLimiter.AddInboundLimiter("inbound", 0, &users, nil); err != nil {
				t.Fatalf("AddInboundLimiter failed: %v", err)
			}
			if _, _, rejected := panelLimiter.Admit("inbound", "inbound|one@example.com|1", "192.0.2.1", nil, nil); rejected {
				t.Fatal("expected user IP to be accepted")
			}

			var output bytes.Buffer
			logger := log.New()
			logger.SetOutput(&output)
			controller := &Controller{
				apiClient: aliveListTestAPI{alive: test.alive, err: test.err},
				dispatcher: &mydispatcher.DefaultDispatcher{
					Limiter: panelLimiter,
				},
				logger: log.NewEntry(logger),
			}

			controller.syncAliveListFromPanel("inbound")

			online, err := panelLimiter.GetOnlineDevice("inbound")
			if err != nil {
				t.Fatalf("GetOnlineDevice failed: %v", err)
			}
			if len(*online) != len(test.wantOnline) {
				t.Fatalf("online devices = %#v, want %#v", *online, test.wantOnline)
			}
			for i := range test.wantOnline {
				if (*online)[i] != test.wantOnline[i] {
					t.Fatalf("online devices = %#v, want %#v", *online, test.wantOnline)
				}
			}
			if test.wantLog != "" && !strings.Contains(output.String(), test.wantLog) {
				t.Fatalf("log output = %q, want %q", output.String(), test.wantLog)
			}
			if test.wantNoLog != "" && strings.Contains(output.String(), test.wantNoLog) {
				t.Fatalf("log output = %q, did not want %q", output.String(), test.wantNoLog)
			}
		})
	}
}
