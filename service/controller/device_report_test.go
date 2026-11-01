package controller

import (
	"context"
	"errors"
	"io"
	"reflect"
	"testing"

	log "github.com/sirupsen/logrus"

	"github.com/Mtoly/XrayRP/api"
	"github.com/Mtoly/XrayRP/app/mydispatcher"
	"github.com/Mtoly/XrayRP/common/limiter"
)

type recordingDeviceReporter struct {
	reports []map[int][]string
	err     error
}

func (r *recordingDeviceReporter) Start() {}

func (r *recordingDeviceReporter) Stop() {}

func (r *recordingDeviceReporter) ReportDevices(devices map[int][]string) error {
	copied := make(map[int][]string, len(devices))
	for uid, ips := range devices {
		copied[uid] = append([]string(nil), ips...)
	}
	r.reports = append(r.reports, copied)
	return r.err
}

type readinessDeviceReporter struct {
	recordingDeviceReporter
	ready bool
}

func (r *readinessDeviceReporter) DeviceReporterReady() bool {
	return r.ready
}

func TestControllerReportOnlineDevicesSendsEmptyChangedSnapshotOverWS(t *testing.T) {
	controller, _ := newTestSyncApplyController(&fakeSyncApplyAPI{})
	reporter := &recordingDeviceReporter{}
	controller.wsRuntime = reporter
	controller.deviceReportState = newDeviceReportState()

	controller.reportOnlineDevices("tag", &[]api.OnlineUser{{UID: 1, IP: "192.0.2.1"}})
	controller.reportOnlineDevices("tag", &[]api.OnlineUser{})

	if len(reporter.reports) != 2 {
		t.Fatalf("reports=%d", len(reporter.reports))
	}
	if want := map[int][]string{1: []string{"192.0.2.1"}}; !reflect.DeepEqual(reporter.reports[0], want) {
		t.Fatalf("first report=%#v, want %#v", reporter.reports[0], want)
	}
	if len(reporter.reports[1]) != 0 {
		t.Fatalf("second report should be empty: %#v", reporter.reports[1])
	}
}

func TestControllerReportOnlineDevicesDefersChangedSnapshotUntilReporterReady(t *testing.T) {
	controller, _ := newTestSyncApplyController(&fakeSyncApplyAPI{})
	reporter := &readinessDeviceReporter{}
	controller.wsRuntime = reporter
	controller.deviceReportState = newDeviceReportState()

	onlineUsers := []api.OnlineUser{{UID: 1, IP: "192.0.2.1"}}
	controller.reportOnlineDevices("tag", &onlineUsers)
	if len(reporter.reports) != 0 {
		t.Fatalf("expected no report while reporter is not ready, got %#v", reporter.reports)
	}

	reporter.ready = true
	controller.reportOnlineDevices("tag", &onlineUsers)
	if len(reporter.reports) != 1 {
		t.Fatalf("reports=%d, want 1 after reporter becomes ready", len(reporter.reports))
	}
	want := map[int][]string{1: []string{"192.0.2.1"}}
	if !reflect.DeepEqual(reporter.reports[0], want) {
		t.Fatalf("report=%#v, want %#v", reporter.reports[0], want)
	}

	controller.reportOnlineDevices("tag", &onlineUsers)
	if len(reporter.reports) != 1 {
		t.Fatalf("expected unchanged snapshot not to be reported again, reports=%d", len(reporter.reports))
	}
}

func TestControllerReportOnlineDevicesRetriesChangedSnapshotAfterReportError(t *testing.T) {
	controller, _ := newTestSyncApplyController(&fakeSyncApplyAPI{})
	reporter := &readinessDeviceReporter{ready: true}
	reporter.err = errors.New("send failed")
	controller.wsRuntime = reporter
	controller.deviceReportState = newDeviceReportState()

	onlineUsers := []api.OnlineUser{{UID: 1, IP: "192.0.2.1"}}
	controller.reportOnlineDevices("tag", &onlineUsers)
	if len(reporter.reports) != 1 {
		t.Fatalf("reports=%d, want first send attempt", len(reporter.reports))
	}

	reporter.err = nil
	controller.reportOnlineDevices("tag", &onlineUsers)
	if len(reporter.reports) != 2 {
		t.Fatalf("reports=%d, want retry after failed send", len(reporter.reports))
	}
	want := map[int][]string{1: []string{"192.0.2.1"}}
	if !reflect.DeepEqual(reporter.reports[1], want) {
		t.Fatalf("retry report=%#v, want %#v", reporter.reports[1], want)
	}

	controller.reportOnlineDevices("tag", &onlineUsers)
	if len(reporter.reports) != 2 {
		t.Fatalf("expected successful retry to commit snapshot, reports=%d", len(reporter.reports))
	}
}

type aliveSnapshotReportAPI struct {
	panelClientWithoutDebug
	reportErr     error
	snapshot      *api.AliveSnapshot
	snapshotErr   error
	reportCalls   int
	snapshotCalls int
	onReport      func(*[]api.OnlineUser)
}

func (a *aliveSnapshotReportAPI) ReportNodeOnlineUsers(users *[]api.OnlineUser) error {
	a.reportCalls++
	if a.onReport != nil {
		a.onReport(users)
	}
	return a.reportErr
}

func (a *aliveSnapshotReportAPI) GetAliveSnapshot() (*api.AliveSnapshot, error) {
	a.snapshotCalls++
	return a.snapshot, a.snapshotErr
}

func newDeviceSyncTestController(apiClient PanelClient, deviceLimiter *limiter.Limiter) *Controller {
	logger := log.New()
	logger.SetOutput(io.Discard)
	return &Controller{
		apiClient: apiClient,
		dispatcher: &mydispatcher.DefaultDispatcher{
			Limiter: deviceLimiter,
		},
		logger: log.NewEntry(logger),
	}
}

func TestControllerHTTPDeviceReceiptRequiresSuccessfulReportAndIsDetached(t *testing.T) {
	online := []api.OnlineUser{{UID: 1, IP: "192.0.2.1"}}
	apiClient := &aliveSnapshotReportAPI{
		onReport: func(users *[]api.OnlineUser) {
			if got := (*users)[0].IP; got != "192.0.2.1" {
				t.Fatalf("reported IP = %q, want detached source IP", got)
			}
			(*users)[0].IP = "198.51.100.99"
			online[0].IP = "203.0.113.99"
		},
	}
	controller := newDeviceSyncTestController(apiClient, limiter.New())

	receipt := controller.reportOnlineDevices("tag", &online)
	if got := receipt[1]; !reflect.DeepEqual(got, []string{"192.0.2.1"}) {
		t.Fatalf("report receipt = %#v, want original IP", receipt)
	}

	apiClient.onReport = nil
	apiClient.reportErr = errors.New("report failed")
	if receipt := controller.reportOnlineDevices("tag", &online); receipt != nil {
		t.Fatalf("failed HTTP report receipt = %#v, want nil", receipt)
	}
}

func TestControllerHTTPDeviceReceiptIsIndependentOfWebSocketSuccess(t *testing.T) {
	apiClient := &aliveSnapshotReportAPI{reportErr: errors.New("HTTP unavailable")}
	controller := newDeviceSyncTestController(apiClient, limiter.New())
	reporter := &recordingDeviceReporter{}
	controller.wsRuntime = reporter
	controller.deviceReportState = newDeviceReportState()

	online := []api.OnlineUser{{UID: 1, IP: "192.0.2.1"}}
	if receipt := controller.reportOnlineDevices("tag", &online); receipt != nil {
		t.Fatalf("WebSocket success produced an HTTP receipt: %#v", receipt)
	}
	if len(reporter.reports) != 1 {
		t.Fatalf("WebSocket reports = %d, want 1", len(reporter.reports))
	}
}

func TestControllerSuccessfulEmptyObservationReturnsEmptyReceiptWithoutHTTP(t *testing.T) {
	apiClient := &aliveSnapshotReportAPI{}
	controller := newDeviceSyncTestController(apiClient, limiter.New())

	receipt := controller.reportOnlineDevices("tag", &[]api.OnlineUser{})
	if receipt == nil || len(receipt) != 0 {
		t.Fatalf("empty observation receipt = %#v, want non-nil empty", receipt)
	}
	if apiClient.reportCalls != 0 {
		t.Fatalf("HTTP report calls = %d, want 0 for an empty observation", apiClient.reportCalls)
	}
}

func TestControllerCanceledCycleDoesNotReturnHTTPReceipt(t *testing.T) {
	apiClient := &aliveSnapshotReportAPI{}
	controller := newDeviceSyncTestController(apiClient, limiter.New())
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	receipt := controller.reportOnlineDevicesContext(ctx, "tag", &[]api.OnlineUser{{UID: 1, IP: "192.0.2.1"}})
	if receipt != nil {
		t.Fatalf("canceled report receipt = %#v, want nil", receipt)
	}
	if apiClient.reportCalls != 0 {
		t.Fatalf("canceled HTTP report calls = %d, want 0", apiClient.reportCalls)
	}
}

func TestControllerDeviceSyncPairsOnlySuccessfulHTTPReportWithFollowingSnapshot(t *testing.T) {
	deviceLimiter := limiter.New()
	users := []api.UserInfo{{UID: 1, Email: "new@example.test", DeviceLimit: 2}}
	if err := deviceLimiter.AddInboundLimiter("tag", 0, &users, nil); err != nil {
		t.Fatalf("AddInboundLimiter() error = %v", err)
	}
	userKey := "tag|new@example.test|1"
	if _, _, rejected := deviceLimiter.Admit("tag", userKey, "192.0.2.1", nil, nil); rejected {
		t.Fatal("initial local IP was rejected")
	}
	apiClient := &aliveSnapshotReportAPI{
		snapshot: &api.AliveSnapshot{Counts: map[int]int{1: 2}},
	}
	controller := newDeviceSyncTestController(apiClient, deviceLimiter)

	controller.reportAndSyncAliveSnapshotContext(
		context.Background(),
		"tag",
		&[]api.OnlineUser{{UID: 1, IP: "192.0.2.1"}},
	)
	if apiClient.reportCalls != 1 || apiClient.snapshotCalls != 1 {
		t.Fatalf("report/snapshot calls = %d/%d, want 1/1", apiClient.reportCalls, apiClient.snapshotCalls)
	}
	if _, _, rejected := deviceLimiter.Admit("tag", userKey, "198.51.100.1", nil, nil); !rejected {
		t.Fatal("successful same-cycle report/fetch pair did not apply the panel count")
	}
}

func TestControllerEmptyLocalNodeRefreshesPanelCountWithoutHTTPReport(t *testing.T) {
	deviceLimiter := limiter.New()
	users := []api.UserInfo{{UID: 1, Email: "one@example.test", DeviceLimit: 2}}
	if err := deviceLimiter.AddInboundLimiter("tag", 0, &users, nil); err != nil {
		t.Fatalf("AddInboundLimiter() error = %v", err)
	}
	apiClient := &aliveSnapshotReportAPI{
		snapshot: &api.AliveSnapshot{Counts: map[int]int{1: 2}},
	}
	controller := newDeviceSyncTestController(apiClient, deviceLimiter)

	controller.reportAndSyncAliveSnapshotContext(context.Background(), "tag", &[]api.OnlineUser{})
	if apiClient.reportCalls != 0 || apiClient.snapshotCalls != 1 {
		t.Fatalf("report/snapshot calls = %d/%d, want 0/1", apiClient.reportCalls, apiClient.snapshotCalls)
	}
	if _, _, rejected := deviceLimiter.Admit("tag", "tag|one@example.test|1", "192.0.2.1", nil, nil); !rejected {
		t.Fatal("empty local node did not adopt the full paired panel count")
	}
}

func TestControllerDevicePairFailurePreservesPreviousPanelCount(t *testing.T) {
	tests := []struct {
		name  string
		setup func(*aliveSnapshotReportAPI)
	}{
		{
			name: "report failure",
			setup: func(apiClient *aliveSnapshotReportAPI) {
				apiClient.reportErr = errors.New("report failed")
				apiClient.snapshot = &api.AliveSnapshot{Counts: map[int]int{1: 0}}
			},
		},
		{
			name: "fetch failure",
			setup: func(apiClient *aliveSnapshotReportAPI) {
				apiClient.snapshotErr = errors.New("snapshot failed")
			},
		},
		{
			name: "missing snapshot",
			setup: func(apiClient *aliveSnapshotReportAPI) {
				apiClient.snapshot = nil
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			deviceLimiter := limiter.New()
			users := []api.UserInfo{{UID: 1, Email: "one@example.test", DeviceLimit: 3}}
			if err := deviceLimiter.AddInboundLimiter("tag", 0, &users, nil); err != nil {
				t.Fatalf("AddInboundLimiter() error = %v", err)
			}
			apiClient := &aliveSnapshotReportAPI{
				snapshot: &api.AliveSnapshot{Counts: map[int]int{1: 2}},
			}
			controller := newDeviceSyncTestController(apiClient, deviceLimiter)
			controller.reportAndSyncAliveSnapshotContext(context.Background(), "tag", &[]api.OnlineUser{})
			if _, _, rejected := deviceLimiter.Admit("tag", "tag|one@example.test|1", "192.0.2.1", nil, nil); rejected {
				t.Fatal("pending local admission was rejected before failed synchronization")
			}

			test.setup(apiClient)
			controller.wsRuntime = &recordingDeviceReporter{}
			controller.deviceReportState = newDeviceReportState()
			controller.reportAndSyncAliveSnapshotContext(
				context.Background(),
				"tag",
				&[]api.OnlineUser{{UID: 1, IP: "192.0.2.1"}},
			)
			if _, _, rejected := deviceLimiter.Admit("tag", "tag|one@example.test|1", "198.51.100.1", nil, nil); !rejected {
				t.Fatal("failed report/fetch cycle overwrote the previous panel count")
			}
		})
	}
}
