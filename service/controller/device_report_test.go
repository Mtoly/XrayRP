package controller

import (
	"errors"
	"reflect"
	"testing"

	"github.com/Mtoly/XrayRP/api"
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
