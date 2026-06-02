package controller

import (
	"reflect"
	"testing"

	"github.com/Mtoly/XrayRP/api"
)

func TestDeviceReportStateChangedOnly(t *testing.T) {
	state := newDeviceReportState()
	onlineUsers := []api.OnlineUser{
		{UID: 1, IP: "198.51.100.1"},
		{UID: 1, IP: "192.0.2.1"},
		{UID: 2, IP: "203.0.113.2"},
		{UID: 1, IP: "198.51.100.1"},
		{UID: 0, IP: "192.0.2.55"},
		{UID: 2, IP: "   "},
		{UID: 1, IP: " 192.0.2.1 "},
	}

	got, changed := state.BuildChangedReport(&onlineUsers)
	if !changed {
		t.Fatal("expected first snapshot to be reported as changed")
	}
	want := map[int][]string{
		1: []string{"192.0.2.1", "198.51.100.1"},
		2: []string{"203.0.113.2"},
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("unexpected normalized devices: got %#v want %#v", got, want)
	}

	reorderedSameSnapshot := []api.OnlineUser{
		{UID: 2, IP: "203.0.113.2"},
		{UID: 1, IP: "198.51.100.1"},
		{UID: 1, IP: "192.0.2.1"},
	}
	got, changed = state.BuildChangedReport(&reorderedSameSnapshot)
	if changed {
		t.Fatalf("expected equivalent snapshot to be unchanged, got %#v", got)
	}
	if got != nil {
		t.Fatalf("expected unchanged snapshot to return nil devices, got %#v", got)
	}
}

func TestDeviceReportStateReportsEmptyAfterNonEmpty(t *testing.T) {
	state := newDeviceReportState()
	onlineUsers := []api.OnlineUser{{UID: 1, IP: "192.0.2.1"}}
	if _, changed := state.BuildChangedReport(&onlineUsers); !changed {
		t.Fatal("expected first non-empty snapshot to be reported as changed")
	}

	emptyOnlineUsers := []api.OnlineUser{}
	got, changed := state.BuildChangedReport(&emptyOnlineUsers)
	if !changed {
		t.Fatal("expected empty snapshot after non-empty snapshot to be reported as changed")
	}
	want := map[int][]string{}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("unexpected empty devices: got %#v want %#v", got, want)
	}
}

func TestDeviceReportStateNilSnapshotIsStable(t *testing.T) {
	state := newDeviceReportState()

	got, changed := state.BuildChangedReport(nil)
	if !changed {
		t.Fatal("expected first nil snapshot to be reported as changed")
	}
	want := map[int][]string{}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("unexpected first nil devices: got %#v want %#v", got, want)
	}

	got, changed = state.BuildChangedReport(nil)
	if changed {
		t.Fatalf("expected repeated nil snapshot to be unchanged, got %#v", got)
	}
	if got != nil {
		t.Fatalf("expected repeated nil snapshot to return nil devices, got %#v", got)
	}
}
