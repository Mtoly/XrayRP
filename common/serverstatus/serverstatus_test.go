package serverstatus

import (
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/shirou/gopsutil/v3/disk"
	"github.com/shirou/gopsutil/v3/mem"
	netio "github.com/shirou/gopsutil/v3/net"
)

func TestGetMachineStatusPreservesPartialStatusWhenCollectorsFail(t *testing.T) {
	resetServerStatusTestSeams(t)

	swapErr := errors.New("swap failed")
	cpuPercentFunc = func(time.Duration, bool) ([]float64, error) { return []float64{12.5}, nil }
	virtualMemoryFunc = func() (*mem.VirtualMemoryStat, error) { return &mem.VirtualMemoryStat{Total: 1000, Used: 400}, nil }
	swapMemoryFunc = func() (*mem.SwapMemoryStat, error) { return nil, swapErr }
	diskUsageFunc = func(string) (*disk.UsageStat, error) { return &disk.UsageStat{Total: 5000, Used: 1234}, nil }
	netIOCountersFunc = func(bool) ([]netio.IOCountersStat, error) {
		return []netio.IOCountersStat{{Name: "eth0", BytesRecv: 100, BytesSent: 200}}, nil
	}
	nowFunc = func() time.Time { return time.Unix(100, 0) }

	status, err := GetMachineStatus()
	if err == nil {
		t.Fatal("expected partial collector error")
	}
	if !strings.Contains(err.Error(), "swap failed") {
		t.Fatalf("expected swap error, got %v", err)
	}
	if status.CPU != 12.5 {
		t.Fatalf("expected CPU to be preserved, got %f", status.CPU)
	}
	if status.MemTotal != 1000 || status.MemUsed != 400 {
		t.Fatalf("expected mem totals to be preserved, got %#v", status)
	}
	if status.SwapTotal != 0 || status.SwapUsed != 0 {
		t.Fatalf("expected failed swap collector to leave zero values, got %#v", status)
	}
	if status.DiskTotal != 5000 || status.DiskUsed != 1234 {
		t.Fatalf("expected disk totals to be preserved, got %#v", status)
	}
	if status.NetInSpeed != -1 || status.NetOutSpeed != -1 {
		t.Fatalf("expected first net sample to be unavailable, got in=%f out=%f", status.NetInSpeed, status.NetOutSpeed)
	}
}

func TestCollectNetSpeedFirstSampleUnavailable(t *testing.T) {
	resetServerStatusTestSeams(t)

	netIOCountersFunc = func(bool) ([]netio.IOCountersStat, error) {
		return []netio.IOCountersStat{{Name: "eth0", BytesRecv: 100, BytesSent: 200}}, nil
	}
	nowFunc = func() time.Time { return time.Unix(100, 0) }

	inSpeed, outSpeed := collectNetSpeed()
	if inSpeed != -1 || outSpeed != -1 {
		t.Fatalf("expected first net sample to be unavailable, got in=%f out=%f", inSpeed, outSpeed)
	}
}

func TestCollectNetSpeedSkipsVirtualAndLoopbackInterfaces(t *testing.T) {
	resetServerStatusTestSeams(t)

	currentTime := time.Unix(100, 0)
	nowFunc = func() time.Time { return currentTime }

	samples := [][]netio.IOCountersStat{
		{
			{Name: "lo", BytesRecv: 9000, BytesSent: 9000},
			{Name: "docker0", BytesRecv: 9000, BytesSent: 9000},
			{Name: "vethabc", BytesRecv: 9000, BytesSent: 9000},
			{Name: "br-test", BytesRecv: 9000, BytesSent: 9000},
			{Name: "virbr0", BytesRecv: 9000, BytesSent: 9000},
			{Name: "vnet0", BytesRecv: 9000, BytesSent: 9000},
			{Name: "tun0", BytesRecv: 9000, BytesSent: 9000},
			{Name: "tap0", BytesRecv: 9000, BytesSent: 9000},
			{Name: "eth0", BytesRecv: 100, BytesSent: 200},
		},
		{
			{Name: "lo", BytesRecv: 19000, BytesSent: 19000},
			{Name: "docker0", BytesRecv: 19000, BytesSent: 19000},
			{Name: "vethabc", BytesRecv: 19000, BytesSent: 19000},
			{Name: "br-test", BytesRecv: 19000, BytesSent: 19000},
			{Name: "virbr0", BytesRecv: 19000, BytesSent: 19000},
			{Name: "vnet0", BytesRecv: 19000, BytesSent: 19000},
			{Name: "tun0", BytesRecv: 19000, BytesSent: 19000},
			{Name: "tap0", BytesRecv: 19000, BytesSent: 19000},
			{Name: "eth0", BytesRecv: 300, BytesSent: 600},
		},
	}
	call := 0
	netIOCountersFunc = func(bool) ([]netio.IOCountersStat, error) {
		if call >= len(samples) {
			t.Fatalf("unexpected net counter call %d", call+1)
		}
		result := samples[call]
		call++
		return result, nil
	}

	inSpeed, outSpeed := collectNetSpeed()
	if inSpeed != -1 || outSpeed != -1 {
		t.Fatalf("expected first net sample to be unavailable, got in=%f out=%f", inSpeed, outSpeed)
	}

	currentTime = currentTime.Add(2 * time.Second)
	inSpeed, outSpeed = collectNetSpeed()
	if inSpeed != 100 || outSpeed != 200 {
		t.Fatalf("expected only eth0 deltas to be counted, got in=%f out=%f", inSpeed, outSpeed)
	}
}

func resetServerStatusTestSeams(t *testing.T) {
	t.Helper()

	oldCPUPercentFunc := cpuPercentFunc
	oldVirtualMemoryFunc := virtualMemoryFunc
	oldSwapMemoryFunc := swapMemoryFunc
	oldDiskUsageFunc := diskUsageFunc
	oldNetIOCountersFunc := netIOCountersFunc
	oldNowFunc := nowFunc
	resetNetSpeedState()

	t.Cleanup(func() {
		cpuPercentFunc = oldCPUPercentFunc
		virtualMemoryFunc = oldVirtualMemoryFunc
		swapMemoryFunc = oldSwapMemoryFunc
		diskUsageFunc = oldDiskUsageFunc
		netIOCountersFunc = oldNetIOCountersFunc
		nowFunc = oldNowFunc
		resetNetSpeedState()
	})
}

func resetNetSpeedState() {
	netSpeedMu.Lock()
	defer netSpeedMu.Unlock()

	netSpeedPrevRecv = 0
	netSpeedPrevSent = 0
	netSpeedPrevTime = time.Time{}
	netSpeedHasBase = false
}
