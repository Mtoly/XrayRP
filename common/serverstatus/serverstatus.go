package serverstatus

import (
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/Mtoly/XrayRP/api"
	"github.com/shirou/gopsutil/v3/cpu"
	"github.com/shirou/gopsutil/v3/disk"
	"github.com/shirou/gopsutil/v3/host"
	"github.com/shirou/gopsutil/v3/mem"
	netio "github.com/shirou/gopsutil/v3/net"
)

var (
	netSpeedMu       sync.Mutex
	netSpeedPrevRecv uint64
	netSpeedPrevSent uint64
	netSpeedPrevTime time.Time
	netSpeedHasBase  bool

	cpuPercentFunc    = cpu.Percent
	virtualMemoryFunc = mem.VirtualMemory
	swapMemoryFunc    = mem.SwapMemory
	diskUsageFunc     = disk.Usage
	netIOCountersFunc = netio.IOCounters
	nowFunc           = time.Now
)

// GetSystemInfo get the system info of a given periodic
func GetSystemInfo() (Cpu float64, Mem float64, Disk float64, Uptime uint64, err error) {

	errorString := ""

	cpuPercent, err := cpu.Percent(0, false)
	// Check if cpuPercent is empty
	if len(cpuPercent) > 0 && err == nil {
		Cpu = cpuPercent[0]
	} else {
		Cpu = 0
		errorString += fmt.Sprintf("get cpu usage failed: %s ", err)
	}

	memUsage, err := mem.VirtualMemory()
	if err != nil {
		errorString += fmt.Sprintf("get mem usage failed: %s ", err)
	} else {
		Mem = memUsage.UsedPercent
	}

	diskUsage, err := disk.Usage("/")
	if err != nil {
		errorString += fmt.Sprintf("get disk usage failed: %s ", err)
	} else {
		Disk = diskUsage.UsedPercent
	}

	uptime, err := host.Uptime()
	if err != nil {
		errorString += fmt.Sprintf("get uptime failed: %s ", err)
	} else {
		Uptime = uptime
	}

	if errorString != "" {
		err = fmt.Errorf("%s", errorString)
	}

	return Cpu, Mem, Disk, Uptime, err
}

func GetMachineStatus() (api.MachineStatus, error) {
	var status api.MachineStatus
	errorString := ""

	cpuPercent, err := cpuPercentFunc(0, false)
	if len(cpuPercent) > 0 && err == nil {
		status.CPU = cpuPercent[0]
	} else {
		errorString += fmt.Sprintf("get cpu usage failed: %s ", err)
	}

	memUsage, err := virtualMemoryFunc()
	if err != nil {
		errorString += fmt.Sprintf("get mem usage failed: %s ", err)
	} else {
		status.MemTotal = memUsage.Total
		status.MemUsed = memUsage.Used
	}

	swapUsage, err := swapMemoryFunc()
	if err != nil {
		errorString += fmt.Sprintf("get swap usage failed: %s ", err)
	} else {
		status.SwapTotal = swapUsage.Total
		status.SwapUsed = swapUsage.Used
	}

	diskUsage, err := diskUsageFunc("/")
	if err != nil {
		errorString += fmt.Sprintf("get disk usage failed: %s ", err)
	} else {
		status.DiskTotal = diskUsage.Total
		status.DiskUsed = diskUsage.Used
	}

	status.NetInSpeed, status.NetOutSpeed = collectNetSpeed()

	if errorString != "" {
		return status, fmt.Errorf("%s", errorString)
	}
	return status, nil
}

func skipNetInterface(name string) bool {
	lower := strings.ToLower(name)
	for _, prefix := range []string{"lo", "docker", "veth", "br-", "virbr", "vnet", "tun", "tap"} {
		if strings.HasPrefix(lower, prefix) {
			return true
		}
	}
	return false
}

func collectNetSpeed() (float64, float64) {
	counters, err := netIOCountersFunc(true)
	if err != nil {
		return -1, -1
	}

	var totalRecv, totalSent uint64
	for _, counter := range counters {
		if skipNetInterface(counter.Name) {
			continue
		}
		totalRecv += counter.BytesRecv
		totalSent += counter.BytesSent
	}

	now := nowFunc()
	netSpeedMu.Lock()
	defer netSpeedMu.Unlock()

	if !netSpeedHasBase {
		netSpeedPrevRecv = totalRecv
		netSpeedPrevSent = totalSent
		netSpeedPrevTime = now
		netSpeedHasBase = true
		return -1, -1
	}

	elapsed := now.Sub(netSpeedPrevTime).Seconds()
	if elapsed <= 0 || totalRecv < netSpeedPrevRecv || totalSent < netSpeedPrevSent {
		netSpeedPrevRecv = totalRecv
		netSpeedPrevSent = totalSent
		netSpeedPrevTime = now
		return -1, -1
	}

	inSpeed := float64(totalRecv-netSpeedPrevRecv) / elapsed
	outSpeed := float64(totalSent-netSpeedPrevSent) / elapsed
	netSpeedPrevRecv = totalRecv
	netSpeedPrevSent = totalSent
	netSpeedPrevTime = now
	return inSpeed, outSpeed
}
