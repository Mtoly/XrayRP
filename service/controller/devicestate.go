package controller

import (
	"crypto/sha256"
	"encoding/hex"
	"sort"
	"strconv"
	"strings"
	"sync"

	"github.com/Mtoly/XrayRP/api"
)

type deviceReportState struct {
	mu       sync.Mutex
	lastHash string
}

func newDeviceReportState() *deviceReportState { return &deviceReportState{} }

type pendingDeviceReport struct {
	hash string
}

func (s *deviceReportState) BuildChangedReport(onlineUsers *[]api.OnlineUser) (map[int][]string, bool) {
	devices, pending, changed := s.PrepareChangedReport(onlineUsers)
	if changed {
		s.CommitChangedReport(pending)
	}
	return devices, changed
}

func (s *deviceReportState) PrepareChangedReport(onlineUsers *[]api.OnlineUser) (map[int][]string, *pendingDeviceReport, bool) {
	devices := normalizeOnlineDevices(onlineUsers)
	hash := hashDeviceSnapshot(devices)
	s.mu.Lock()
	defer s.mu.Unlock()
	if hash == s.lastHash {
		return nil, nil, false
	}
	return devices, &pendingDeviceReport{hash: hash}, true
}

func (s *deviceReportState) CommitChangedReport(report *pendingDeviceReport) {
	if report == nil {
		return
	}

	s.mu.Lock()
	defer s.mu.Unlock()
	s.lastHash = report.hash
}

func normalizeOnlineDevices(onlineUsers *[]api.OnlineUser) map[int][]string {
	devices := make(map[int][]string)
	if onlineUsers == nil {
		return devices
	}

	seen := make(map[int]map[string]struct{})
	for _, onlineUser := range *onlineUsers {
		if onlineUser.UID == 0 {
			continue
		}

		ip := strings.TrimSpace(onlineUser.IP)
		if ip == "" {
			continue
		}

		if _, ok := seen[onlineUser.UID]; !ok {
			seen[onlineUser.UID] = make(map[string]struct{})
		}
		seen[onlineUser.UID][ip] = struct{}{}
	}

	for uid, ips := range seen {
		devices[uid] = make([]string, 0, len(ips))
		for ip := range ips {
			devices[uid] = append(devices[uid], ip)
		}
		sort.Strings(devices[uid])
	}

	return devices
}

func hashDeviceSnapshot(devices map[int][]string) string {
	hash := sha256.New()

	uids := make([]int, 0, len(devices))
	for uid := range devices {
		uids = append(uids, uid)
	}
	sort.Ints(uids)

	for _, uid := range uids {
		hash.Write([]byte("uid"))
		hash.Write([]byte(strconv.Itoa(uid)))
		hash.Write([]byte{0})

		ips := append([]string(nil), devices[uid]...)
		sort.Strings(ips)
		for _, ip := range ips {
			hash.Write([]byte("ip"))
			hash.Write([]byte(ip))
			hash.Write([]byte{0})
		}
	}

	return hex.EncodeToString(hash.Sum(nil))
}
