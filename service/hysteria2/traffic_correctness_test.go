package hysteria2

import (
	"math"
	"testing"
	"time"
)

func TestTrafficAccountingSaturatesAtMaxInt64(t *testing.T) {
	service := limiterTestService()
	service.traffic["user"] = &userTraffic{
		Upload:   math.MaxInt64 - 1,
		Download: math.MaxInt64 - 1,
	}

	if !(&hyTrafficLogger{svc: service}).LogTraffic("user", 2, 2) {
		t.Fatal("LogTraffic() rejected traffic without a limiter")
	}
	service.mu.RLock()
	traffic := *service.traffic["user"]
	service.mu.RUnlock()
	if traffic.Upload != math.MaxInt64 || traffic.Download != math.MaxInt64 {
		t.Fatalf("traffic = %#v, want saturated counters", traffic)
	}
}

func TestTrafficAccountingSaturatesUint64Delta(t *testing.T) {
	service := limiterTestService()

	if !(&hyTrafficLogger{svc: service}).LogTraffic("user", math.MaxUint64, math.MaxUint64) {
		t.Fatal("LogTraffic() rejected traffic without a limiter")
	}
	service.mu.RLock()
	traffic := *service.traffic["user"]
	service.mu.RUnlock()
	if traffic.Upload != math.MaxInt64 || traffic.Download != math.MaxInt64 {
		t.Fatalf("traffic = %#v, want saturated counters", traffic)
	}
}

func TestCollectAndRestorePreserveNewTraffic(t *testing.T) {
	service := limiterTestService()
	service.traffic["user"] = &userTraffic{Upload: 10, Download: 20}

	_, _, snapshot := service.collectUsage()
	if !(&hyTrafficLogger{svc: service}).LogTraffic("user", 1, 1) {
		t.Fatal("LogTraffic() rejected traffic without a limiter")
	}
	service.restoreTraffic(snapshot)

	service.mu.RLock()
	traffic := *service.traffic["user"]
	service.mu.RUnlock()
	if traffic.Upload != 11 || traffic.Download != 21 {
		t.Fatalf("traffic after restore = %#v, want upload=11 download=21", traffic)
	}
}

func TestRestoreTrafficSaturatesAtMaxInt64(t *testing.T) {
	service := limiterTestService()
	service.traffic["user"] = &userTraffic{
		Upload:   math.MaxInt64 - 1,
		Download: math.MaxInt64 - 1,
	}

	_, _, snapshot := service.collectUsage()
	service.traffic["user"] = &userTraffic{Upload: 2, Download: 2}
	service.restoreTraffic(snapshot)

	service.mu.RLock()
	traffic := *service.traffic["user"]
	service.mu.RUnlock()
	if traffic.Upload != math.MaxInt64 || traffic.Download != math.MaxInt64 {
		t.Fatalf("restored traffic = %#v, want saturated counters", traffic)
	}
}

func TestCollectUsagePrunesStaleDevicesAndReportsEmpty(t *testing.T) {
	service := limiterTestService()
	service.onlineIPs = map[string]map[string]struct{}{
		"user": {"192.0.2.1": {}},
	}
	service.ipLastActive = map[string]map[string]time.Time{
		"user": {"192.0.2.1": time.Now().Add(-onlineIPTTL - time.Second)},
	}

	_, online, _ := service.collectUsage()

	if len(online) != 0 {
		t.Fatalf("online users = %#v, want empty after stale cleanup", online)
	}
	service.mu.RLock()
	_, hasOnline := service.onlineIPs["user"]
	_, hasActive := service.ipLastActive["user"]
	service.mu.RUnlock()
	if hasOnline || hasActive {
		t.Fatalf("stale device retained: online=%v active=%v", hasOnline, hasActive)
	}
}
