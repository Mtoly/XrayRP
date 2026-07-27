package hysteria2

import (
	"fmt"
	"sync/atomic"
	"testing"
)

func BenchmarkTrafficAccounting5000Users(b *testing.B) {
	for _, scenario := range []struct {
		name        string
		activeUsers int
	}{
		{name: "low-active-50", activeUsers: 50},
		{name: "burst-active-1000", activeUsers: 1000},
		{name: "high-active-5000", activeUsers: 5000},
	} {
		b.Run(scenario.name, func(b *testing.B) {
			service, userKeys := benchmarkTrafficService(5000)
			logger := &hyTrafficLogger{svc: service}
			var next atomic.Uint64
			b.ReportAllocs()
			b.ResetTimer()
			b.RunParallel(func(pb *testing.PB) {
				for pb.Next() {
					index := int(next.Add(1)-1) % scenario.activeUsers
					if !logger.LogTraffic(userKeys[index], 1, 1) {
						b.Errorf("traffic for user %d rejected", index)
						return
					}
				}
			})
		})
	}
}

func benchmarkTrafficService(userCount int) (*Hysteria2Service, []string) {
	service := &Hysteria2Service{
		users:   make(map[string]userRecord, userCount),
		traffic: make(map[string]*userTraffic, userCount),
	}
	userKeys := make([]string, userCount)
	for i := range userKeys {
		key := fmt.Sprintf("user-%04d", i)
		userKeys[i] = key
		service.users[key] = userRecord{UID: i + 1}
		service.traffic[key] = &userTraffic{}
	}
	return service, userKeys
}
