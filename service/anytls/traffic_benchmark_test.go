package anytls

import (
	"fmt"
	"sync/atomic"
	"testing"
	"time"
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
			var next atomic.Uint64
			b.ReportAllocs()
			b.ResetTimer()
			b.RunParallel(func(pb *testing.PB) {
				connection := &limiterTestConn{
					remoteAddr: limiterTestAddr("192.0.2.1:1234"),
				}
				counter := &connCounter{Conn: connection, svc: service}
				payload := []byte{1}
				for pb.Next() {
					index := int(next.Add(1)-1) % scenario.activeUsers
					counter.user = userKeys[index]
					_, _ = counter.Write(payload)
				}
			})
		})
	}
}

func benchmarkTrafficService(userCount int) (*AnyTLSService, []string) {
	service := &AnyTLSService{
		traffic:      make(map[string]*userTraffic, userCount),
		onlineIPs:    make(map[string]map[string]struct{}, userCount),
		ipLastActive: make(map[string]map[string]time.Time, userCount),
	}
	userKeys := make([]string, userCount)
	for i := range userKeys {
		key := fmt.Sprintf("user-%04d", i)
		userKeys[i] = key
		service.traffic[key] = &userTraffic{}
		service.onlineIPs[key] = map[string]struct{}{"192.0.2.1": {}}
		service.ipLastActive[key] = map[string]time.Time{"192.0.2.1": time.Unix(1, 0)}
	}
	return service, userKeys
}
