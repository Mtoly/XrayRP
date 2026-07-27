package limiter

import (
	"fmt"
	"sync/atomic"
	"testing"

	"github.com/Mtoly/XrayRP/api"
)

const benchmarkUserCount = 5000

func BenchmarkGetUserBucket5000Users(b *testing.B) {
	for _, scenario := range []struct {
		name        string
		activeUsers int
	}{
		{name: "low-active-50", activeUsers: 50},
		{name: "burst-active-1000", activeUsers: 1000},
		{name: "high-active-5000", activeUsers: 5000},
	} {
		b.Run(scenario.name, func(b *testing.B) {
			limiter, userKeys, ips := benchmarkLimiter(b, benchmarkUserCount)
			for i := 0; i < scenario.activeUsers; i++ {
				if _, _, rejected := limiter.GetUserBucket("inbound", userKeys[i], ips[i]); rejected {
					b.Fatalf("preseed user %d rejected", i)
				}
			}

			var next atomic.Uint64
			b.ReportAllocs()
			b.ResetTimer()
			b.RunParallel(func(pb *testing.PB) {
				for pb.Next() {
					index := int(next.Add(1)-1) % scenario.activeUsers
					if _, _, rejected := limiter.GetUserBucket("inbound", userKeys[index], ips[index]); rejected {
						b.Errorf("existing device for user %d rejected", index)
						return
					}
				}
			})
		})
	}
}

func BenchmarkGetOnlineDevice5000Users(b *testing.B) {
	limiter, userKeys, ips := benchmarkLimiter(b, benchmarkUserCount)
	for i, userKey := range userKeys {
		if _, _, rejected := limiter.GetUserBucket("inbound", userKey, ips[i]); rejected {
			b.Fatalf("preseed user %d rejected", i)
		}
	}

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		online, err := limiter.GetOnlineDevice("inbound")
		if err != nil {
			b.Fatal(err)
		}
		if len(*online) != benchmarkUserCount {
			b.Fatalf("online devices = %d, want %d", len(*online), benchmarkUserCount)
		}
	}
}

func benchmarkLimiter(b *testing.B, userCount int) (*Limiter, []string, []string) {
	b.Helper()
	users := make([]api.UserInfo, userCount)
	userKeys := make([]string, userCount)
	ips := make([]string, userCount)
	for i := range users {
		email := fmt.Sprintf("user-%04d@example.test", i)
		users[i] = api.UserInfo{
			UID:         i + 1,
			Email:       email,
			DeviceLimit: 2,
		}
		userKeys[i] = fmt.Sprintf("inbound|%s|%d", email, i+1)
		ips[i] = benchmarkIP(i)
	}
	limiter := New()
	if err := limiter.AddInboundLimiter("inbound", 0, &users, nil); err != nil {
		b.Fatal(err)
	}
	return limiter, userKeys, ips
}

func benchmarkIP(index int) string {
	return fmt.Sprintf("192.0.%d.%d", (index/250)%250, index%250+1)
}
