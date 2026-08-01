package limiter

import (
	"context"
	"fmt"
	"sync/atomic"
	"testing"
	"time"

	"github.com/Mtoly/XrayRP/api"
	"github.com/eko/gocache/lib/v4/cache"
	"github.com/eko/gocache/lib/v4/store"
	goCacheStore "github.com/eko/gocache/store/go_cache/v4"
	goCache "github.com/patrickmn/go-cache"
	"golang.org/x/time/rate"
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
				if _, _, rejected := limiter.getUserBucket("inbound", userKeys[i], ips[i]); rejected {
					b.Fatalf("preseed user %d rejected", i)
				}
			}

			var next atomic.Uint64
			b.ReportAllocs()
			b.ResetTimer()
			b.RunParallel(func(pb *testing.PB) {
				for pb.Next() {
					index := int(next.Add(1)-1) % scenario.activeUsers
					if _, _, rejected := limiter.getUserBucket("inbound", userKeys[index], ips[index]); rejected {
						b.Errorf("existing device for user %d rejected", index)
						return
					}
				}
			})
		})
	}
}

func BenchmarkAdmit5000Users(b *testing.B) {
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
				if _, _, rejected := limiter.Admit("inbound", userKeys[i], ips[i], nil, nil); rejected {
					b.Fatalf("preseed user %d rejected", i)
				}
			}

			var next atomic.Uint64
			b.ReportAllocs()
			b.ResetTimer()
			b.RunParallel(func(pb *testing.PB) {
				for pb.Next() {
					index := int(next.Add(1)-1) % scenario.activeUsers
					if _, _, rejected := limiter.Admit("inbound", userKeys[index], ips[index], nil, nil); rejected {
						b.Errorf("existing device for user %d rejected", index)
						return
					}
				}
			})
		})
	}
}

func BenchmarkRateWaitFastPathParallel(b *testing.B) {
	owner := New()
	b.ReportAllocs()
	b.RunParallel(func(pb *testing.PB) {
		bucket := rate.NewLimiter(rate.Inf, 1)
		for pb.Next() {
			if err := waitRate(owner, bucket, 1); err != nil {
				b.Fatal(err)
			}
		}
	})
}

func BenchmarkUpdateInboundLimiter5000Users(b *testing.B) {
	limiter, _, _ := benchmarkLimiter(b, benchmarkUserCount)
	update := []api.UserInfo{{UID: 1, Email: "user-0000@example.test", SpeedLimit: 100, DeviceLimit: 2}}
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		update[0].SpeedLimit = 100 + uint64(i&1)
		if err := limiter.UpdateInboundLimiter("inbound", &update); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkReplaceInboundUsers5000Users(b *testing.B) {
	users, _, _ := benchmarkUserData(benchmarkUserCount)
	limiter := New()
	if err := limiter.AddInboundLimiter("inbound", 0, &users, nil); err != nil {
		b.Fatal(err)
	}
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		users[0].SpeedLimit = uint64(i & 1)
		if err := limiter.ReplaceInboundUsers("inbound", &users); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkSnapshotInboundLimiterState5000Users(b *testing.B) {
	limiter, userKeys, ips := benchmarkLimiter(b, benchmarkUserCount)
	for index, userKey := range userKeys {
		if _, _, rejected := limiter.Admit("inbound", userKey, ips[index], nil, nil); rejected {
			b.Fatalf("preseed user %d rejected", index)
		}
	}
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, err := limiter.SnapshotInboundLimiterState("inbound"); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkGetOnlineDevice5000Users(b *testing.B) {
	limiter, userKeys, ips := benchmarkLimiter(b, benchmarkUserCount)
	for i, userKey := range userKeys {
		if _, _, rejected := limiter.getUserBucket("inbound", userKey, ips[i]); rejected {
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

func BenchmarkGlobalLimitCacheLocalHit(b *testing.B) {
	ctx := context.Background()
	value := []byte("value")

	b.Run("owned-layered", func(b *testing.B) {
		local := benchmarkGlobalLimitCacheLayer()
		shared := benchmarkGlobalLimitCacheLayer()
		if err := local.Set(ctx, "user", value, store.WithExpiration(time.Minute)); err != nil {
			b.Fatal(err)
		}
		cacheManager := newLayeredGlobalLimitCache(local, shared, "local", "shared")

		b.ReportAllocs()
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			if _, err := cacheManager.Get(ctx, "user"); err != nil {
				b.Fatal(err)
			}
		}
	})

	b.Run("legacy-background-chain", func(b *testing.B) {
		local := benchmarkGlobalLimitCacheLayer()
		shared := benchmarkGlobalLimitCacheLayer()
		if err := local.Set(ctx, "user", value, store.WithExpiration(time.Minute)); err != nil {
			b.Fatal(err)
		}
		cacheManager := cache.NewChain[any](local, shared)

		b.ReportAllocs()
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			if _, err := cacheManager.Get(ctx, "user"); err != nil {
				b.Fatal(err)
			}
		}
	})
}

func benchmarkGlobalLimitCacheLayer() cache.SetterCacheInterface[any] {
	client := goCache.New(time.Minute, 0)
	return cache.New[any](goCacheStore.NewGoCache(client))
}

func benchmarkLimiter(b *testing.B, userCount int) (*Limiter, []string, []string) {
	b.Helper()
	users, userKeys, ips := benchmarkUserData(userCount)
	limiter := New()
	if err := limiter.AddInboundLimiter("inbound", 0, &users, nil); err != nil {
		b.Fatal(err)
	}
	return limiter, userKeys, ips
}

func benchmarkUserData(userCount int) ([]api.UserInfo, []string, []string) {
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
	return users, userKeys, ips
}

func benchmarkIP(index int) string {
	return fmt.Sprintf("192.0.%d.%d", (index/250)%250, index%250+1)
}
