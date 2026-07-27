package hysteria2

import (
	"fmt"
	"math"
	"strings"
	"sync"
	"testing"

	logtest "github.com/sirupsen/logrus/hooks/test"
	"golang.org/x/time/rate"

	"github.com/Mtoly/XrayRP/service/controller"
)

func TestTrafficLoggerRejectsLimiterFailure(t *testing.T) {
	service := limiterTestService()
	service.rateLimiters["user"] = rate.NewLimiter(1, 0)

	if (&hyTrafficLogger{svc: service}).LogTraffic("user", 1, 0) {
		t.Fatal("LogTraffic() = true, want disconnect on limiter failure")
	}
	if got := service.rateLimitFailures.Load(); got != 1 {
		t.Fatalf("rate limit failure count = %d, want 1", got)
	}
}

func TestTrafficLoggerDoesNotBypassUint64Overflow(t *testing.T) {
	service := limiterTestService()
	service.rateLimiters["user"] = rate.NewLimiter(1, 0)

	if (&hyTrafficLogger{svc: service}).LogTraffic("user", math.MaxUint64, 1) {
		t.Fatal("LogTraffic() = true, want disconnect instead of tx+rx overflow bypass")
	}
}

func TestTrafficLoggerConcurrentFailuresRemainObservable(t *testing.T) {
	const calls = 64
	service := limiterTestService()
	service.rateLimiters["user"] = rate.NewLimiter(1, 0)
	results := make(chan bool, calls)
	var workers sync.WaitGroup
	workers.Add(calls)

	for i := 0; i < calls; i++ {
		go func() {
			defer workers.Done()
			results <- (&hyTrafficLogger{svc: service}).LogTraffic("user", 1, 0)
		}()
	}

	workers.Wait()
	close(results)
	for allowed := range results {
		if allowed {
			t.Fatal("concurrent LogTraffic() allowed a limiter failure")
		}
	}
	if got := service.rateLimitFailures.Load(); got != calls {
		t.Fatalf("rate limit failure count = %d, want %d", got, calls)
	}
	service.mu.RLock()
	upload := service.traffic["user"].Upload
	service.mu.RUnlock()
	if upload != calls {
		t.Fatalf("accounted upload = %d, want %d", upload, calls)
	}
}

func TestTrafficLoggerFailureLogRedactsAuthenticationID(t *testing.T) {
	const authenticationID = "secret-authentication-id"
	service := limiterTestService()
	service.users = map[string]userRecord{authenticationID: {UID: 17}}
	service.traffic = make(map[string]*userTraffic)
	service.rateLimiters = map[string]*rate.Limiter{
		authenticationID: rate.NewLimiter(1, 0),
	}
	logger, hook := logtest.NewNullLogger()
	service.logger = logger.WithField("test", "limiter")

	if (&hyTrafficLogger{svc: service}).LogTraffic(authenticationID, 1, 0) {
		t.Fatal("LogTraffic() = true, want limiter rejection")
	}
	for _, entry := range hook.AllEntries() {
		if strings.Contains(entry.Message, authenticationID) {
			t.Fatalf("log message leaked authentication ID: %q", entry.Message)
		}
		for key, value := range entry.Data {
			if strings.Contains(fmt.Sprint(value), authenticationID) {
				t.Fatalf("log field %q leaked authentication ID", key)
			}
		}
	}
}

func limiterTestService() *Hysteria2Service {
	service := New(&configurablePanelClient{}, &controller.Config{})
	service.users = map[string]userRecord{"user": {UID: 17}}
	service.traffic = make(map[string]*userTraffic)
	service.rateLimiters = make(map[string]*rate.Limiter)
	return service
}
