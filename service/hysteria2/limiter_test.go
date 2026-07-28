package hysteria2

import (
	"context"
	"fmt"
	"math"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/apernet/hysteria/core/v2/server"
	logtest "github.com/sirupsen/logrus/hooks/test"
	"golang.org/x/time/rate"

	"github.com/Mtoly/XrayRP/api"
	"github.com/Mtoly/XrayRP/service/controller"
)

func TestCloseCancelsTrafficLimiterWaits(t *testing.T) {
	events := &lifecycleEvents{}
	runtime := &fakeRuntimeServer{
		events:     events,
		serveBlock: make(chan struct{}),
		serving:    make(chan struct{}),
	}
	service := newStartTestService(events, runtime)
	service.apiClient.(*configurablePanelClient).users = []api.UserInfo{{
		UID: 17, UUID: "user", SpeedLimit: 1,
	}}

	var trafficContext context.Context
	service.serverConfigFactory = func(_ *Hysteria2Service, spec serverBuildSpec) (*server.Config, error) {
		trafficContext = spec.trafficContext
		return &server.Config{}, nil
	}
	waitEntered := make(chan struct{})
	service.waitTraffic = func(ctx context.Context, _ *rate.Limiter, _ uint64) error {
		close(waitEntered)
		<-ctx.Done()
		return ctx.Err()
	}
	if err := service.Start(); err != nil {
		t.Fatalf("Start() error = %v", err)
	}
	t.Cleanup(func() { _ = service.Close() })

	result := make(chan bool, 1)
	go func() {
		result <- (&hyTrafficLogger{svc: service, ctx: trafficContext}).LogTraffic("user", 1, 0)
	}()
	<-waitEntered

	if err := service.Close(); err != nil {
		t.Fatalf("Close() error = %v", err)
	}
	select {
	case allowed := <-result:
		if allowed {
			t.Fatal("LogTraffic() = true after runtime shutdown canceled limiter wait")
		}
	case <-time.After(time.Second):
		t.Fatal("LogTraffic() did not exit after Close")
	}
}

func TestReloadCancelsOnlyReplacedRuntimeTrafficWaits(t *testing.T) {
	events := &lifecycleEvents{}
	oldRuntime := &fakeRuntimeServer{
		events:     events,
		serveBlock: make(chan struct{}),
		serving:    make(chan struct{}),
	}
	candidateRuntime := &fakeRuntimeServer{
		events:     events,
		serveBlock: make(chan struct{}),
		serving:    make(chan struct{}),
	}
	service := newStartTestService(events, oldRuntime)
	service.apiClient.(*configurablePanelClient).users = []api.UserInfo{{
		UID: 17, UUID: "user", SpeedLimit: 1,
	}}
	var trafficContexts []context.Context
	service.serverConfigFactory = func(_ *Hysteria2Service, spec serverBuildSpec) (*server.Config, error) {
		trafficContexts = append(trafficContexts, spec.trafficContext)
		return &server.Config{}, nil
	}
	runtimes := []runtimeServer{oldRuntime, candidateRuntime}
	service.runtimeServerFactory = func(*server.Config) (runtimeServer, error) {
		runtime := runtimes[0]
		runtimes = runtimes[1:]
		return runtime, nil
	}
	service.serveHandshake = func(start func(), started <-chan struct{}, _ <-chan error) error {
		start()
		<-started
		return nil
	}
	waitEntered := make(chan struct{})
	service.waitTraffic = func(ctx context.Context, _ *rate.Limiter, _ uint64) error {
		close(waitEntered)
		<-ctx.Done()
		return ctx.Err()
	}
	if err := service.Start(); err != nil {
		t.Fatalf("Start() error = %v", err)
	}
	t.Cleanup(func() { _ = service.Close() })

	oldResult := make(chan bool, 1)
	go func() {
		oldResult <- (&hyTrafficLogger{svc: service, ctx: trafficContexts[0]}).LogTraffic("user", 1, 0)
	}()
	<-waitEntered

	reloadDone := make(chan error, 1)
	go func() {
		reloadDone <- service.reloadNode(newReloadNode(10443, "new.example.test"))
	}()
	select {
	case err := <-reloadDone:
		if err != nil {
			t.Fatalf("reloadNode() error = %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("reloadNode() did not finish after canceling replaced runtime traffic")
	}
	if allowed := <-oldResult; allowed {
		t.Fatal("old runtime traffic remained allowed after replacement")
	}
	if len(trafficContexts) != 2 {
		t.Fatalf("runtime traffic contexts = %d, want 2", len(trafficContexts))
	}
	select {
	case <-trafficContexts[1].Done():
		t.Fatal("reload canceled candidate runtime traffic context")
	default:
	}
}

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
