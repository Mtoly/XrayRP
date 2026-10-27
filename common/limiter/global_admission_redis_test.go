package limiter

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/redis/go-redis/v9"
)

// Redis-backed acceptance tests are opt-in so ordinary `go test ./...` never
// depends on an external service. Point them at a disposable database:
//
//	XRAYRP_RUN_REDIS_INTEGRATION=1
//	XRAYRP_REDIS_ADDR=127.0.0.1:16379
//	XRAYRP_REDIS_DB=0        (optional)
//	XRAYRP_REDIS_TEST_NAMESPACE=<unique prefix>  (optional)
//
// Each manager uses a random Namespace and cleanup deletes only keys under the
// derived prefix. The tests never issue FLUSHDB.
func redisIntegrationConfig(t *testing.T, namespace string) *GlobalDeviceLimitConfig {
	t.Helper()
	if os.Getenv("XRAYRP_RUN_REDIS_INTEGRATION") != "1" {
		t.Skip("set XRAYRP_RUN_REDIS_INTEGRATION=1 with XRAYRP_REDIS_ADDR to run real Redis tests")
	}
	address := strings.TrimSpace(os.Getenv("XRAYRP_REDIS_ADDR"))
	if address == "" {
		address = "127.0.0.1:16379"
	}
	database := 0
	if raw := strings.TrimSpace(os.Getenv("XRAYRP_REDIS_DB")); raw != "" {
		parsed, err := strconv.Atoi(raw)
		if err != nil {
			t.Fatalf("invalid XRAYRP_REDIS_DB: %v", err)
		}
		database = parsed
	}
	if namespace == "" {
		namespace = fmt.Sprintf("%s-%d-%d", testNamespacePrefix(), time.Now().UnixNano(), redisNamespaceSequence.Add(1))
	}
	return &GlobalDeviceLimitConfig{
		Enable:       true,
		RedisNetwork: "tcp",
		RedisAddr:    address,
		RedisDB:      database,
		Timeout:      2,
		Expiry:       minGlobalAdmissionExpiry,
		Namespace:    namespace,
		Mode:         globalAdmissionModeStrict,
	}
}

var redisNamespaceSequence atomic.Uint64

func testNamespacePrefix() string {
	prefix := strings.TrimSpace(os.Getenv("XRAYRP_REDIS_TEST_NAMESPACE"))
	if prefix == "" {
		return "xrayrp-itest"
	}
	return prefix
}

// redisTestClient returns a client for assertions only. Callers must not use
// it to mutate shared state outside their namespaced keys.
func redisTestClient(t *testing.T, config *GlobalDeviceLimitConfig) *redis.Client {
	t.Helper()
	client := redis.NewClient(&redis.Options{
		Network: config.RedisNetwork,
		Addr:    config.RedisAddr,
		DB:      config.RedisDB,
	})
	t.Cleanup(func() { _ = client.Close() })
	return client
}

func newRedisAdmission(t *testing.T, config *GlobalDeviceLimitConfig) *GlobalAdmission {
	t.Helper()
	admission, err := NewGlobalAdmission(config, "", "")
	if err != nil {
		t.Fatalf("NewGlobalAdmission() error = %v", err)
	}
	if admission == nil {
		t.Fatal("NewGlobalAdmission() returned nil for enabled config")
	}
	t.Cleanup(func() {
		keys, err := redisTestClient(t, config).Keys(context.Background(), admission.keyPrefix+"*").Result()
		if err == nil && len(keys) > 0 {
			_ = redisTestClient(t, config).Del(context.Background(), keys...).Err()
		}
		_ = admission.Close()
	})
	return admission
}

func TestRedisIntegrationQuotaAndDedupAcrossManagers(t *testing.T) {
	config := redisIntegrationConfig(t, "")
	first := newRedisAdmission(t, config)
	second := newRedisAdmission(t, config)

	first.SetUsers(map[int]int{1: 1})
	second.SetUsers(map[int]int{1: 1})

	lease, err := first.Acquire(context.Background(), 1, "203.0.113.1", 1)
	if err != nil || lease == nil {
		t.Fatalf("first Acquire() = %v, %v", lease, err)
	}
	if err := lease.Commit(); err != nil {
		t.Fatalf("Commit() = %v", err)
	}
	if !lease.GlobalConfirmed() {
		t.Fatal("committed lease is not confirmed")
	}

	if _, err := second.Acquire(context.Background(), 1, "203.0.113.2", 1); !errors.Is(err, ErrGlobalAdmissionQuota) {
		t.Fatalf("second manager Acquire(new IP) error = %v, want quota", err)
	}

	// The same canonical IP is a reservation refresh, not a new device.
	existing, err := second.Acquire(context.Background(), 1, "203.0.113.1", 1)
	if err != nil || existing == nil {
		t.Fatalf("second manager Acquire(same IP) = %v, %v", existing, err)
	}
	if err := existing.Abort(); err != nil {
		t.Fatalf("Abort() = %v", err)
	}

	// Aborting must not release the first manager's committed slot.
	if _, err := second.Acquire(context.Background(), 1, "203.0.113.2", 1); !errors.Is(err, ErrGlobalAdmissionQuota) {
		t.Fatalf("Abort() erased a live lease: error = %v, want quota", err)
	}
	_ = lease.Close()
}

func TestRedisIntegrationNormalizedIPv6SharesOneSlot(t *testing.T) {
	config := redisIntegrationConfig(t, "")
	prefix := 64
	config.IPv6Prefix = &prefix
	admission := newRedisAdmission(t, config)
	admission.SetUsers(map[int]int{5: 1})

	lease, err := admission.Acquire(context.Background(), 5, "2001:db8:aa:bb::1", 1)
	if err != nil || lease == nil {
		t.Fatalf("Acquire() = %v, %v", lease, err)
	}
	_ = lease.Commit()
	if _, err := admission.Acquire(context.Background(), 5, "2001:db8:aa:bb::ffff", 1); err != nil {
		t.Fatalf("same /64 Acquire() error = %v, want allowed", err)
	}
	if _, err := admission.Acquire(context.Background(), 5, "2001:db8:aa:cc::1", 1); !errors.Is(err, ErrGlobalAdmissionQuota) {
		t.Fatalf("different /64 Acquire() error = %v, want quota", err)
	}
	_ = lease.Close()
}

func TestRedisIntegrationPolicyMinimumAcrossInstances(t *testing.T) {
	config := redisIntegrationConfig(t, "")
	permissive := newRedisAdmission(t, config)
	restrictive := newRedisAdmission(t, config)

	// Register a positive limit from a second instance without any connection.
	restrictive.SetUsers(map[int]int{9: 1})
	permissive.SetUsers(map[int]int{9: 5})
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	if err := restrictive.flushPoliciesIfDirty(ctx); err != nil {
		cancel()
		t.Fatalf("restrictive policy publish error = %v", err)
	}
	if err := permissive.flushPoliciesIfDirty(ctx); err != nil {
		cancel()
		t.Fatalf("permissive policy publish error = %v", err)
	}
	cancel()

	first, err := permissive.Acquire(context.Background(), 9, "198.51.100.1", 5)
	if err != nil || first == nil {
		t.Fatalf("Acquire(first) = %v, %v", first, err)
	}
	_ = first.Commit()
	if _, err := permissive.Acquire(context.Background(), 9, "198.51.100.2", 5); !errors.Is(err, ErrGlobalAdmissionQuota) {
		t.Fatalf("minimum positive policy not enforced: error = %v, want quota", err)
	}
	_ = first.Close()

	// A zero registration must not override the positive limit.
	zero := newRedisAdmission(t, config)
	zero.SetUsers(map[int]int{9: 0})
	zeroCtx, zeroCancel := context.WithTimeout(context.Background(), 3*time.Second)
	if err := zero.flushPoliciesIfDirty(zeroCtx); err != nil {
		zeroCancel()
		t.Fatalf("zero policy publish error = %v", err)
	}
	zeroCancel()
	if _, err := zero.Acquire(context.Background(), 9, "198.51.100.3", 5); !errors.Is(err, ErrGlobalAdmissionQuota) {
		t.Fatalf("zero policy overrode a positive limit: error = %v, want quota", err)
	}
}

// TestRedisIntegrationLeaseExpiresAfterStoppedManager stops renewal by closing
// the manager (no Redis delete) and verifies TTL expiry. This is NOT a process
// crash; real process-kill recovery is TestRedisIntegrationProcessKillRecoversCapacity.
func TestRedisIntegrationLeaseExpiresAfterStoppedManager(t *testing.T) {
	config := redisIntegrationConfig(t, "")
	config.Expiry = minGlobalAdmissionExpiry
	admission := newRedisAdmission(t, config)
	admission.SetUsers(map[int]int{3: 1})

	lease, err := admission.Acquire(context.Background(), 3, "203.0.113.77", 1)
	if err != nil || lease == nil {
		t.Fatalf("Acquire() = %v, %v", lease, err)
	}
	_ = lease.Commit()

	// Stop renewal without any Redis delete, then wait for TTL. This is a
	// stopped manager, not a crash.
	if err := admission.Close(); err != nil {
		t.Fatalf("Close() = %v", err)
	}
	survivor := newRedisAdmission(t, config)
	survivor.SetUsers(map[int]int{3: 1})
	deadline := time.Now().Add(time.Duration(config.Expiry)*time.Second + 3*time.Second)
	for {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		lease2, err := survivor.Acquire(ctx, 3, "203.0.113.78", 1)
		cancel()
		if err == nil {
			_ = lease2.Abort()
			return
		}
		if !errors.Is(err, ErrGlobalAdmissionQuota) {
			t.Fatalf("Acquire() error = %v, want quota until TTL expiry", err)
		}
		if time.Now().After(deadline) {
			t.Fatal("crashed lease never expired; lease key has no TTL boundary")
		}
		time.Sleep(500 * time.Millisecond)
	}
}

func TestRedisIntegrationNamespaceIsolation(t *testing.T) {
	firstConfig := redisIntegrationConfig(t, "")
	secondConfig := redisIntegrationConfig(t, "")
	first := newRedisAdmission(t, firstConfig)
	second := newRedisAdmission(t, secondConfig)
	first.SetUsers(map[int]int{4: 1})
	second.SetUsers(map[int]int{4: 1})

	lease, err := first.Acquire(context.Background(), 4, "203.0.113.20", 1)
	if err != nil || lease == nil {
		t.Fatalf("Acquire() = %v, %v", lease, err)
	}
	_ = lease.Commit()

	if other, err := second.Acquire(context.Background(), 4, "203.0.113.21", 1); err != nil || other == nil {
		t.Fatalf("isolated namespace Acquire() = %v, %v; want allowed", other, err)
	} else {
		_ = other.Close()
	}
	_ = lease.Close()
}

func TestRedisIntegrationAbortKeepsGraceLease(t *testing.T) {
	config := redisIntegrationConfig(t, "")
	admission := newRedisAdmission(t, config)
	admission.SetUsers(map[int]int{6: 1})

	grace, err := admission.Acquire(context.Background(), 6, "203.0.113.30", 1)
	if err != nil || grace == nil {
		t.Fatalf("Acquire(grace) = %v, %v", grace, err)
	}
	if err := grace.Commit(); err != nil {
		t.Fatalf("Commit(grace) = %v", err)
	}

	// A second tentative reservation for the same IP must not erase the grace
	// lease when it is aborted.
	tentative, err := admission.Acquire(context.Background(), 6, "203.0.113.30", 1)
	if err != nil || tentative == nil {
		t.Fatalf("Acquire(tentative) = %v, %v", tentative, err)
	}
	if err := tentative.Abort(); err != nil {
		t.Fatalf("Abort(tentative) = %v", err)
	}

	if _, err := admission.Acquire(context.Background(), 6, "203.0.113.31", 1); !errors.Is(err, ErrGlobalAdmissionQuota) {
		t.Fatalf("abort removed the grace lease: error = %v, want quota", err)
	}
	_ = grace.Close()
}

func TestRedisIntegrationCanceledContextDoesNotReachRedis(t *testing.T) {
	config := redisIntegrationConfig(t, "")
	admission := newRedisAdmission(t, config)
	admission.SetUsers(map[int]int{8: 1})

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := admission.Acquire(ctx, 8, "203.0.113.40", 1); !errors.Is(err, context.Canceled) {
		t.Fatalf("Acquire(canceled) error = %v, want context.Canceled", err)
	}
	// The canceled attempt must not leave a phantom reservation.
	if lease, err := admission.Acquire(context.Background(), 8, "203.0.113.41", 1); err != nil || lease == nil {
		t.Fatalf("Acquire(after cancel) = %v, %v; want allowed", lease, err)
	} else {
		_ = lease.Close()
	}
}

// TestRedisIntegrationCrossProcessQuota launches an independent process that
// acquires the same UID while the parent holds it, proving the quota is not
// process-local. The child uses the same randomized namespace.
func TestRedisIntegrationCrossProcessQuota(t *testing.T) {
	config := redisIntegrationConfig(t, "")
	admission := newRedisAdmission(t, config)
	admission.SetUsers(map[int]int{11: 1})

	lease, err := admission.Acquire(context.Background(), 11, "203.0.113.50", 1)
	if err != nil || lease == nil {
		t.Fatalf("parent Acquire() = %v, %v", lease, err)
	}
	_ = lease.Commit()
	defer func() { _ = lease.Close() }()

	child := startRedisChild(t, config, "probe", 11, 1, "203.0.113.51")
	select {
	case <-child.done:
	case <-time.After(15 * time.Second):
		t.Fatal("child probe did not finish")
	}
	if !strings.Contains(child.outputString(), "CHILD_RESULT=quota") {
		t.Fatalf("child did not observe the parent's quota: %s", child.outputString())
	}
}

// TestRedisIntegrationChildProbe is the child half of the cross-process tests.
// It is inert unless XRAYRP_REDIS_CHILD_PROBE is set.
//
// Modes:
//   - probe: acquire once after SetUsers{uid:limit}, print CHILD_RESULT.
//   - barrier: SetUsers{uid:limit}, wait for a line on stdin, then acquire and
//     print CHILD_RESULT, then stay alive until stdin closes (leased hold).
//   - hold: SetUsers{uid:limit}, acquire+commit, print CHILD_RESULT=holding,
//     then block until killed (simulates a real process crash).
func TestRedisIntegrationChildProbe(t *testing.T) {
	if os.Getenv("XRAYRP_REDIS_CHILD_PROBE") != "1" {
		t.Skip("child probe only")
	}
	config := &GlobalDeviceLimitConfig{
		Enable:       true,
		RedisNetwork: "tcp",
		RedisAddr:    os.Getenv("XRAYRP_REDIS_CHILD_ADDR"),
		Timeout:      2,
		Expiry:       minGlobalAdmissionExpiry,
		Namespace:    os.Getenv("XRAYRP_REDIS_CHILD_NAMESPACE"),
		Mode:         globalAdmissionModeStrict,
	}
	if raw := os.Getenv("XRAYRP_REDIS_CHILD_DB"); raw != "" {
		parsed, err := strconv.Atoi(raw)
		if err != nil {
			t.Fatalf("invalid child DB: %v", err)
		}
		config.RedisDB = parsed
	}
	if raw := os.Getenv("XRAYRP_REDIS_CHILD_EXPIRY"); raw != "" {
		parsed, err := strconv.Atoi(raw)
		if err != nil {
			t.Fatalf("invalid child expiry: %v", err)
		}
		config.Expiry = parsed
	}
	uid, err := strconv.Atoi(os.Getenv("XRAYRP_REDIS_CHILD_UID"))
	if err != nil {
		t.Fatalf("invalid child uid: %v", err)
	}
	limit, err := strconv.Atoi(os.Getenv("XRAYRP_REDIS_CHILD_LIMIT"))
	if err != nil {
		t.Fatalf("invalid child limit: %v", err)
	}
	ip := os.Getenv("XRAYRP_REDIS_CHILD_IP")
	mode := os.Getenv("XRAYRP_REDIS_CHILD_MODE")

	admission, err := NewGlobalAdmission(config, "", "")
	if err != nil {
		t.Fatalf("child NewGlobalAdmission() error = %v", err)
	}
	defer func() { _ = admission.Close() }()
	admission.SetUsers(map[int]int{uid: limit})

	acquireAndReport := func() *GlobalLease {
		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()
		lease, err := admission.Acquire(ctx, uid, ip, limit)
		switch {
		case errors.Is(err, ErrGlobalAdmissionQuota):
			fmt.Println("CHILD_RESULT=quota")
		case err != nil:
			fmt.Println("CHILD_RESULT=error:", err)
		default:
			_ = lease.Commit()
			fmt.Println("CHILD_RESULT=allowed")
			return lease
		}
		return nil
	}

	// Publish policies before signalling readiness so a READY child has a
	// complete, deterministic view; the parent needs no sleep heuristic.
	publishCtx, publishCancel := context.WithTimeout(context.Background(), 3*time.Second)
	if err := admission.flushPoliciesIfDirty(publishCtx); err != nil {
		publishCancel()
		fmt.Println("CHILD_RESULT=error:", err)
		return
	}
	publishCancel()
	fmt.Println("CHILD_READY=1")

	switch mode {
	case "barrier":
		// Wait for the parent's start signal so both processes race from the
		// same moment instead of sequentially.
		reader := bufio.NewReader(os.Stdin)
		if _, err := reader.ReadString(byte(10)); err != nil {
			t.Fatalf("barrier read error = %v", err)
		}
		lease := acquireAndReport()
		// Stay alive so a successful hold is not released before the parent
		// has observed both outcomes.
		_, _ = reader.ReadString(byte(10))
		_ = lease.Close()
	case "hold":
		lease := acquireAndReport()
		if lease != nil {
			fmt.Println("CHILD_RESULT=holding")
		}
		select {} // killed by the parent to simulate a crash
	default:
		if lease := acquireAndReport(); lease != nil {
			_ = lease.Abort()
		}
	}
}

// childProcess spawns this test binary in one child mode and returns handles.
type childProcess struct {
	command *exec.Cmd
	stdin   io.WriteCloser
	mu      sync.Mutex
	output  bytes.Buffer
	done    chan struct{}
	err     error
}

func (c *childProcess) appendOutput(data []byte) {
	c.mu.Lock()
	c.output.Write(data)
	c.mu.Unlock()
}

func (c *childProcess) outputString() string {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.output.String()
}

func startRedisChild(t *testing.T, config *GlobalDeviceLimitConfig, mode string, uid, limit int, ip string) *childProcess {
	t.Helper()
	command := exec.Command(os.Args[0], "-test.run", "^TestRedisIntegrationChildProbe$")
	command.Env = append(os.Environ(),
		"XRAYRP_REDIS_CHILD_PROBE=1",
		"XRAYRP_REDIS_CHILD_ADDR="+config.RedisAddr,
		"XRAYRP_REDIS_CHILD_DB="+strconv.Itoa(config.RedisDB),
		"XRAYRP_REDIS_CHILD_NAMESPACE="+config.Namespace,
		"XRAYRP_REDIS_CHILD_EXPIRY="+strconv.Itoa(config.Expiry),
		"XRAYRP_REDIS_CHILD_MODE="+mode,
		"XRAYRP_REDIS_CHILD_UID="+strconv.Itoa(uid),
		"XRAYRP_REDIS_CHILD_LIMIT="+strconv.Itoa(limit),
		"XRAYRP_REDIS_CHILD_IP="+ip,
	)
	stdin, err := command.StdinPipe()
	if err != nil {
		t.Fatalf("child stdin pipe error = %v", err)
	}
	child := &childProcess{command: command, stdin: stdin, done: make(chan struct{})}
	command.Stdout = childWriter{child: child}
	command.Stderr = childWriter{child: child}
	if err := command.Start(); err != nil {
		t.Fatalf("child start error = %v", err)
	}
	go func() {
		child.err = command.Wait()
		close(child.done)
	}()
	t.Cleanup(func() {
		_ = stdin.Close()
		_ = command.Process.Kill()
		<-child.done
	})
	return child
}

type childWriter struct{ child *childProcess }

func (w childWriter) Write(data []byte) (int, error) {
	w.child.appendOutput(data)
	return len(data), nil
}

func (c *childProcess) signal(line string) error {
	_, err := io.WriteString(c.stdin, line+string(byte(10)))
	return err
}

func (c *childProcess) waitFor(t *testing.T, marker string, timeout time.Duration) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if strings.Contains(c.outputString(), marker) {
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatalf("child did not emit %q within %s; output: %s", marker, timeout, c.outputString())
}

// TestRedisIntegrationTwoProcessBarrierRace has two independent OS processes
// attempt different IPs for the same UID with limit 1 at the same barrier. The
// atomic reservation must admit exactly one.
func TestRedisIntegrationTwoProcessBarrierRace(t *testing.T) {
	config := redisIntegrationConfig(t, "")
	first := startRedisChild(t, config, "barrier", 21, 1, "203.0.113.60")
	second := startRedisChild(t, config, "barrier", 21, 1, "203.0.113.61")

	// Release both only after each child reports READY and blocks before Acquire.
	first.waitFor(t, "CHILD_READY=1", 15*time.Second)
	second.waitFor(t, "CHILD_READY=1", 15*time.Second)
	if err := first.signal("go"); err != nil {
		t.Fatalf("first signal error = %v", err)
	}
	if err := second.signal("go"); err != nil {
		t.Fatalf("second signal error = %v", err)
	}

	first.waitFor(t, "CHILD_RESULT=", 10*time.Second)
	second.waitFor(t, "CHILD_RESULT=", 10*time.Second)
	combined := first.outputString() + second.outputString()
	allowed := strings.Count(combined, "CHILD_RESULT=allowed")
	quota := strings.Count(combined, "CHILD_RESULT=quota")
	if allowed != 1 || quota != 1 {
		t.Fatalf("barrier race allowed=%d quota=%d, want exactly 1/1; output: %s", allowed, quota, combined)
	}

	// Let both children exit cleanly.
	_ = first.signal("done")
	_ = second.signal("done")
}

// TestRedisIntegrationTwoProcessSharedIPDedup proves genuine same-IP dedup:
// two processes hold the SAME canonical IP at limit 1, so both are admitted
// without consuming two slots, while a different IP is still rejected.
func TestRedisIntegrationTwoProcessSharedIPDedup(t *testing.T) {
	config := redisIntegrationConfig(t, "")
	// Same IP in both children at limit 1: both must be admitted.
	first := startRedisChild(t, config, "barrier", 22, 1, "203.0.113.70")
	second := startRedisChild(t, config, "barrier", 22, 1, "203.0.113.70")

	first.waitFor(t, "CHILD_READY=1", 15*time.Second)
	second.waitFor(t, "CHILD_READY=1", 15*time.Second)
	_ = first.signal("go")
	_ = second.signal("go")
	first.waitFor(t, "CHILD_RESULT=", 10*time.Second)
	second.waitFor(t, "CHILD_RESULT=", 10*time.Second)
	combined := first.outputString() + second.outputString()
	if allowed := strings.Count(combined, "CHILD_RESULT=allowed"); allowed != 2 {
		t.Fatalf("same-IP admissions allowed=%d, want 2 (dedup); output: %s", allowed, combined)
	}

	// With the shared IP still held, a DIFFERENT IP must be rejected at limit 1.
	third := startRedisChild(t, config, "probe", 22, 1, "203.0.113.71")
	select {
	case <-third.done:
	case <-time.After(15 * time.Second):
		t.Fatal("third child did not finish")
	}
	if !strings.Contains(third.outputString(), "CHILD_RESULT=quota") {
		t.Fatalf("different IP was not rejected while the shared IP holds the only slot: %s", third.outputString())
	}

	_ = first.signal("done")
	_ = second.signal("done")
}

// TestRedisIntegrationTwoProcessQuota2ThreeIPs runs three processes for the
// same UID with limit 2 and requires exactly two admissions.
func TestRedisIntegrationTwoProcessQuota2ThreeIPs(t *testing.T) {
	config := redisIntegrationConfig(t, "")
	children := []*childProcess{
		startRedisChild(t, config, "barrier", 23, 2, "203.0.113.80"),
		startRedisChild(t, config, "barrier", 23, 2, "203.0.113.81"),
		startRedisChild(t, config, "barrier", 23, 2, "203.0.113.82"),
	}
	for _, child := range children {
		child.waitFor(t, "CHILD_READY=1", 15*time.Second)
	}
	for _, child := range children {
		if err := child.signal("go"); err != nil {
			t.Fatalf("signal error = %v", err)
		}
	}
	combined := ""
	for _, child := range children {
		child.waitFor(t, "CHILD_RESULT=", 10*time.Second)
		combined += child.outputString()
	}
	if allowed, quota := strings.Count(combined, "CHILD_RESULT=allowed"), strings.Count(combined, "CHILD_RESULT=quota"); allowed != 2 || quota != 1 {
		t.Fatalf("quota-2 three-process race allowed=%d quota=%d, want 2/1; output: %s", allowed, quota, combined)
	}
	for _, child := range children {
		_ = child.signal("done")
	}
}

// TestRedisIntegrationProcessKillRecoversCapacity starts a real child process,
// waits until it holds a lease, then kills it without any cleanup. Capacity
// must recover by TTL alone.
func TestRedisIntegrationProcessKillRecoversCapacity(t *testing.T) {
	config := redisIntegrationConfig(t, "")
	config.Expiry = minGlobalAdmissionExpiry
	child := startRedisChild(t, config, "hold", 24, 1, "203.0.113.90")
	child.waitFor(t, "CHILD_RESULT=holding", 10*time.Second)

	// Prove the child's slot is really held before killing it.
	admission := newRedisAdmission(t, config)
	admission.SetUsers(map[int]int{24: 1})
	if _, err := admission.Acquire(context.Background(), 24, "203.0.113.91", 1); !errors.Is(err, ErrGlobalAdmissionQuota) {
		t.Fatalf("child lease not visible before kill: error = %v, want quota", err)
	}

	if err := child.command.Process.Kill(); err != nil {
		t.Fatalf("kill child error = %v", err)
	}
	<-child.done

	deadline := time.Now().Add(time.Duration(config.Expiry)*time.Second + 3*time.Second)
	for {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		lease, err := admission.Acquire(ctx, 24, "203.0.113.92", 1)
		cancel()
		if err == nil {
			_ = lease.Abort()
			return
		}
		if !errors.Is(err, ErrGlobalAdmissionQuota) {
			t.Fatalf("Acquire() after kill error = %v, want quota until TTL", err)
		}
		if time.Now().After(deadline) {
			t.Fatal("killed process lease never expired")
		}
		time.Sleep(500 * time.Millisecond)
	}
}

// TestRedisIntegrationDerivedPanelIdentityIsolation exercises namespace
// derivation end to end: canonical NewV2board/V2board aliases on the same API
// host share one live quota, while a different API host is isolated.
func TestRedisIntegrationDerivedPanelIdentityIsolation(t *testing.T) {
	base := redisIntegrationConfig(t, "")
	base.Namespace = "" // force derived identity
	base.PanelType = ""
	base.APIHost = ""

	uniqueHost := fmt.Sprintf("https://panel-%d.example.test", time.Now().UnixNano())
	aliasAdmission, err := NewGlobalAdmission(base, "NewV2board", uniqueHost)
	if err != nil {
		t.Fatalf("NewGlobalAdmission(NewV2board) error = %v", err)
	}
	t.Cleanup(func() { cleanupNamespace(t, base, aliasAdmission) })
	v2Admission, err := NewGlobalAdmission(base, "V2board", uniqueHost)
	if err != nil {
		t.Fatalf("NewGlobalAdmission(V2board) error = %v", err)
	}
	t.Cleanup(func() { cleanupNamespace(t, base, v2Admission) })
	otherAdmission, err := NewGlobalAdmission(base, "NewV2board", uniqueHost+"-other")
	if err != nil {
		t.Fatalf("NewGlobalAdmission(other host) error = %v", err)
	}
	t.Cleanup(func() { cleanupNamespace(t, base, otherAdmission) })

	if aliasAdmission.keyPrefix != v2Admission.keyPrefix {
		t.Fatalf("canonical aliases derived different namespaces: %q vs %q", aliasAdmission.keyPrefix, v2Admission.keyPrefix)
	}
	if aliasAdmission.keyPrefix == otherAdmission.keyPrefix {
		t.Fatal("different API hosts derived the same namespace")
	}

	aliasAdmission.SetUsers(map[int]int{51: 1})
	v2Admission.SetUsers(map[int]int{51: 1})
	otherAdmission.SetUsers(map[int]int{51: 1})

	lease, err := aliasAdmission.Acquire(context.Background(), 51, "203.0.113.100", 1)
	if err != nil || lease == nil {
		t.Fatalf("alias Acquire() = %v, %v", lease, err)
	}
	_ = lease.Commit()
	defer func() { _ = lease.Close() }()

	// Same canonical panel identity shares the live quota (no re-registration
	// bypass, even with a different IP).
	if _, err := v2Admission.Acquire(context.Background(), 51, "203.0.113.101", 1); !errors.Is(err, ErrGlobalAdmissionQuota) {
		t.Fatalf("alias Acquire(new IP) error = %v, want shared quota", err)
	}
	// Different panel host is isolated.
	isolated, err := otherAdmission.Acquire(context.Background(), 51, "203.0.113.102", 1)
	if err != nil || isolated == nil {
		t.Fatalf("isolated host Acquire() = %v, %v; want allowed", isolated, err)
	}
	_ = isolated.Close()
}

// cleanupNamespace deletes only this admission's own key prefix.
func cleanupNamespace(t *testing.T, config *GlobalDeviceLimitConfig, admission *GlobalAdmission) {
	t.Helper()
	if admission == nil {
		return
	}
	client := redisTestClient(t, config)
	keys, err := client.Keys(context.Background(), admission.keyPrefix+"*").Result()
	if err == nil && len(keys) > 0 {
		_ = client.Del(context.Background(), keys...).Err()
	}
	_ = admission.Close()
}
