package limiter

import (
	"context"
	"errors"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/eko/gocache/lib/v4/store"
	goCache "github.com/patrickmn/go-cache"
)

type cacheLayerValue struct {
	value any
	ttl   time.Duration
}

type fakeGlobalLimitCacheLayer struct {
	values map[string]cacheLayerValue

	getErr      error
	setErr      error
	getCalls    int
	setCalls    int
	lastSetTTL  time.Duration
	deleteCalls int
	clearCalls  int
}

func (f *fakeGlobalLimitCacheLayer) GetWithTTL(_ context.Context, key any) (any, time.Duration, error) {
	f.getCalls++
	if f.getErr != nil {
		return nil, 0, f.getErr
	}
	value, ok := f.values[key.(string)]
	if !ok {
		return nil, 0, store.NotFoundWithCause(errors.New("not found"))
	}
	return value.value, value.ttl, nil
}

func (f *fakeGlobalLimitCacheLayer) Set(_ context.Context, key any, value any, options ...store.Option) error {
	f.setCalls++
	applied := store.ApplyOptions(options...)
	f.lastSetTTL = applied.Expiration
	if f.values == nil {
		f.values = make(map[string]cacheLayerValue)
	}
	f.values[key.(string)] = cacheLayerValue{value: value, ttl: applied.Expiration}
	return f.setErr
}

func (f *fakeGlobalLimitCacheLayer) Delete(_ context.Context, key any) error {
	f.deleteCalls++
	delete(f.values, key.(string))
	return nil
}

func (f *fakeGlobalLimitCacheLayer) Invalidate(context.Context, ...store.InvalidateOption) error {
	return nil
}

func (f *fakeGlobalLimitCacheLayer) Clear(context.Context) error {
	f.clearCalls++
	clear(f.values)
	return nil
}

func TestLayeredGlobalLimitCacheLocalHitSkipsShared(t *testing.T) {
	local := &fakeGlobalLimitCacheLayer{
		values: map[string]cacheLayerValue{"user": {value: []byte("local"), ttl: time.Minute}},
	}
	shared := &fakeGlobalLimitCacheLayer{
		values: map[string]cacheLayerValue{"user": {value: []byte("shared"), ttl: time.Minute}},
	}
	cache := newLayeredGlobalLimitCache(local, shared, "local", "shared")

	value, err := cache.Get(context.Background(), "user")
	if err != nil {
		t.Fatalf("Get() error = %v", err)
	}
	if string(value.([]byte)) != "local" {
		t.Fatalf("Get() value = %q, want local", value)
	}
	if shared.getCalls != 0 || local.setCalls != 0 {
		t.Fatalf("local hit calls = shared get:%d local set:%d, want 0/0", shared.getCalls, local.setCalls)
	}
}

func TestLayeredGlobalLimitCacheSharedHitBackfillsLocalTTL(t *testing.T) {
	local := &fakeGlobalLimitCacheLayer{values: make(map[string]cacheLayerValue)}
	sharedTTL := 37 * time.Second
	shared := &fakeGlobalLimitCacheLayer{
		values: map[string]cacheLayerValue{"user": {value: []byte("shared"), ttl: sharedTTL}},
	}
	cache := newLayeredGlobalLimitCache(local, shared, "local", "shared")

	value, err := cache.Get(context.Background(), "user")
	if err != nil {
		t.Fatalf("Get() error = %v", err)
	}
	if string(value.([]byte)) != "shared" {
		t.Fatalf("Get() value = %q, want shared", value)
	}
	if local.setCalls != 1 || local.lastSetTTL != sharedTTL {
		t.Fatalf("local backfill = calls:%d ttl:%v, want 1/%v", local.setCalls, local.lastSetTTL, sharedTTL)
	}

	shared.getErr = errors.New("shared unavailable after backfill")
	value, err = cache.Get(context.Background(), "user")
	if err != nil || string(value.([]byte)) != "shared" {
		t.Fatalf("backfilled Get() = value:%q error:%v", value, err)
	}
	if shared.getCalls != 1 {
		t.Fatalf("shared GetWithTTL() calls = %d, want 1", shared.getCalls)
	}
}

func TestLayeredGlobalLimitCacheReturnsSharedReadFailure(t *testing.T) {
	sharedErr := errors.New("shared unavailable")
	cache := newLayeredGlobalLimitCache(
		&fakeGlobalLimitCacheLayer{values: make(map[string]cacheLayerValue)},
		&fakeGlobalLimitCacheLayer{getErr: sharedErr},
		"local",
		"shared",
	)

	if _, err := cache.Get(context.Background(), "user"); !errors.Is(err, sharedErr) {
		t.Fatalf("Get() error = %v, want %v", err, sharedErr)
	}
}

func TestLayeredGlobalLimitCacheSetWritesBothAndReportsSharedFailure(t *testing.T) {
	sharedErr := errors.New("shared unavailable")
	local := &fakeGlobalLimitCacheLayer{}
	shared := &fakeGlobalLimitCacheLayer{setErr: sharedErr}
	cache := newLayeredGlobalLimitCache(local, shared, "local", "shared")

	err := cache.Set(context.Background(), "user", []byte("value"), store.WithExpiration(time.Minute))
	if !errors.Is(err, sharedErr) || !strings.Contains(err.Error(), "shared") {
		t.Fatalf("Set() error = %v, want wrapped shared failure", err)
	}
	if local.setCalls != 1 || shared.setCalls != 1 {
		t.Fatalf("Set() calls = local:%d shared:%d, want 1/1", local.setCalls, shared.setCalls)
	}
	if got := string(local.values["user"].value.([]byte)); got != "value" {
		t.Fatalf("local value = %q, want value", got)
	}
}

func TestLocalTTLCacheDeletesExpiredEntriesWithoutJanitor(t *testing.T) {
	now := time.Date(2026, 7, 31, 12, 0, 0, 0, time.UTC)
	local := newLocalTTLCache(time.Minute, time.Minute)
	local.cache = goCache.NewFrom(time.Minute, 0, map[string]goCache.Item{
		"expired": {
			Object:     []byte("expired"),
			Expiration: time.Now().Add(-time.Minute).UnixNano(),
		},
	})
	local.now = func() time.Time { return now }
	local.nextCleanup = now.Add(-time.Second)

	if _, ok := local.Get("expired"); ok {
		t.Fatal("Get() returned expired value")
	}
	if count := local.cache.ItemCount(); count != 0 {
		t.Fatalf("expired item count = %d, want 0", count)
	}
}

func TestGlobalLimitBackendCloserFlushesLocalAndReturnsSharedFailure(t *testing.T) {
	local := newLocalTTLCache(time.Minute, time.Minute)
	local.Set("user", []byte("value"), time.Minute)
	sharedErr := errors.New("shared close failed")
	shared := &failingCloser{err: sharedErr}
	closer := &globalLimitBackendCloser{local: local, shared: shared}

	if err := closer.Close(); !errors.Is(err, sharedErr) {
		t.Fatalf("Close() error = %v, want %v", err, sharedErr)
	}
	if count := local.cache.ItemCount(); count != 0 {
		t.Fatalf("local item count after Close() = %d, want 0", count)
	}
	if shared.calls != 1 {
		t.Fatalf("shared Close() calls = %d, want 1", shared.calls)
	}
}

func TestGlobalLimitCacheCompositionOwnsNoBackgroundChain(t *testing.T) {
	entries, err := os.ReadDir(".")
	if err != nil {
		t.Fatal(err)
	}
	for _, entry := range entries {
		if entry.IsDir() || filepath.Ext(entry.Name()) != ".go" || strings.HasSuffix(entry.Name(), "_test.go") {
			continue
		}
		path := entry.Name()
		file, err := parser.ParseFile(token.NewFileSet(), path, nil, 0)
		if err != nil {
			t.Fatalf("parse %s: %v", path, err)
		}
		cacheAliases := make(map[string]struct{})
		for _, imported := range file.Imports {
			if imported.Path.Value != `"github.com/eko/gocache/lib/v4/cache"` {
				continue
			}
			name := "cache"
			if imported.Name != nil {
				name = imported.Name.Name
			}
			cacheAliases[name] = struct{}{}
		}
		ast.Inspect(file, func(node ast.Node) bool {
			call, ok := node.(*ast.CallExpr)
			if !ok {
				return true
			}
			selector, ok := call.Fun.(*ast.SelectorExpr)
			if !ok || selector.Sel.Name != "NewChain" {
				return true
			}
			identifier, ok := selector.X.(*ast.Ident)
			if !ok {
				return true
			}
			if _, imported := cacheAliases[identifier.Name]; imported {
				t.Errorf("%s uses cache.NewChain, which starts an unowned background worker", path)
			}
			return true
		})
	}
}

type fakeGlobalOnlineIPCache struct {
	getErr error
	setErr error
}

func (f *fakeGlobalOnlineIPCache) Get(context.Context, any, any) (any, error) {
	return nil, f.getErr
}

func (f *fakeGlobalOnlineIPCache) Set(context.Context, any, any, ...store.Option) error {
	return f.setErr
}

func TestGlobalLimitCacheReadAndWriteFailuresRemainFailOpen(t *testing.T) {
	tests := []struct {
		name  string
		cache globalOnlineIPCache
	}{
		{
			name:  "read failure",
			cache: &fakeGlobalOnlineIPCache{getErr: errors.New("shared read failed")},
		},
		{
			name: "initial write failure",
			cache: &fakeGlobalOnlineIPCache{
				getErr: store.NotFoundWithCause(errors.New("not found")),
				setErr: errors.New("shared write failed"),
			},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			state := &inboundState{
				GlobalLimit: &globalLimitState{
					config:         &GlobalDeviceLimitConfig{Enable: true, Timeout: 1},
					globalOnlineIP: test.cache,
				},
			}
			if rejected := globalLimit(state, "inbound|user@example.test|1", 1, "192.0.2.1", 1); rejected {
				t.Fatal("cache failure rejected admission, want existing fail-open behavior")
			}
		})
	}
}
