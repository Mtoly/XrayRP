package limiter

import (
	"testing"
	"time"

	goCache "github.com/patrickmn/go-cache"
)

func TestLocalTTLCacheAddWritesAbsentKey(t *testing.T) {
	local := newLocalTTLCache(time.Minute, time.Minute)

	if err := local.Add("user", []byte("value"), time.Minute); err != nil {
		t.Fatalf("Add() error = %v, want nil for absent key", err)
	}
	got, ok := local.Get("user")
	if !ok {
		t.Fatal("Get() after Add() reported the key as absent")
	}
	if value := string(got.([]byte)); value != "value" {
		t.Fatalf("Get() value = %q, want value", value)
	}
}

func TestLocalTTLCacheAddKeepsExistingValue(t *testing.T) {
	local := newLocalTTLCache(time.Minute, time.Minute)
	local.Set("user", []byte("original"), time.Minute)

	if err := local.Add("user", []byte("replacement"), time.Minute); err == nil {
		t.Fatal("Add() error = nil, want an error for a live key")
	}
	got, ok := local.Get("user")
	if !ok {
		t.Fatal("Get() after rejected Add() reported the key as absent")
	}
	if value := string(got.([]byte)); value != "original" {
		t.Fatalf("Get() value = %q, want original", value)
	}
}

func TestLocalTTLCacheAddReplacesExpiredEntry(t *testing.T) {
	now := time.Date(2026, 7, 31, 12, 0, 0, 0, time.UTC)
	local := newLocalTTLCache(time.Minute, 0)
	local.cache = goCache.NewFrom(time.Minute, 0, map[string]goCache.Item{
		"expired": {
			Object:     []byte("expired"),
			Expiration: now.Add(-time.Minute).UnixNano(),
		},
	})
	local.now = func() time.Time { return now }

	if err := local.Add("expired", []byte("fresh"), time.Minute); err != nil {
		t.Fatalf("Add() error = %v, want nil for an expired key", err)
	}
	got, ok := local.Get("expired")
	if !ok {
		t.Fatal("Get() after Add() reported the refreshed key as absent")
	}
	if value := string(got.([]byte)); value != "fresh" {
		t.Fatalf("Get() value = %q, want fresh", value)
	}
}

func TestLocalTTLCacheAddRunsDueExpiryCleanup(t *testing.T) {
	now := time.Date(2026, 7, 31, 12, 0, 0, 0, time.UTC)
	local := newLocalTTLCache(time.Minute, time.Minute)
	local.cache = goCache.NewFrom(time.Minute, 0, map[string]goCache.Item{
		"expired": {
			Object:     []byte("expired"),
			Expiration: now.Add(-time.Minute).UnixNano(),
		},
	})
	local.now = func() time.Time { return now }
	local.nextCleanup = now.Add(-time.Second)

	if err := local.Add("fresh", []byte("fresh"), time.Minute); err != nil {
		t.Fatalf("Add() error = %v, want nil", err)
	}
	if count := local.cache.ItemCount(); count != 1 {
		t.Fatalf("local item count after Add() = %d, want 1 (only the new entry)", count)
	}
	if _, ok := local.cache.Get("expired"); ok {
		t.Fatal("Add() did not prune the expired entry on a due cleanup interval")
	}
}
