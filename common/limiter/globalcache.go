package limiter

import (
	"context"
	"errors"
	"fmt"
	"io"
	"sync"
	"time"

	"github.com/eko/gocache/lib/v4/cache"
	"github.com/eko/gocache/lib/v4/marshaler"
	"github.com/eko/gocache/lib/v4/store"
	goCacheStore "github.com/eko/gocache/store/go_cache/v4"
	redisStore "github.com/eko/gocache/store/redis/v4"
	goCache "github.com/patrickmn/go-cache"
	"github.com/redis/go-redis/v9"
)

const localGlobalLimitCleanupInterval = time.Minute

type globalOnlineIPCache interface {
	Get(context.Context, any, any) (any, error)
	Set(context.Context, any, any, ...store.Option) error
}

type globalLimitBackend struct {
	globalOnlineIP globalOnlineIPCache
	closer         io.Closer
}

type globalLimitCacheLayer interface {
	GetWithTTL(context.Context, any) (any, time.Duration, error)
	Set(context.Context, any, any, ...store.Option) error
	Delete(context.Context, any) error
	Invalidate(context.Context, ...store.InvalidateOption) error
	Clear(context.Context) error
}

// layeredGlobalLimitCache keeps the existing local-first, shared-fallback
// behavior without starting an unowned asynchronous backfill worker.
type layeredGlobalLimitCache struct {
	local      globalLimitCacheLayer
	shared     globalLimitCacheLayer
	localName  string
	sharedName string
}

func newLayeredGlobalLimitCache(local, shared globalLimitCacheLayer, localName, sharedName string) *layeredGlobalLimitCache {
	return &layeredGlobalLimitCache{
		local:      local,
		shared:     shared,
		localName:  localName,
		sharedName: sharedName,
	}
}

func (c *layeredGlobalLimitCache) Get(ctx context.Context, key any) (any, error) {
	if value, _, err := c.local.GetWithTTL(ctx, key); err == nil {
		return value, nil
	}

	value, ttl, err := c.shared.GetWithTTL(ctx, key)
	if err != nil {
		return nil, err
	}
	_ = c.local.Set(ctx, key, value, store.WithExpiration(ttl))
	return value, nil
}

func (c *layeredGlobalLimitCache) Set(ctx context.Context, key any, value any, options ...store.Option) error {
	var errs []error
	if err := c.local.Set(ctx, key, value, options...); err != nil {
		errs = append(errs, fmt.Errorf("unable to set item into cache with store '%s': %w", c.localName, err))
	}
	if err := c.shared.Set(ctx, key, value, options...); err != nil {
		errs = append(errs, fmt.Errorf("unable to set item into cache with store '%s': %w", c.sharedName, err))
	}
	return errors.Join(errs...)
}

func (c *layeredGlobalLimitCache) Delete(ctx context.Context, key any) error {
	_ = c.local.Delete(ctx, key)
	_ = c.shared.Delete(ctx, key)
	return nil
}

func (c *layeredGlobalLimitCache) Invalidate(ctx context.Context, options ...store.InvalidateOption) error {
	_ = c.local.Invalidate(ctx, options...)
	_ = c.shared.Invalidate(ctx, options...)
	return nil
}

func (c *layeredGlobalLimitCache) Clear(ctx context.Context) error {
	_ = c.local.Clear(ctx)
	_ = c.shared.Clear(ctx)
	return nil
}

func (c *layeredGlobalLimitCache) GetType() string {
	return cache.ChainType
}

// localTTLCache preserves periodic expiry cleanup without owning a janitor
// goroutine. Cleanup runs at most once per interval on an active cache path.
type localTTLCache struct {
	cache           *goCache.Cache
	cleanupInterval time.Duration
	now             func() time.Time

	cleanupMu   sync.Mutex
	nextCleanup time.Time
}

func newLocalTTLCache(defaultExpiration, cleanupInterval time.Duration) *localTTLCache {
	now := time.Now
	return &localTTLCache{
		cache:           goCache.New(defaultExpiration, 0),
		cleanupInterval: cleanupInterval,
		now:             now,
		nextCleanup:     now().Add(cleanupInterval),
	}
}

func (c *localTTLCache) Get(key string) (any, bool) {
	c.deleteExpiredIfDue()
	return c.cache.Get(key)
}

func (c *localTTLCache) GetWithExpiration(key string) (any, time.Time, bool) {
	c.deleteExpiredIfDue()
	return c.cache.GetWithExpiration(key)
}

func (c *localTTLCache) Set(key string, value any, expiration time.Duration) {
	c.deleteExpiredIfDue()
	c.cache.Set(key, value, expiration)
}

func (c *localTTLCache) Delete(key string) {
	c.cache.Delete(key)
}

func (c *localTTLCache) Flush() {
	c.cache.Flush()
}

func (c *localTTLCache) deleteExpiredIfDue() {
	if c == nil || c.cache == nil || c.cleanupInterval <= 0 {
		return
	}
	now := c.now()

	c.cleanupMu.Lock()
	if now.Before(c.nextCleanup) {
		c.cleanupMu.Unlock()
		return
	}
	c.nextCleanup = now.Add(c.cleanupInterval)
	c.cleanupMu.Unlock()

	c.cache.DeleteExpired()
}

type globalLimitBackendCloser struct {
	local  *localTTLCache
	shared io.Closer
}

func (c *globalLimitBackendCloser) Close() error {
	if c == nil {
		return nil
	}
	if c.local != nil {
		c.local.Flush()
	}
	if c.shared == nil {
		return nil
	}
	return c.shared.Close()
}

func newGlobalLimitBackend(config *GlobalDeviceLimitConfig) globalLimitBackend {
	localClient := newLocalTTLCache(
		time.Duration(config.Expiry)*time.Second,
		localGlobalLimitCleanupInterval,
	)
	localStore := goCacheStore.NewGoCache(localClient)
	local := cache.New[any](localStore)

	redisClient := redis.NewClient(&redis.Options{
		Network:  config.RedisNetwork,
		Addr:     config.RedisAddr,
		Username: config.RedisUsername,
		Password: config.RedisPassword,
		DB:       config.RedisDB,
	})
	sharedStore := redisStore.NewRedis(
		redisClient,
		store.WithExpiration(time.Duration(config.Expiry)*time.Second),
	)
	shared := cache.New[any](sharedStore)
	cacheManager := newLayeredGlobalLimitCache(
		local,
		shared,
		goCacheStore.GoCacheType,
		redisStore.RedisType,
	)

	return globalLimitBackend{
		globalOnlineIP: marshaler.New(cacheManager),
		closer: &globalLimitBackendCloser{
			local:  localClient,
			shared: redisClient,
		},
	}
}
