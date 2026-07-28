// Package limiter is to control the links that go into the dispatcher
package limiter

import (
	"context"
	"errors"
	"fmt"
	"io"
	"strconv"
	"sync"
	"sync/atomic"
	"time"

	"github.com/eko/gocache/lib/v4/cache"
	"github.com/eko/gocache/lib/v4/marshaler"
	"github.com/eko/gocache/lib/v4/store"
	goCacheStore "github.com/eko/gocache/store/go_cache/v4"
	redisStore "github.com/eko/gocache/store/redis/v4"
	goCache "github.com/patrickmn/go-cache"
	"github.com/redis/go-redis/v9"
	xrayerrors "github.com/xtls/xray-core/common/errors"
	"golang.org/x/time/rate"

	"github.com/Mtoly/XrayRP/api"
)

type UserInfo struct {
	UID         int
	SpeedLimit  uint64
	DeviceLimit int
}

type userPolicy = UserInfo

type InboundLimiterStateSnapshot struct {
	UserInfo map[string]UserInfo
	Buckets  map[string]bucketStateSnapshot

	state         *inboundState
	policyVersion uint64
	buckets       map[string]*rate.Limiter
}

type bucketStateSnapshot struct {
	Limit rate.Limit
	Burst int
}

// connIP tracks a single online IP with its UID and last-seen timestamp.
type connIP struct {
	UID      int
	LastSeen int64 // unix timestamp
}

// userOnlineEntry stores per-user IP tracking with an atomic device counter
// to avoid O(N) Range() for device counting.
type userOnlineEntry struct {
	mu      sync.Mutex
	ips     sync.Map // Key: IP string -> connIP
	count   int32    // atomic device count — avoids Range() for counting
	retired bool
}

func newUserOnlineEntry() *userOnlineEntry {
	return &userOnlineEntry{}
}

func (e *userOnlineEntry) hasIP(ip string) bool {
	_, loaded := e.ips.Load(ip)
	return loaded
}

func (e *userOnlineEntry) touchIP(ip string, uid int) {
	now := time.Now().Unix()
	if _, loaded := e.ips.LoadOrStore(ip, connIP{UID: uid, LastSeen: now}); !loaded {
		atomic.AddInt32(&e.count, 1)
		return
	}
	e.ips.Store(ip, connIP{UID: uid, LastSeen: now})
}

func (e *userOnlineEntry) snapshotIPs() []string {
	capacity := atomic.LoadInt32(&e.count)
	if capacity < 0 {
		capacity = 0
	}
	ips := make([]string, 0, capacity)
	e.ips.Range(func(key, value interface{}) bool {
		ips = append(ips, key.(string))
		return true
	})
	return ips
}

func (e *userOnlineEntry) deleteIP(key interface{}) bool {
	if _, loaded := e.ips.LoadAndDelete(key); loaded {
		atomic.AddInt32(&e.count, -1)
		return true
	}
	return false
}

func (e *userOnlineEntry) pruneToAdmitted(admitted map[string]struct{}) {
	if admitted == nil {
		return
	}
	e.ips.Range(func(key, value interface{}) bool {
		ip := key.(string)
		if _, ok := admitted[ip]; !ok {
			e.deleteIP(key)
		}
		return true
	})
}

func (e *userOnlineEntry) admitIP(ip string, uid int, deviceLimit int, globalDevices *globalDeviceState) (reject bool, retry bool) {
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.retired {
		return false, true
	}

	if e.hasIP(ip) {
		e.touchIP(ip, uid)
		return false, false
	}

	localIPs := e.snapshotIPs()
	reject, usedFreshGlobal, admitted := globalDevices.admissionDecisionFresh(uid, ip, deviceLimit, localIPs)
	if usedFreshGlobal {
		if reject {
			return true, false
		}
		e.pruneToAdmitted(admitted)
		e.touchIP(ip, uid)
		return false, false
	}

	return e.addIP(ip, uid, deviceLimit), false
}

// addIP records an IP for this user. Returns false (reject) if device limit exceeded.
func (e *userOnlineEntry) addIP(ip string, uid int, deviceLimit int) (reject bool) {
	now := time.Now().Unix()
	// Fast path: IP already tracked
	if v, loaded := e.ips.Load(ip); loaded {
		entry := v.(connIP)
		entry.LastSeen = now
		e.ips.Store(ip, entry)
		return false
	}
	// New IP — check device limit before adding
	if deviceLimit > 0 {
		current := atomic.LoadInt32(&e.count)
		if int(current) >= deviceLimit {
			return true // reject
		}
	}
	// Try to store; if another goroutine stored the same IP concurrently, don't double-count
	if _, loaded := e.ips.LoadOrStore(ip, connIP{UID: uid, LastSeen: now}); !loaded {
		atomic.AddInt32(&e.count, 1)
	}
	return false
}

// cleanStale removes IPs not seen within ttl and returns remaining count.
func (e *userOnlineEntry) cleanStale(ttl int64) int32 {
	return e.cleanStaleAndCollect(ttl, nil, false)
}

func (e *userOnlineEntry) cleanStaleAndCollect(ttl int64, out *[]api.OnlineUser, retireEmpty bool) int32 {
	e.mu.Lock()
	defer e.mu.Unlock()

	now := time.Now().Unix()
	e.ips.Range(func(key, value interface{}) bool {
		entry := value.(connIP)
		if now-entry.LastSeen > ttl {
			e.deleteIP(key)
			return true
		}
		if out != nil {
			*out = append(*out, api.OnlineUser{UID: entry.UID, IP: key.(string)})
		}
		return true
	})
	remaining := atomic.LoadInt32(&e.count)
	if remaining == 0 && retireEmpty {
		e.retired = true
	}
	return remaining
}

// collectOnline gathers all online user records efficiently.
func (e *userOnlineEntry) collectOnline(out *[]api.OnlineUser) {
	e.mu.Lock()
	defer e.mu.Unlock()

	e.ips.Range(func(key, value interface{}) bool {
		entry := value.(connIP)
		*out = append(*out, api.OnlineUser{UID: entry.UID, IP: key.(string)})
		return true
	})
}

type InboundInfo struct {
	Tag            string
	NodeSpeedLimit uint64
	UserInfo       *sync.Map // Key: user tag (buildUserTag) -> UserInfo
	BucketHub      *sync.Map // Key: user tag -> *rate.Limiter
	UserOnlineIP   *sync.Map // Key: user tag -> *userOnlineEntry
	GlobalDevices  *globalDeviceState
	GlobalLimit    *globalLimitState

	admissionMu         sync.RWMutex
	retired             bool
	replacementReady    chan struct{}
	replacementNotified bool
	policyVersion       uint64
	owner               *Limiter
	ownerTag            string
	self                *InboundInfo
	applied             atomic.Bool
	ownedGlobalLimit    *globalLimitState
}

type inboundState = InboundInfo

func (i *inboundState) beginAdmission() (bool, <-chan struct{}) {
	if i == nil {
		return false, nil
	}
	i.admissionMu.RLock()
	if i.retired {
		replacementReady := i.replacementReady
		i.admissionMu.RUnlock()
		return false, replacementReady
	}
	return true, nil
}

func (i *inboundState) endAdmission() {
	i.admissionMu.RUnlock()
}

func (i *inboundState) retireAdmissions() {
	if i == nil {
		return
	}
	i.admissionMu.Lock()
	if !i.retired {
		i.retired = true
		i.replacementReady = make(chan struct{})
		i.replacementNotified = false
	}
	i.admissionMu.Unlock()
}

func (i *inboundState) activateAdmissions() {
	if i == nil {
		return
	}
	i.admissionMu.Lock()
	if i.retired && !i.replacementNotified {
		close(i.replacementReady)
	}
	i.retired = false
	i.replacementReady = nil
	i.replacementNotified = false
	i.admissionMu.Unlock()
}

func (i *inboundState) notifyReplacement() {
	if i == nil {
		return
	}
	i.admissionMu.Lock()
	if i.retired && !i.replacementNotified {
		close(i.replacementReady)
		i.replacementNotified = true
	}
	i.admissionMu.Unlock()
}

type globalLimitBackend struct {
	globalOnlineIP *marshaler.Marshaler
	closer         io.Closer
}

func newGlobalLimitBackend(config *GlobalDeviceLimitConfig) globalLimitBackend {
	gs := goCacheStore.NewGoCache(goCache.New(time.Duration(config.Expiry)*time.Second, time.Minute))
	client := redis.NewClient(&redis.Options{
		Network:  config.RedisNetwork,
		Addr:     config.RedisAddr,
		Username: config.RedisUsername,
		Password: config.RedisPassword,
		DB:       config.RedisDB,
	})
	rs := redisStore.NewRedis(client, store.WithExpiration(time.Duration(config.Expiry)*time.Second))
	cacheManager := cache.NewChain[any](cache.New[any](gs), cache.New[any](rs))
	return globalLimitBackend{
		globalOnlineIP: marshaler.New(cacheManager),
		closer:         client,
	}
}

type globalLimitState struct {
	config         *GlobalDeviceLimitConfig
	globalOnlineIP *marshaler.Marshaler
	closer         io.Closer
	useMu          sync.RWMutex
	keyLocks       sync.Map // Key: user tag -> *sync.Mutex, serializes global-limit cache updates per user
	closeOnce      sync.Once
	closeErr       error
	closed         bool
}

func (s *globalLimitState) Close() error {
	if s == nil {
		return nil
	}
	s.closeOnce.Do(func() {
		s.useMu.Lock()
		defer s.useMu.Unlock()
		s.closed = true
		if s.closer != nil {
			s.closeErr = s.closer.Close()
		}
	})
	return s.closeErr
}

func (s *globalLimitState) restoreConfigIfClosed() (*GlobalDeviceLimitConfig, bool) {
	if s == nil {
		return nil, true
	}
	s.useMu.RLock()
	defer s.useMu.RUnlock()
	if !s.closed {
		return nil, false
	}
	if s.config == nil {
		return nil, true
	}
	config := *s.config
	return &config, true
}

func (s *globalLimitState) pruneKeyLocks(activeUsers *sync.Map) {
	if s == nil || s.config == nil || !s.config.Enable {
		return
	}

	s.useMu.Lock()
	defer s.useMu.Unlock()
	s.keyLocks.Range(func(key, value interface{}) bool {
		if activeUsers == nil {
			s.keyLocks.Delete(key)
			return true
		}
		if _, active := activeUsers.Load(key); !active {
			s.keyLocks.Delete(key)
		}
		return true
	})
}

func (i *inboundState) Close() error {
	if i == nil {
		return nil
	}
	i.retireAdmissions()
	err := i.ownedGlobalLimit.Close()
	i.notifyReplacement()
	return err
}

type ownedOperations struct {
	mu     sync.Mutex
	cond   *sync.Cond
	ctx    context.Context
	cancel context.CancelFunc
	active int
	closed bool
}

func newOwnedOperations() *ownedOperations {
	ctx, cancel := context.WithCancel(context.Background())
	operations := &ownedOperations{ctx: ctx, cancel: cancel}
	operations.cond = sync.NewCond(&operations.mu)
	return operations
}

func (o *ownedOperations) begin() (context.Context, bool) {
	o.mu.Lock()
	defer o.mu.Unlock()
	if o.closed {
		return o.ctx, false
	}
	o.active++
	return o.ctx, true
}

func (o *ownedOperations) end() {
	o.mu.Lock()
	o.active--
	if o.active == 0 {
		o.cond.Broadcast()
	}
	o.mu.Unlock()
}

func (o *ownedOperations) Close() {
	if o == nil {
		return
	}
	o.mu.Lock()
	if !o.closed {
		o.closed = true
		o.cancel()
	}
	for o.active > 0 {
		o.cond.Wait()
	}
	o.mu.Unlock()
}

type Limiter struct {
	InboundInfo      *sync.Map
	ownedInboundInfo *sync.Map // Key: Tag, Value: the lifecycle-owned applied *InboundInfo

	lifecycleMu sync.Mutex
	closed      atomic.Bool
	closeErr    error
	cleanupErrs []error
	operations  *ownedOperations

	buildGlobalLimitBackend func(*GlobalDeviceLimitConfig) globalLimitBackend

	onAdmissionEntered         func()
	onAdmissionDrainStarted    func()
	onAdmissionWaiting         func()
	onBeforeReplacementPublish func()
	onRateWaitEntered          func()
	onCloseDrainEntered        func()
}

func New() *Limiter {
	return &Limiter{
		InboundInfo:             new(sync.Map),
		ownedInboundInfo:        new(sync.Map),
		operations:              newOwnedOperations(),
		buildGlobalLimitBackend: newGlobalLimitBackend,
	}
}
func (l *Limiter) loadAppliedInbound(tag string) (*inboundState, bool) {
	if l == nil || l.InboundInfo == nil {
		return nil, false
	}
	value, ok := l.InboundInfo.Load(tag)
	if !ok {
		return nil, false
	}
	state, ok := value.(*inboundState)
	if !ok || state == nil || state.owner != l || state.ownerTag != tag || state.self != state || !state.applied.Load() {
		return nil, false
	}
	return state, true
}

func (l *Limiter) publishAppliedInbound(tag string, state *inboundState) {
	state.owner = l
	state.ownerTag = tag
	state.self = state
	state.applied.Store(true)
	l.ownedInboundInfo.Store(tag, state)
	l.InboundInfo.Store(tag, state)
}

func retireAppliedInbound(state *inboundState) {
	if state != nil {
		state.applied.Store(false)
	}
}

func (l *Limiter) publishReplacementInbound(tag string, applied, replacement *inboundState) {
	if l.onBeforeReplacementPublish != nil {
		l.onBeforeReplacementPublish()
	}
	l.publishAppliedInbound(tag, replacement)
	retireAppliedInbound(applied)
	applied.notifyReplacement()
}

func (l *Limiter) beginMutation() error {
	if l == nil {
		return fmt.Errorf("limiter is nil")
	}
	l.lifecycleMu.Lock()
	if l.closed.Load() {
		l.lifecycleMu.Unlock()
		return fmt.Errorf("limiter is closed")
	}
	return nil
}

func (l *Limiter) endMutation() {
	l.lifecycleMu.Unlock()
}

func (l *Limiter) beginOwnedOperation() (context.Context, bool) {
	if l == nil || l.closed.Load() {
		return context.Background(), false
	}
	if l.operations == nil {
		return context.Background(), true
	}
	return l.operations.begin()
}

func (l *Limiter) endOwnedOperation() {
	if l != nil && l.operations != nil {
		l.operations.end()
	}
}

func (l *Limiter) drainAdmissions(state *inboundState) {
	if l.onAdmissionDrainStarted != nil {
		l.onAdmissionDrainStarted()
	}
	state.retireAdmissions()
}

func (l *Limiter) recordCleanupError(operation string, err error) error {
	if err == nil {
		return nil
	}
	wrapped := fmt.Errorf("%s: %w", operation, err)
	l.cleanupErrs = append(l.cleanupErrs, wrapped)
	xrayerrors.LogErrorInner(context.Background(), wrapped, "limiter cleanup")
	return wrapped
}

func (l *Limiter) Close() error {
	if l == nil {
		return nil
	}
	l.lifecycleMu.Lock()
	defer l.lifecycleMu.Unlock()
	if l.closed.Load() {
		return l.closeErr
	}
	l.closed.Store(true)
	if l.onCloseDrainEntered != nil {
		l.onCloseDrainEntered()
	}
	if l.operations != nil {
		l.operations.Close()
	}

	closeErrs := append([]error(nil), l.cleanupErrs...)
	l.ownedInboundInfo.Range(func(key, value interface{}) bool {
		l.ownedInboundInfo.Delete(key)
		l.InboundInfo.Delete(key)
		retireAppliedInbound(value.(*inboundState))
		if err := value.(*inboundState).Close(); err != nil {
			closeErrs = append(closeErrs, err)
		}
		return true
	})
	l.closeErr = errors.Join(closeErrs...)
	return l.closeErr
}

func newInboundLimiterStateSnapshot() *InboundLimiterStateSnapshot {
	return &InboundLimiterStateSnapshot{
		UserInfo: make(map[string]UserInfo),
		Buckets:  make(map[string]bucketStateSnapshot),
	}
}

func populateCompatibilitySnapshot(snapshot *InboundLimiterStateSnapshot) {
	if snapshot == nil {
		return
	}
	snapshot.Buckets = make(map[string]bucketStateSnapshot, len(snapshot.buckets))
	for userKey, bucket := range snapshot.buckets {
		snapshot.Buckets[userKey] = bucketStateSnapshot{
			Limit: bucket.Limit(),
			Burst: bucket.Burst(),
		}
	}
}

func snapshotInboundPolicies(state *inboundState, users map[string]userPolicy) map[string]*rate.Limiter {
	if users == nil {
		users = make(map[string]userPolicy)
	}
	buckets := make(map[string]*rate.Limiter)
	if state == nil {
		return buckets
	}
	state.UserInfo.Range(func(key, value interface{}) bool {
		users[key.(string)] = value.(userPolicy)
		return true
	})
	state.BucketHub.Range(func(key, value interface{}) bool {
		buckets[key.(string)] = value.(*rate.Limiter)
		return true
	})
	return buckets
}

func clearSyncMap(values *sync.Map) {
	if values == nil {
		return
	}
	values.Range(func(key, _ interface{}) bool {
		values.Delete(key)
		return true
	})
}

func restoreInboundPolicies(state *inboundState, snapshot *InboundLimiterStateSnapshot) {
	if state == nil || snapshot == nil {
		return
	}
	compatibleCurrentBuckets := make(map[string]*rate.Limiter)
	state.BucketHub.Range(func(key, value interface{}) bool {
		compatibleCurrentBuckets[key.(string)] = value.(*rate.Limiter)
		return true
	})

	clearSyncMap(state.UserInfo)
	for userKey, user := range snapshot.UserInfo {
		state.UserInfo.Store(userKey, user)
	}
	clearSyncMap(state.BucketHub)
	for userKey, bucketState := range snapshot.Buckets {
		if original, exists := snapshot.buckets[userKey]; exists &&
			original.Limit() == bucketState.Limit && original.Burst() == bucketState.Burst {
			state.BucketHub.Store(userKey, original)
		} else {
			state.BucketHub.Store(userKey, rate.NewLimiter(bucketState.Limit, bucketState.Burst))
		}
	}
	for userKey, user := range snapshot.UserInfo {
		if _, restored := snapshot.Buckets[userKey]; restored {
			continue
		}
		if _, explicitlyDeleted := snapshot.buckets[userKey]; explicitlyDeleted {
			continue
		}
		bucket, exists := compatibleCurrentBuckets[userKey]
		limit := determineRate(state.NodeSpeedLimit, user.SpeedLimit)
		if !exists || limit == 0 || bucket.Limit() != rate.Limit(limit) || bucket.Burst() != int(limit) {
			continue
		}
		state.BucketHub.Store(userKey, bucket)
	}
	state.UserOnlineIP.Range(func(key, _ interface{}) bool {
		if _, applied := snapshot.UserInfo[key.(string)]; !applied {
			state.UserOnlineIP.Delete(key)
		}
		return true
	})
	state.policyVersion = snapshot.policyVersion
}

func (l *Limiter) newGlobalLimitState(config *GlobalDeviceLimitConfig) *globalLimitState {
	state := &globalLimitState{}
	if config == nil || !config.Enable {
		return state
	}
	appliedConfig := *config
	buildBackend := l.buildGlobalLimitBackend
	if buildBackend == nil {
		buildBackend = newGlobalLimitBackend
	}
	backend := buildBackend(&appliedConfig)
	state.config = &appliedConfig
	state.globalOnlineIP = backend.globalOnlineIP
	state.closer = backend.closer
	return state
}

func inheritCompatibleAdmissionState(candidate, applied *inboundState) {
	if candidate == nil || applied == nil {
		return
	}
	if applied.GlobalDevices != nil {
		candidate.GlobalDevices = applied.GlobalDevices
	}
	candidate.UserInfo.Range(func(key, value interface{}) bool {
		if online, exists := applied.UserOnlineIP.Load(key); exists {
			candidate.UserOnlineIP.Store(key, online)
		}
		user := value.(userPolicy)
		limit := determineRate(candidate.NodeSpeedLimit, user.SpeedLimit)
		if limit == 0 {
			return true
		}
		if existing, exists := applied.BucketHub.Load(key); exists {
			bucket := existing.(*rate.Limiter)
			if bucket.Limit() == rate.Limit(limit) && bucket.Burst() == int(limit) {
				candidate.BucketHub.Store(key, bucket)
			}
		}
		return true
	})
}

func (l *Limiter) AddInboundLimiter(tag string, nodeSpeedLimit uint64, userList *[]api.UserInfo, globalLimit *GlobalDeviceLimitConfig) error {
	if err := l.beginMutation(); err != nil {
		return err
	}
	defer l.endMutation()
	ownedGlobalLimit := l.newGlobalLimitState(globalLimit)
	candidate := &inboundState{
		Tag:              tag,
		NodeSpeedLimit:   nodeSpeedLimit,
		BucketHub:        new(sync.Map),
		UserOnlineIP:     new(sync.Map),
		GlobalDevices:    newGlobalDeviceState(),
		GlobalLimit:      ownedGlobalLimit,
		ownedGlobalLimit: ownedGlobalLimit,
	}

	userMap := new(sync.Map)
	for _, u := range *userList {
		userKey := fmt.Sprintf("%s|%s|%d", tag, u.Email, u.UID)
		userMap.Store(userKey, userPolicy{
			UID:         u.UID,
			SpeedLimit:  u.SpeedLimit,
			DeviceLimit: u.DeviceLimit,
		})
	}
	candidate.UserInfo = userMap
	if value, replaced := l.ownedInboundInfo.Load(tag); replaced {
		applied := value.(*inboundState)
		l.drainAdmissions(applied)
		inheritCompatibleAdmissionState(candidate, applied)
		l.publishReplacementInbound(tag, applied, candidate)
		if err := applied.ownedGlobalLimit.Close(); err != nil {
			l.recordCleanupError(fmt.Sprintf("close replaced inbound limiter %q", tag), err)
		}
		return nil
	}
	l.publishAppliedInbound(tag, candidate)
	return nil
}

func (l *Limiter) UpdateInboundLimiter(tag string, updatedUserList *[]api.UserInfo) error {
	if err := l.beginMutation(); err != nil {
		return err
	}
	defer l.endMutation()

	inboundInfo, ok := l.loadAppliedInbound(tag)
	if !ok {
		return fmt.Errorf("no such inbound in limiter: %s", tag)
	}
	l.drainAdmissions(inboundInfo)
	defer inboundInfo.activateAdmissions()

	if updatedUserList != nil {
		for _, user := range *updatedUserList {
			userKey := fmt.Sprintf("%s|%s|%d", tag, user.Email, user.UID)
			inboundInfo.UserInfo.Store(userKey, userPolicy{
				UID:         user.UID,
				SpeedLimit:  user.SpeedLimit,
				DeviceLimit: user.DeviceLimit,
			})

			limit := determineRate(inboundInfo.NodeSpeedLimit, user.SpeedLimit)
			if limit == 0 {
				inboundInfo.BucketHub.Delete(userKey)
			} else if existing, exists := inboundInfo.BucketHub.Load(userKey); exists {
				bucket := existing.(*rate.Limiter)
				if bucket.Limit() != rate.Limit(limit) || bucket.Burst() != int(limit) {
					inboundInfo.BucketHub.Store(userKey, rate.NewLimiter(rate.Limit(limit), int(limit)))
				}
			} else {
				inboundInfo.BucketHub.Store(userKey, rate.NewLimiter(rate.Limit(limit), int(limit)))
			}
		}
	}

	inboundInfo.policyVersion++
	inboundInfo.GlobalLimit.pruneKeyLocks(inboundInfo.UserInfo)
	return nil
}

func (l *Limiter) SnapshotInboundLimiterState(tag string) (*InboundLimiterStateSnapshot, error) {
	snapshot := newInboundLimiterStateSnapshot()
	if l == nil || l.InboundInfo == nil {
		return snapshot, nil
	}
	if err := l.beginMutation(); err != nil {
		return nil, err
	}
	defer l.endMutation()

	state, ok := l.loadAppliedInbound(tag)
	if !ok {
		return snapshot, fmt.Errorf("no such inbound in limiter: %s", tag)
	}
	snapshot.state = state
	snapshot.policyVersion = snapshot.state.policyVersion
	snapshot.buckets = snapshotInboundPolicies(snapshot.state, snapshot.UserInfo)
	populateCompatibilitySnapshot(snapshot)
	return snapshot, nil
}

func (l *Limiter) RestoreInboundLimiterState(tag string, snapshot *InboundLimiterStateSnapshot) error {
	if err := l.beginMutation(); err != nil {
		return err
	}
	defer l.endMutation()
	if snapshot == nil {
		return nil
	}
	if l.InboundInfo == nil || l.ownedInboundInfo == nil {
		return fmt.Errorf("limiter state is not initialized")
	}
	if snapshot.state == nil {
		value, ok := l.ownedInboundInfo.Load(tag)
		if !ok {
			return fmt.Errorf("no such inbound in limiter: %s", tag)
		}
		snapshot.state = value.(*inboundState)
		snapshot.policyVersion = snapshot.state.policyVersion
	}
	if snapshot.state.owner != l || snapshot.state.ownerTag != tag || snapshot.state.self != snapshot.state {
		return fmt.Errorf("snapshot does not belong to inbound %s", tag)
	}

	var candidate *inboundState
	if value, ok := l.ownedInboundInfo.Load(tag); ok {
		candidate = value.(*inboundState)
	}
	if candidate == snapshot.state {
		candidate.retireAdmissions()
		restoreInboundPolicies(candidate, snapshot)
		snapshot.state.activateAdmissions()
		l.publishAppliedInbound(tag, snapshot.state)
		snapshot.state.GlobalLimit.pruneKeyLocks(snapshot.state.UserInfo)
		return nil
	}
	if candidate != nil {
		candidate.retireAdmissions()
	}
	snapshot.state.retireAdmissions()
	restoreInboundPolicies(snapshot.state, snapshot)

	originalOwnedGlobalLimit := snapshot.state.ownedGlobalLimit
	publicUsesOwnedGlobalLimit := snapshot.state.GlobalLimit == originalOwnedGlobalLimit
	if config, closed := originalOwnedGlobalLimit.restoreConfigIfClosed(); closed {
		restoredGlobalLimit := l.newGlobalLimitState(config)
		snapshot.state.ownedGlobalLimit = restoredGlobalLimit
		if publicUsesOwnedGlobalLimit {
			snapshot.state.GlobalLimit = restoredGlobalLimit
		}
	}
	snapshot.state.activateAdmissions()
	if candidate != nil {
		l.publishReplacementInbound(tag, candidate, snapshot.state)
	} else {
		l.publishAppliedInbound(tag, snapshot.state)
	}
	snapshot.state.GlobalLimit.pruneKeyLocks(snapshot.state.UserInfo)

	if candidate != nil && candidate.ownedGlobalLimit != originalOwnedGlobalLimit {
		if err := candidate.ownedGlobalLimit.Close(); err != nil {
			return l.recordCleanupError(fmt.Sprintf("close rolled-back candidate inbound limiter %q", tag), err)
		}
	}
	return nil
}

func (l *Limiter) DeleteInboundLimiter(tag string) error {
	if err := l.beginMutation(); err != nil {
		return err
	}
	defer l.endMutation()
	l.InboundInfo.Delete(tag)
	if value, loaded := l.ownedInboundInfo.LoadAndDelete(tag); loaded {
		retireAppliedInbound(value.(*inboundState))
		if err := value.(*inboundState).Close(); err != nil {
			l.recordCleanupError(fmt.Sprintf("close deleted inbound limiter %q", tag), err)
		}
	}
	return nil
}

func (l *Limiter) UpdateGlobalDevices(tag string, devices map[int][]string) error {
	if err := l.beginMutation(); err != nil {
		return err
	}
	defer l.endMutation()
	if inboundInfo, ok := l.loadAppliedInbound(tag); ok {
		if inboundInfo.GlobalDevices == nil {
			return fmt.Errorf("global device state is not initialized for inbound: %s", tag)
		}
		inboundInfo.GlobalDevices.Replace(devices)
		return nil
	}
	return fmt.Errorf("no such inbound in limiter: %s", tag)
}

func (l *Limiter) ClearGlobalDevices(tag string) error {
	if err := l.beginMutation(); err != nil {
		return err
	}
	defer l.endMutation()
	if inboundInfo, ok := l.loadAppliedInbound(tag); ok {
		if inboundInfo.GlobalDevices != nil {
			inboundInfo.GlobalDevices.Clear()
		}
		return nil
	}
	return fmt.Errorf("no such inbound in limiter: %s", tag)
}

// ipTTL is the time-to-live for online IP entries. IPs not seen within this
// duration are considered stale and cleaned up during GetOnlineDevice.
const ipTTL int64 = 120 // seconds

func (l *Limiter) GetOnlineDevice(tag string) (*[]api.OnlineUser, error) {
	if err := l.beginMutation(); err != nil {
		return nil, err
	}
	defer l.endMutation()
	if inboundInfo, ok := l.loadAppliedInbound(tag); ok {
		// Pre-allocate with a reasonable capacity to reduce slice growth
		onlineUser := make([]api.OnlineUser, 0, 256)

		// Single pass: collect online IPs and clean stale entries
		inboundInfo.UserOnlineIP.Range(func(userKey, value interface{}) bool {
			entry := value.(*userOnlineEntry)
			// Clean stale IPs (not seen within TTL) and collect the fresh snapshot
			// while holding the per-user entry lock, so pruning/admission cannot
			// race the count bookkeeping.
			if entry.cleanStaleAndCollect(ipTTL, &onlineUser, true) == 0 {
				inboundInfo.UserOnlineIP.CompareAndDelete(userKey, entry)
				inboundInfo.BucketHub.Delete(userKey)
			}
			return true
		})

		return &onlineUser, nil
	}
	return nil, fmt.Errorf("no such inbound in limiter: %s", tag)
}

// SyncAliveList synchronizes the alive list from panel to local tracking
func (l *Limiter) SyncAliveList(tag string, aliveList map[int][]string) error {
	if err := l.beginMutation(); err != nil {
		return err
	}
	defer l.endMutation()
	if inboundInfo, ok := l.loadAppliedInbound(tag); ok {

		// Build a complete authoritative panel snapshot for quick lookup.
		panelIPs := make(map[string]map[string]bool)
		for uid, ips := range aliveList {
			uidStr := fmt.Sprintf("%d", uid)
			panelIPs[uidStr] = make(map[string]bool)
			for _, ip := range ips {
				panelIPs[uidStr][ip] = true
			}
		}

		// Sync local tracking with panel data
		processedUserKeys := make(map[string]struct{})
		syncEntry := func(entry *userOnlineEntry, uid int, admitted map[string]bool) {
			entry.mu.Lock()
			defer entry.mu.Unlock()

			entry.ips.Range(func(ip, val interface{}) bool {
				ipStr := ip.(string)
				if !admitted[ipStr] {
					entry.deleteIP(ip)
				}
				return true
			})
			for ip := range admitted {
				entry.touchIP(ip, uid)
			}
		}
		inboundInfo.UserOnlineIP.Range(func(userKey, value interface{}) bool {
			entry := value.(*userOnlineEntry)
			userKeyStr := userKey.(string)
			processedUserKeys[userKeyStr] = struct{}{}

			userValue, exists := inboundInfo.UserInfo.Load(userKey)
			if !exists {
				return true
			}
			uidInt := userValue.(userPolicy).UID
			uidStr := strconv.Itoa(uidInt)
			syncEntry(entry, uidInt, panelIPs[uidStr])
			return true
		})

		// Seed panel-confirmed devices for known users even if this process has
		// not observed a local connection for them yet.
		inboundInfo.UserInfo.Range(func(userKey, value interface{}) bool {
			userKeyStr := userKey.(string)
			if _, processed := processedUserKeys[userKeyStr]; processed {
				return true
			}
			user := value.(userPolicy)
			admitted, present := panelIPs[strconv.Itoa(user.UID)]
			if !present {
				return true
			}
			entry := newUserOnlineEntry()
			if existing, loaded := inboundInfo.UserOnlineIP.LoadOrStore(userKey, entry); loaded {
				entry = existing.(*userOnlineEntry)
			}
			syncEntry(entry, user.UID, admitted)
			return true
		})

		return nil
	}
	return fmt.Errorf("no such inbound in limiter: %s", tag)
}

func (l *Limiter) GetUserBucket(tag string, userKey string, ip string) (*rate.Limiter, bool, bool) {
	return l.getUserBucket(tag, userKey, ip)
}

func (l *Limiter) getUserBucket(tag string, userKey string, ip string) (limiter *rate.Limiter, SpeedLimit bool, Reject bool) {
	if l == nil {
		return nil, false, true
	}
	for {
		if l.closed.Load() {
			return nil, false, true
		}
		if l.InboundInfo == nil {
			xrayerrors.LogDebug(context.Background(), "Get Inbound Limiter information failed")
			return nil, false, true
		}
		value, ok := l.InboundInfo.Load(tag)
		inboundInfo, valid := value.(*inboundState)
		identityValid := ok && valid && inboundInfo != nil && inboundInfo.owner == l && inboundInfo.ownerTag == tag && inboundInfo.self == inboundInfo
		if !identityValid {
			xrayerrors.LogDebug(context.Background(), "Get Inbound Limiter information failed")
			return nil, false, true
		}
		if !inboundInfo.applied.Load() {
			current, currentOK := l.InboundInfo.Load(tag)
			if currentOK && current != value {
				continue
			}
			xrayerrors.LogDebug(context.Background(), "Get Inbound Limiter information failed")
			return nil, false, true
		}
		admitted, replacementReady := inboundInfo.beginAdmission()
		if !admitted {
			if replacementReady == nil {
				return nil, false, true
			}
			if l.onAdmissionWaiting != nil {
				l.onAdmissionWaiting()
			}
			<-replacementReady
			continue
		}
		if l.onAdmissionEntered != nil {
			l.onAdmissionEntered()
		}
		bucket, speedLimited, rejected := getUserBucketFromState(inboundInfo, userKey, ip)
		inboundInfo.endAdmission()
		return bucket, speedLimited, rejected
	}
}

func getUserBucketFromState(inboundInfo *inboundState, userKey string, ip string) (limiter *rate.Limiter, SpeedLimit bool, Reject bool) {
	var (
		userLimit        uint64
		deviceLimit, uid int
	)
	nodeLimit := inboundInfo.NodeSpeedLimit

	value, exists := inboundInfo.UserInfo.Load(userKey)
	if !exists {
		return nil, false, true
	}
	u := value.(userPolicy)
	uid = u.UID
	userLimit = u.SpeedLimit
	deviceLimit = u.DeviceLimit

	for {
		entryValue, ok := inboundInfo.UserOnlineIP.Load(userKey)
		if !ok {
			entryValue, _ = inboundInfo.UserOnlineIP.LoadOrStore(userKey, newUserOnlineEntry())
		}
		entry := entryValue.(*userOnlineEntry)
		reject, retry := entry.admitIP(ip, uid, deviceLimit, inboundInfo.GlobalDevices)
		if retry {
			continue
		}
		if reject {
			return nil, false, true
		}
		break
	}

	if inboundInfo.GlobalLimit != nil && inboundInfo.GlobalLimit.config != nil && inboundInfo.GlobalLimit.config.Enable {
		if reject := globalLimit(inboundInfo, userKey, uid, ip, deviceLimit); reject {
			return nil, false, true
		}
	}

	limit := determineRate(nodeLimit, userLimit)
	if limit > 0 {
		if v, ok := inboundInfo.BucketHub.Load(userKey); ok {
			return v.(*rate.Limiter), true, false
		}
		newLimiter := rate.NewLimiter(rate.Limit(limit), int(limit))
		if v, loaded := inboundInfo.BucketHub.LoadOrStore(userKey, newLimiter); loaded {
			return v.(*rate.Limiter), true, false
		}
		return newLimiter, true, false
	}
	return nil, false, false
}

func getGlobalLimitLock(inboundInfo *inboundState, uniqueKey string) *sync.Mutex {
	lock := &sync.Mutex{}
	if v, loaded := inboundInfo.GlobalLimit.keyLocks.LoadOrStore(uniqueKey, lock); loaded {
		return v.(*sync.Mutex)
	}
	return lock
}

// Global device limit
func globalLimit(inboundInfo *inboundState, userKey string, uid int, ip string, deviceLimit int) bool {
	state := inboundInfo.GlobalLimit
	state.useMu.RLock()
	defer state.useMu.RUnlock()
	if state.closed {
		return true
	}

	if state.globalOnlineIP == nil {
		return false
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Duration(inboundInfo.GlobalLimit.config.Timeout)*time.Second)
	defer cancel()

	uniqueKey := userKey
	lock := getGlobalLimitLock(inboundInfo, uniqueKey)
	lock.Lock()
	defer lock.Unlock()

	v, err := inboundInfo.GlobalLimit.globalOnlineIP.Get(ctx, uniqueKey, new(map[string]int))
	if err != nil {
		if _, ok := err.(*store.NotFound); ok {
			ipMap := map[string]int{ip: uid}
			if err := pushIP(ctx, inboundInfo, uniqueKey, &ipMap); err != nil {
				xrayerrors.LogErrorInner(context.Background(), err, "cache service")
			}
			return false
		}
		xrayerrors.LogErrorInner(context.Background(), err, "cache service")
		return false
	}

	cached := v.(*map[string]int)
	current := make(map[string]int, len(*cached)+1)
	for k, v := range *cached {
		current[k] = v
	}

	if _, ok := current[ip]; ok {
		return false
	}

	if deviceLimit > 0 && len(current) >= deviceLimit {
		return true
	}

	current[ip] = uid
	if err := pushIP(ctx, inboundInfo, uniqueKey, &current); err != nil {
		xrayerrors.LogErrorInner(context.Background(), err, "cache service")
	}

	return false
}

// push the ip to cache
func pushIP(ctx context.Context, inboundInfo *inboundState, uniqueKey string, ipMap *map[string]int) error {
	return inboundInfo.GlobalLimit.globalOnlineIP.Set(ctx, uniqueKey, ipMap)
}

// determineRate returns the minimum non-zero rate
func determineRate(nodeLimit, userLimit uint64) (limit uint64) {
	if nodeLimit == 0 && userLimit == 0 {
		return 0
	}
	if nodeLimit == 0 {
		return userLimit
	}
	if userLimit == 0 {
		return nodeLimit
	}
	if nodeLimit < userLimit {
		return nodeLimit
	}
	return userLimit
}

// ReplaceInboundUsers applies an authoritative user policy snapshot for one
// inbound. State for users absent from the replacement is not retained.
func (l *Limiter) ReplaceInboundUsers(tag string, userList *[]api.UserInfo) error {
	if err := l.beginMutation(); err != nil {
		return err
	}
	defer l.endMutation()
	value, ok := l.ownedInboundInfo.Load(tag)
	if !ok {
		return fmt.Errorf("no such inbound in limiter: %s", tag)
	}

	inboundInfo := value.(*inboundState)
	l.drainAdmissions(inboundInfo)
	userInfo := new(sync.Map)
	bucketHub := new(sync.Map)
	userOnlineIP := new(sync.Map)
	if userList != nil {
		for _, user := range *userList {
			userKey := fmt.Sprintf("%s|%s|%d", tag, user.Email, user.UID)
			userInfo.Store(userKey, userPolicy{
				UID:         user.UID,
				SpeedLimit:  user.SpeedLimit,
				DeviceLimit: user.DeviceLimit,
			})
			if existing, exists := inboundInfo.UserOnlineIP.Load(userKey); exists {
				userOnlineIP.Store(userKey, existing)
			}

			limit := determineRate(inboundInfo.NodeSpeedLimit, user.SpeedLimit)
			if limit == 0 {
				continue
			}
			if existing, exists := inboundInfo.BucketHub.Load(userKey); exists {
				bucket := existing.(*rate.Limiter)
				if bucket.Limit() == rate.Limit(limit) && bucket.Burst() == int(limit) {
					bucketHub.Store(userKey, bucket)
					continue
				}
			}
			bucketHub.Store(userKey, rate.NewLimiter(rate.Limit(limit), int(limit)))
		}
	}

	replacement := &inboundState{
		Tag:              inboundInfo.Tag,
		NodeSpeedLimit:   inboundInfo.NodeSpeedLimit,
		UserInfo:         userInfo,
		BucketHub:        bucketHub,
		UserOnlineIP:     userOnlineIP,
		GlobalDevices:    inboundInfo.GlobalDevices,
		GlobalLimit:      inboundInfo.GlobalLimit,
		ownedGlobalLimit: inboundInfo.ownedGlobalLimit,
	}
	l.publishReplacementInbound(tag, inboundInfo, replacement)
	inboundInfo.GlobalLimit.pruneKeyLocks(userInfo)
	return nil
}
