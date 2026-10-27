package limiter

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"hash/fnv"
	"net/netip"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/redis/go-redis/v9"
	xrayerrors "github.com/xtls/xray-core/common/errors"
)

const (
	globalAdmissionModeCache  = "cache"
	globalAdmissionModeStrict = "strict"

	globalAdmissionFailOpen   = "open"
	globalAdmissionFailClosed = "closed"

	globalAdmissionSourcePeer      = "peer"
	globalAdmissionSourceForwarded = "forwarded"

	defaultGlobalAdmissionExpiry  = 60
	defaultGlobalAdmissionTimeout = 5
	minGlobalAdmissionExpiry      = 3
	defaultGlobalIPv6Prefix       = 64
	fullIPv6Prefix                = 128

	globalAdmissionBreakerFailures = 3
	globalAdmissionBreakerCooldown = 5 * time.Second
	globalAdmissionKeyStripes      = 128
	globalAdmissionKeyPrefix       = "xrayrp:gli"
	globalAdmissionNamespaceLength = 24
)

var (
	// ErrGlobalAdmissionQuota reports that the effective per-UID source-IP
	// quota is full. Callers should reject the connection.
	ErrGlobalAdmissionQuota = errors.New("global device admission quota reached")
	// ErrGlobalAdmissionUnavailable reports that Redis-backed admission could
	// not be verified in FailMode=closed. Callers should reject the connection.
	ErrGlobalAdmissionUnavailable = errors.New("global device admission backend unavailable")
)

// GlobalAdmissionStatus is a credential-free readiness view. Degraded means
// the distributed guarantee is currently weakened: Redis admission failed or
// a live holder lost its reservation. It clears only after every live holder
// is reserved again.
type GlobalAdmissionStatus struct {
	Degraded bool
	Reason   string
}

// GlobalAdmission coordinates cross-node source-IP quotas for one panel
// namespace. It is safe for concurrent use. Managers with the same Redis
// connection share one process-wide client; each manager owns its policies,
// holders and renewal worker.
type GlobalAdmission struct {
	backend    *globalAdmissionBackend
	instanceID string
	mode       string
	failClosed bool
	expiry     time.Duration
	timeout    time.Duration
	leaseTTL   time.Duration
	ipv6Prefix int
	keyPrefix  string

	mu             sync.Mutex
	policies       map[int]int
	policiesKnown  bool
	policiesDirty  bool
	policiesGen    uint64
	holders        map[globalAdmissionHolderKey]*globalAdmissionHolder
	holderSequence uint64
	breakerFails   int
	breakerUntil   time.Time
	backendFailed  bool
	policiesStale  bool

	keyLocks []chan struct{}

	closed    atomic.Bool
	closeOnce sync.Once
	ctx       context.Context
	cancel    context.CancelFunc
	closeCh   chan struct{}
	wakeCh    chan struct{}
	worker    sync.WaitGroup
}

type globalAdmissionHolderKey struct {
	uid int
	ip  string
}

// globalAdmissionHolder is one local reservation for a uid/IP pair. Several
// connections on the same manager share it, so one renewal keeps them all.
type globalAdmissionHolder struct {
	token       string
	uid         int
	ip          string
	limit       int
	pending     int
	live        int
	reserved    bool // token is confirmed in Redis
	lost        bool // commit or renewal could not confirm the token
	localOnly   bool // reservation exists only in this process
	confirmedAt time.Time
}

type globalAdmissionSettings struct {
	mode                 string
	failClosed           bool
	expiry               int
	timeout              int
	ipv6Prefix           int
	strictClientIPSource string
}

// NewGlobalAdmission builds a Redis-backed admission manager. It returns
// (nil, nil) when global device limiting is disabled.
func NewGlobalAdmission(config *GlobalDeviceLimitConfig, panelType, apiHost string) (*GlobalAdmission, error) {
	if config == nil || !config.Enable {
		return nil, nil
	}

	settings, err := normalizeGlobalAdmissionSettings(config)
	if err != nil {
		return nil, err
	}
	namespace, err := globalAdmissionNamespace(config, panelType, apiHost)
	if err != nil {
		return nil, err
	}

	timeout := time.Duration(settings.timeout) * time.Second
	backend := acquireGlobalAdmissionBackend(config, timeout)
	instanceID, err := randomGlobalAdmissionID()
	if err != nil {
		backend.release()
		return nil, fmt.Errorf("unable to create global device admission instance: %w", err)
	}

	expiry := time.Duration(settings.expiry) * time.Second
	ctx, cancel := context.WithCancel(context.Background())
	keyLocks := make([]chan struct{}, globalAdmissionKeyStripes)
	for index := range keyLocks {
		keyLocks[index] = make(chan struct{}, 1)
	}
	admission := &GlobalAdmission{
		backend:    backend,
		instanceID: instanceID,
		mode:       settings.mode,
		failClosed: settings.failClosed,
		expiry:     expiry,
		timeout:    timeout,
		leaseTTL:   expiry,
		ipv6Prefix: settings.ipv6Prefix,
		keyPrefix:  globalAdmissionKeyPrefix + ":" + namespace,
		holders:    make(map[globalAdmissionHolderKey]*globalAdmissionHolder),
		keyLocks:   keyLocks,
		ctx:        ctx,
		cancel:     cancel,
		closeCh:    make(chan struct{}),
		wakeCh:     make(chan struct{}, 1),
	}
	admission.worker.Add(1)
	go admission.renewWorker()
	return admission, nil
}

// ValidateGlobalDeviceLimitConfig validates an enabled configuration without
// mutating it. forwardedConfigured reports whether trusted forwarded source
// headers are configured. Strict mode requires an explicit acknowledgement
// that those headers are the intended source identity.
func ValidateGlobalDeviceLimitConfig(config *GlobalDeviceLimitConfig, forwardedConfigured bool) error {
	if config == nil || !config.Enable {
		return nil
	}
	settings, err := normalizeGlobalAdmissionSettings(config)
	if err != nil {
		return err
	}
	if settings.mode == globalAdmissionModeStrict &&
		forwardedConfigured &&
		settings.strictClientIPSource != globalAdmissionSourceForwarded {
		return errors.New("global device limit strict mode with trusted forwarded headers requires StrictClientIPSource=forwarded")
	}
	return nil
}

// NormalizeGlobalIP returns a canonical source-IP identity. IPv4 and
// IPv4-mapped addresses ignore prefix; IPv6 is masked to prefix (nil means /64,
// 0 means the full /128 address). Addresses with a zone are rejected.
func NormalizeGlobalIP(ip string, prefix *int) (string, error) {
	trimmed := strings.TrimSpace(ip)
	if trimmed == "" {
		return "", errors.New("global device limit source IP must not be empty")
	}
	address, err := netip.ParseAddr(trimmed)
	if err != nil {
		return "", errors.New("global device limit source IP is not a valid address")
	}
	if address.Zone() != "" {
		return "", errors.New("global device limit source IP must not contain a zone")
	}
	address = address.Unmap()
	if address.Is4() {
		return address.String(), nil
	}

	bits := defaultGlobalIPv6Prefix
	if prefix != nil {
		bits = *prefix
	}
	if bits < 0 || bits > fullIPv6Prefix {
		return "", errors.New("global device limit IPv6 prefix must be between 0 and 128")
	}
	if bits == 0 {
		bits = fullIPv6Prefix
	}
	network, err := address.Prefix(bits)
	if err != nil {
		return "", errors.New("global device limit IPv6 prefix is invalid for this address")
	}
	return network.Masked().Addr().String(), nil
}

func normalizeGlobalAdmissionSettings(config *GlobalDeviceLimitConfig) (globalAdmissionSettings, error) {
	settings := globalAdmissionSettings{
		mode:                 strings.ToLower(strings.TrimSpace(config.Mode)),
		expiry:               config.Expiry,
		timeout:              config.Timeout,
		ipv6Prefix:           defaultGlobalIPv6Prefix,
		strictClientIPSource: strings.ToLower(strings.TrimSpace(config.StrictClientIPSource)),
	}
	if settings.mode == "" {
		settings.mode = globalAdmissionModeCache
	}
	switch settings.mode {
	case globalAdmissionModeCache, globalAdmissionModeStrict:
	default:
		return globalAdmissionSettings{}, fmt.Errorf("global device limit Mode must be %q or %q", globalAdmissionModeCache, globalAdmissionModeStrict)
	}

	switch strings.ToLower(strings.TrimSpace(config.FailMode)) {
	case "", globalAdmissionFailOpen:
	case globalAdmissionFailClosed:
		settings.failClosed = true
	default:
		return globalAdmissionSettings{}, fmt.Errorf("global device limit FailMode must be %q or %q", globalAdmissionFailOpen, globalAdmissionFailClosed)
	}

	if settings.expiry < 0 {
		return globalAdmissionSettings{}, errors.New("global device limit Expiry must not be negative")
	}
	if settings.expiry == 0 {
		settings.expiry = defaultGlobalAdmissionExpiry
	}
	if settings.expiry < minGlobalAdmissionExpiry {
		return globalAdmissionSettings{}, fmt.Errorf("global device limit Expiry must be at least %d seconds", minGlobalAdmissionExpiry)
	}

	if settings.timeout < 0 {
		return globalAdmissionSettings{}, errors.New("global device limit Timeout must not be negative")
	}
	if settings.timeout == 0 {
		settings.timeout = defaultGlobalAdmissionTimeout
	}

	if config.IPv6Prefix != nil {
		settings.ipv6Prefix = *config.IPv6Prefix
	}
	if settings.ipv6Prefix < 0 || settings.ipv6Prefix > fullIPv6Prefix {
		return globalAdmissionSettings{}, errors.New("global device limit IPv6Prefix must be between 0 and 128")
	}
	if settings.ipv6Prefix == 0 {
		settings.ipv6Prefix = fullIPv6Prefix
	}

	switch settings.strictClientIPSource {
	case "", globalAdmissionSourcePeer, globalAdmissionSourceForwarded:
	default:
		return globalAdmissionSettings{}, fmt.Errorf("global device limit StrictClientIPSource must be %q or %q", globalAdmissionSourcePeer, globalAdmissionSourceForwarded)
	}
	return settings, nil
}

// globalAdmissionNamespace derives the stable shared key space. It never
// includes node tags, credentials or unhashed panel URLs in Redis keys.
func globalAdmissionNamespace(config *GlobalDeviceLimitConfig, panelType, apiHost string) (string, error) {
	if override := strings.TrimSpace(config.Namespace); override != "" {
		return hashGlobalAdmissionNamespace("override\x00" + override), nil
	}

	canonicalType := canonicalGlobalPanelType(panelType)
	if canonicalType == "" {
		canonicalType = canonicalGlobalPanelType(config.PanelType)
	}
	rawHost := strings.TrimSpace(apiHost)
	if rawHost == "" {
		rawHost = strings.TrimSpace(config.APIHost)
	}
	canonicalHost, err := canonicalGlobalAPIHost(rawHost)
	if err != nil {
		return "", err
	}
	if canonicalType == "" || canonicalHost == "" {
		return "", errors.New("global device limit requires both PanelType and ApiHost, or an explicit Namespace")
	}
	return hashGlobalAdmissionNamespace("panel\x00" + canonicalType + "\x00" + canonicalHost), nil
}

func hashGlobalAdmissionNamespace(basis string) string {
	sum := sha256.Sum256([]byte(basis))
	return hex.EncodeToString(sum[:])[:globalAdmissionNamespaceLength]
}

func canonicalGlobalPanelType(panelType string) string {
	normalized := strings.ToLower(strings.TrimSpace(panelType))
	switch normalized {
	case "v2board", "newv2board":
		return "newv2board"
	default:
		return normalized
	}
}

func canonicalGlobalAPIHost(raw string) (string, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return "", nil
	}
	parsed, err := url.Parse(raw)
	if err != nil || !parsed.IsAbs() || parsed.Host == "" {
		return "", errors.New("global device limit ApiHost must be an absolute HTTP or HTTPS URL")
	}
	scheme := strings.ToLower(parsed.Scheme)
	if scheme != "http" && scheme != "https" {
		return "", errors.New("global device limit ApiHost must use HTTP or HTTPS")
	}
	host := strings.ToLower(parsed.Host)
	path := strings.TrimRight(parsed.EscapedPath(), "/")
	return scheme + "://" + host + path, nil
}

func randomGlobalAdmissionID() (string, error) {
	buffer := make([]byte, 16)
	if _, err := rand.Read(buffer); err != nil {
		return "", err
	}
	return hex.EncodeToString(buffer), nil
}

// Acquire reserves one normalized source IP for uid and returns a tentative
// lease. Callers must Commit after local admission accepts the connection,
// Abort when downstream admission fails, and Close when the connection ends.
//
// On Redis failure, FailMode=open still enforces this process's local quota and
// returns a local-only lease (GlobalConfirmed false); FailMode=closed returns
// ErrGlobalAdmissionUnavailable. A closed manager always returns
// ErrGlobalAdmissionUnavailable. A nil receiver returns (nil, nil).
func (a *GlobalAdmission) Acquire(ctx context.Context, uid int, ip string, limit int) (*GlobalLease, error) {
	if a == nil {
		return nil, nil
	}
	normalized, err := NormalizeGlobalIP(ip, &a.ipv6Prefix)
	if err != nil {
		return nil, err
	}
	if a.closed.Load() {
		// A closed manager is a lifecycle condition, not a Redis outage: never
		// silently accept connections through a nil lease.
		return nil, ErrGlobalAdmissionUnavailable
	}
	callerCtx := ctx
	if err := callerCtx.Err(); err != nil {
		// A canceled connection must never fall through to local admission.
		return nil, err
	}

	// One deadline bounds the whole Acquire, including semaphore wait, policy
	// publish and the atomic reservation, so an unrelated queued caller cannot
	// hold this request past Timeout. callerCtx stays the parent so caller
	// cancellation propagates to every step; the failure paths below check
	// callerCtx.Err() to tell it apart from this internal deadline. Note that
	// go-redis applies ctx.Deadline() to the socket but does not watch ctx.Done()
	// during a blocking read, so a cancellation arriving mid-command is honored
	// once that command returns, at worst after Timeout.
	ctx, cancel := a.operationContext(callerCtx)
	defer cancel()

	// Per-key-stripe semaphore serializes atomic decisions for one uid/IP while
	// honoring caller cancellation and manager close. It is never held together
	// with the manager mutex during network I/O.
	lock := a.keyLock(uid, normalized)
	select {
	case lock <- struct{}{}:
		defer func() { <-lock }()
	case <-callerCtx.Done():
		return nil, callerCtx.Err()
	case <-a.ctx.Done():
		return nil, ErrGlobalAdmissionUnavailable
	case <-ctx.Done():
		// Internal Timeout expired while queued; this is an outage, not a
		// canceled connection, so FailMode applies.
		return a.acquireLocalForCaller(callerCtx, uid, normalized, limit)
	}

	if !a.requestAllowed() {
		return a.acquireLocalForCaller(callerCtx, uid, normalized, limit)
	}

	key := globalAdmissionHolderKey{uid: uid, ip: normalized}
	a.mu.Lock()
	holder := a.holders[key]
	if holder != nil && a.mode == globalAdmissionModeCache && holder.reserved && !holder.lost &&
		(holder.pending > 0 || holder.live > 0) &&
		time.Since(holder.confirmedAt) <= a.leaseTTL {
		holder.pending++
		a.mu.Unlock()
		return a.newLease(holder, uid, normalized, limit), nil
	}
	if holder == nil {
		a.holderSequence++
		holder = &globalAdmissionHolder{
			token: a.instanceID + "-" + strconv.FormatUint(a.holderSequence, 36),
			uid:   uid,
			ip:    normalized,
			limit: limit,
		}
		a.holders[key] = holder
	} else if limit > 0 {
		holder.limit = limit
	}
	holder.pending++
	state := "p"
	if holder.live > 0 {
		state = "l"
	}
	holderToken := holder.token
	holderLimit := holder.limit
	a.mu.Unlock()

	// Policy registrations must be visible before a quota decision, including
	// users that have no connections yet.
	if err := a.flushPoliciesIfDirty(ctx); err != nil {
		a.releaseFailedAcquire(key, holder)
		if callerErr := callerCtx.Err(); callerErr != nil {
			// The caller abandoned this attempt; that is not a backend fault.
			return nil, callerErr
		}
		a.recordBackendFailure()
		return a.acquireLocal(uid, normalized, limit)
	}

	allowed, err := a.upsert(ctx, uid, normalized, holderLimit, holderToken, state)
	if err != nil {
		a.releaseFailedAcquire(key, holder)
		if callerErr := callerCtx.Err(); callerErr != nil {
			return nil, callerErr
		}
		a.recordBackendFailure()
		return a.acquireLocal(uid, normalized, limit)
	}
	if !allowed {
		a.releaseFailedAcquire(key, holder)
		a.recordBackendSuccess()
		return nil, ErrGlobalAdmissionQuota
	}

	a.mu.Lock()
	holder.reserved = true
	holder.localOnly = false
	holder.lost = false
	holder.confirmedAt = time.Now()
	a.mu.Unlock()
	a.recordBackendSuccess()
	return a.newLease(holder, uid, normalized, holderLimit), nil
}

// acquireLocalForCaller applies FailMode after an internal Timeout or an open
// circuit breaker. A caller that already gave up gets its own context error.
func (a *GlobalAdmission) acquireLocalForCaller(callerCtx context.Context, uid int, ip string, limit int) (*GlobalLease, error) {
	if err := callerCtx.Err(); err != nil {
		return nil, err
	}
	return a.acquireLocal(uid, ip, limit)
}

// acquireLocal enforces a process-local quota when Redis is unusable. It keeps
// FailMode=open from becoming unlimited while the shared guarantee is down and
// returns a lease whose holder is retried by the renewal worker on recovery.
func (a *GlobalAdmission) acquireLocal(uid int, ip string, limit int) (*GlobalLease, error) {
	if a.failClosed {
		return nil, ErrGlobalAdmissionUnavailable
	}
	key := globalAdmissionHolderKey{uid: uid, ip: ip}

	a.mu.Lock()
	holder := a.holders[key]
	if holder != nil {
		if limit > 0 {
			holder.limit = limit
		}
		holder.pending++
		holder.lost = true
		a.mu.Unlock()
		return a.newLease(holder, uid, ip, limit), nil
	}

	effective := a.localEffectiveLimitLocked(uid, limit)
	if effective > 0 && a.localDistinctLocked(uid, ip) >= effective {
		a.mu.Unlock()
		return nil, ErrGlobalAdmissionQuota
	}
	a.holderSequence++
	holder = &globalAdmissionHolder{
		token:     a.instanceID + "-" + strconv.FormatUint(a.holderSequence, 36),
		uid:       uid,
		ip:        ip,
		limit:     limit,
		localOnly: true,
		lost:      true,
	}
	a.holders[key] = holder
	holder.pending++
	a.mu.Unlock()
	return a.newLease(holder, uid, ip, limit), nil
}

// localEffectiveLimitLocked finds this user's positive registered limit or the
// caller's own limit. A zero registration never raises the effective limit.
func (a *GlobalAdmission) localEffectiveLimitLocked(uid, fallback int) int {
	if a.policiesKnown {
		if policyLimit, ok := a.policies[uid]; ok && policyLimit > 0 {
			minimum := policyLimit
			if fallback > 0 && fallback < minimum {
				minimum = fallback
			}
			return minimum
		}
	}
	return fallback
}

// localDistinctLocked counts distinct live IPs for uid other than ip.
func (a *GlobalAdmission) localDistinctLocked(uid int, ip string) int {
	count := 0
	for _, holder := range a.holders {
		if holder.uid != uid || (holder.pending <= 0 && holder.live <= 0) {
			continue
		}
		if holder.ip == ip {
			continue
		}
		count++
	}
	return count
}

// UpdateLimit records the latest device limit for uid without network I/O.
// The renewal worker publishes it, including when the user has no connection.
func (a *GlobalAdmission) UpdateLimit(uid int, limit int) {
	if a == nil {
		return
	}
	a.mu.Lock()
	if a.policies == nil {
		a.policies = make(map[int]int)
	}
	a.policies[uid] = limit
	a.policiesKnown = true
	a.policiesDirty = true
	a.policiesGen++
	// Keep existing holders aligned with the latest policy so renewal and
	// reacquisition never send a stale caller limit.
	for _, holder := range a.holders {
		if holder.uid == uid {
			holder.limit = limit
		}
	}
	a.mu.Unlock()
	a.wake()
}

// SetUsers replaces the complete known policy view without network I/O. Zero
// limits are registered but do not participate in the positive minimum.
func (a *GlobalAdmission) SetUsers(limits map[int]int) {
	if a == nil {
		return
	}
	copied := make(map[int]int, len(limits))
	for uid, limit := range limits {
		copied[uid] = limit
	}
	a.mu.Lock()
	a.policies = copied
	a.policiesKnown = true
	a.policiesDirty = true
	a.policiesGen++
	for _, holder := range a.holders {
		if limit, ok := copied[holder.uid]; ok {
			holder.limit = limit
		}
	}
	a.mu.Unlock()
	a.wake()
}

// LiveIPs returns committed, currently held source IPs grouped by UID. It is
// detached and intended for idle online-user reporting, not authentication.
func (a *GlobalAdmission) LiveIPs() map[int][]string {
	if a == nil {
		return nil
	}
	a.mu.Lock()
	live := make(map[int][]string)
	for _, holder := range a.holders {
		if holder.live > 0 {
			live[holder.uid] = append(live[holder.uid], holder.ip)
		}
	}
	a.mu.Unlock()
	for uid := range live {
		sort.Strings(live[uid])
	}
	return live
}

// StatusSnapshot reports whether the distributed guarantee is currently
// degraded. It never contains addresses, credentials, UIDs or IPs.
func (a *GlobalAdmission) StatusSnapshot() GlobalAdmissionStatus {
	if a == nil {
		return GlobalAdmissionStatus{}
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.statusLocked()
}

// Close stops renewal, cancels in-flight Redis work, joins the worker, and
// releases the shared backend reference. It performs no network I/O and is
// idempotent. Live leases stop being renewed and expire by TTL; callers that
// replace a node identity while its links are still alive should reuse the
// same manager rather than closing it.
func (a *GlobalAdmission) Close() error {
	if a == nil {
		return nil
	}
	a.closeOnce.Do(func() {
		a.closed.Store(true)
		a.cancel()
		close(a.closeCh)
		a.worker.Wait()
		a.backend.release()
	})
	return nil
}

func (a *GlobalAdmission) newLease(holder *globalAdmissionHolder, uid int, ip string, limit int) *GlobalLease {
	return &GlobalLease{manager: a, holder: holder, uid: uid, ip: ip, limit: limit}
}

// releaseFailedAcquire drops an unsuccessful Acquire attempt. A holder with
// committed live references is retained but marked lost so status reflects
// suspended coverage; a purely tentative holder is removed.
func (a *GlobalAdmission) releaseFailedAcquire(key globalAdmissionHolderKey, holder *globalAdmissionHolder) {
	a.mu.Lock()
	defer a.mu.Unlock()
	holder.pending--
	if holder.live > 0 {
		holder.lost = true
		return
	}
	if holder.pending <= 0 && !holder.reserved {
		if current, ok := a.holders[key]; ok && current == holder {
			delete(a.holders, key)
		}
	}
}

// detachPending removes one tentative local reference and reports whether this
// was the last reference, in which case the Redis token must be deleted. The
// caller holds lease.mu so state and counts change as one step.
func (a *GlobalAdmission) detachPending(key globalAdmissionHolderKey, holder *globalAdmissionHolder) (uid int, token string, shouldAbort bool) {
	a.mu.Lock()
	defer a.mu.Unlock()
	holder.pending--
	remove := holder.pending <= 0 && holder.live <= 0
	if remove {
		if current, ok := a.holders[key]; ok && current == holder {
			delete(a.holders, key)
		}
	}
	return holder.uid, holder.token, remove && !holder.localOnly && !a.closed.Load()
}

// abortToken deletes only this exact token. A committed grace lease for the
// same instance/IP is a different token and stays intact.
func (a *GlobalAdmission) abortToken(uid int, token string) error {
	ctx, cancel := a.operationContext(context.Background())
	defer cancel()
	if err := a.abortPending(ctx, uid, token); err != nil {
		a.recordBackendFailure()
		return err
	}
	a.recordBackendSuccess()
	return nil
}

// releasePendingLease is used by Acquire's failure paths, where no lease mutex
// is involved yet.
func (a *GlobalAdmission) releasePendingLease(key globalAdmissionHolderKey, holder *globalAdmissionHolder) error {
	uid, token, shouldAbort := a.detachPending(key, holder)
	if !shouldAbort {
		return nil
	}
	return a.abortToken(uid, token)
}

// detachLive removes one committed local reference.
func (a *GlobalAdmission) detachLive(key globalAdmissionHolderKey, holder *globalAdmissionHolder) {
	a.mu.Lock()
	defer a.mu.Unlock()
	holder.live--
	if holder.live <= 0 && holder.pending <= 0 {
		// Stop renewing this local hold. Redis keeps the member until TTL; a
		// last close never issues an unconditional cross-node delete.
		if current, ok := a.holders[key]; ok && current == holder {
			delete(a.holders, key)
		}
	}
}

func (a *GlobalAdmission) releaseLiveLease(key globalAdmissionHolderKey, holder *globalAdmissionHolder) {
	a.detachLive(key, holder)
}

// operationContext bounds one Redis operation and cancels it when the manager
// closes, so Close never waits longer than the remaining operation budget.
func (a *GlobalAdmission) operationContext(parent context.Context) (context.Context, context.CancelFunc) {
	if parent == nil {
		parent = context.Background()
	}
	ctx, cancel := context.WithTimeout(parent, a.timeout)
	stop := context.AfterFunc(a.ctx, cancel)
	return ctx, func() {
		stop()
		cancel()
	}
}

func (a *GlobalAdmission) keyLock(uid int, ip string) chan struct{} {
	hasher := fnv.New32a()
	_, _ = hasher.Write([]byte(strconv.Itoa(uid)))
	_, _ = hasher.Write([]byte{0})
	_, _ = hasher.Write([]byte(ip))
	return a.keyLocks[hasher.Sum32()%globalAdmissionKeyStripes]
}

func (a *GlobalAdmission) upsert(ctx context.Context, uid int, ip string, limit int, token, state string) (bool, error) {
	result, err := globalAdmissionUpsertScript.Run(
		ctx,
		a.backend.client,
		[]string{a.policyIndexKey(), a.leaseKey(uid)},
		a.keyPrefix+":policy:",
		uid,
		token,
		limit,
		ip,
		state,
		int64(a.leaseTTL/time.Millisecond),
	).Result()
	if err != nil {
		return false, err
	}
	values, ok := result.([]interface{})
	if !ok || len(values) == 0 {
		return false, errors.New("unexpected global device admission response")
	}
	allowed, _ := values[0].(int64)
	return allowed == 1, nil
}

func (a *GlobalAdmission) abortPending(ctx context.Context, uid int, token string) error {
	_, err := globalAdmissionAbortScript.Run(
		ctx,
		a.backend.client,
		[]string{a.leaseKey(uid)},
		token,
	).Result()
	return err
}

func (a *GlobalAdmission) policyIndexKey() string {
	return a.keyPrefix + ":policies"
}

func (a *GlobalAdmission) policyKey(instanceID string) string {
	return a.keyPrefix + ":policy:" + instanceID
}

func (a *GlobalAdmission) leaseKey(uid int) string {
	return a.keyPrefix + ":leases:" + strconv.Itoa(uid)
}

func (a *GlobalAdmission) wake() {
	select {
	case a.wakeCh <- struct{}{}:
	default:
	}
}

func (a *GlobalAdmission) renewWorker() {
	defer a.worker.Done()
	interval := a.leaseTTL / 3
	if interval <= 0 {
		interval = time.Second
	}
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-a.closeCh:
			return
		case <-a.wakeCh:
		case <-ticker.C:
		}
		a.renewOnce()
	}
}

// renewOnce republished all known policies and every live or pending holder.
// Policies are renewed even when unchanged so an idle node with no connections
// keeps its limits registered and cannot be overridden by another instance.
//
// One round deadline (half the lease TTL) bounds the whole round, so a slow or
// hung backend cannot let renewal drift past the lease TTL before the next
// tick. Holders not reached in time are marked lost and retried next tick.
//
// A concurrent Acquire publish can race with this one, but because every tick
// republishes the complete snapshot unconditionally, Redis converges to the
// latest policy view within one leaseTTL/3 interval, well inside the lease TTL.
func (a *GlobalAdmission) renewOnce() {
	if a.closed.Load() {
		return
	}
	roundCtx, roundCancel := context.WithTimeout(a.ctx, a.leaseTTL/2)
	defer roundCancel()

	policies, known, generation := a.policySnapshot()
	if known {
		ctx, cancel := a.operationContext(roundCtx)
		err := a.registerPolicies(ctx, policies)
		cancel()
		if err != nil {
			// Registration failure keeps status degraded until this node's
			// latest policy view is actually published again.
			a.markPoliciesStale()
			a.recordBackendFailure()
		} else {
			a.mu.Lock()
			if a.policiesGen == generation {
				a.policiesDirty = false
				a.policiesStale = false
			}
			a.mu.Unlock()
			a.recordBackendSuccess()
		}
	}
	for _, snapshot := range a.holderSnapshot() {
		if a.closed.Load() {
			return
		}
		if roundCtx.Err() != nil {
			a.markHolderLost(snapshot)
			continue
		}
		a.renewHolder(roundCtx, snapshot)
	}
}

type globalAdmissionRenewal struct {
	key    globalAdmissionHolderKey
	holder *globalAdmissionHolder
	uid    int
	ip     string
	limit  int
	token  string
	live   bool
}

func (a *GlobalAdmission) policySnapshot() (map[int]int, bool, uint64) {
	a.mu.Lock()
	defer a.mu.Unlock()
	if !a.policiesKnown {
		return nil, false, a.policiesGen
	}
	copied := make(map[int]int, len(a.policies))
	for uid, limit := range a.policies {
		copied[uid] = limit
	}
	return copied, true, a.policiesGen
}

func (a *GlobalAdmission) flushPoliciesIfDirty(parent context.Context) error {
	a.mu.Lock()
	dirty := a.policiesDirty && a.policiesKnown
	a.mu.Unlock()
	if !dirty {
		return nil
	}
	return a.flushPolicies(parent)
}

func (a *GlobalAdmission) flushPolicies(parent context.Context) error {
	policies, known, generation := a.policySnapshot()
	if !known {
		return nil
	}
	ctx, cancel := a.operationContext(parent)
	err := a.registerPolicies(ctx, policies)
	cancel()
	if err != nil {
		a.markPoliciesStale()
		return err
	}
	a.mu.Lock()
	if a.policiesGen == generation {
		a.policiesDirty = false
		a.policiesStale = false
	}
	a.mu.Unlock()
	return nil
}

// markPoliciesStale records that this node's policy view may be missing from
// Redis. Holder renewals cannot clear it; only a successful publish can.
func (a *GlobalAdmission) markPoliciesStale() {
	a.mu.Lock()
	a.policiesStale = true
	a.mu.Unlock()
}

func (a *GlobalAdmission) holderSnapshot() []globalAdmissionRenewal {
	a.mu.Lock()
	defer a.mu.Unlock()
	snapshots := make([]globalAdmissionRenewal, 0, len(a.holders))
	for key, holder := range a.holders {
		if holder.pending <= 0 && holder.live <= 0 {
			continue
		}
		// The registered policy is authoritative; holder.limit only covers a
		// user with no policy entry.
		limit := holder.limit
		if a.policiesKnown {
			if policyLimit, ok := a.policies[holder.uid]; ok {
				limit = policyLimit
			}
		}
		snapshots = append(snapshots, globalAdmissionRenewal{
			key:    key,
			holder: holder,
			uid:    holder.uid,
			ip:     holder.ip,
			limit:  limit,
			token:  holder.token,
			live:   holder.live > 0,
		})
	}
	return snapshots
}

func (a *GlobalAdmission) registerPolicies(ctx context.Context, policies map[int]int) error {
	args := make([]interface{}, 0, 4+len(policies)*2)
	args = append(args,
		a.instanceID,
		int64(a.expiry/time.Millisecond),
		int64(a.expiry/time.Second),
		len(policies),
	)
	for uid, limit := range policies {
		args = append(args, uid, limit)
	}
	_, err := globalAdmissionPolicyScript.Run(
		ctx,
		a.backend.client,
		[]string{a.policyIndexKey(), a.policyKey(a.instanceID)},
		args...,
	).Result()
	return err
}

// renewHolder retries the reservation atomically. A lost token reacquires only
// if the current quota allows it; a full quota keeps the holder degraded and
// never resurrects it unconditionally.
func (a *GlobalAdmission) renewHolder(roundCtx context.Context, snapshot globalAdmissionRenewal) {
	// Do not resurrect a holder that was released between snapshot and renew.
	a.mu.Lock()
	current, ok := a.holders[snapshot.key]
	if !ok || current != snapshot.holder || (current.pending <= 0 && current.live <= 0) {
		a.mu.Unlock()
		return
	}
	a.mu.Unlock()

	state := "p"
	if snapshot.live {
		state = "l"
	}
	ctx, cancel := a.operationContext(roundCtx)
	allowed, err := a.upsert(ctx, snapshot.uid, snapshot.ip, snapshot.limit, snapshot.token, state)
	cancel()
	if err != nil {
		a.recordBackendFailure()
		a.markHolderLost(snapshot)
		return
	}
	if !allowed {
		a.recordBackendFailure()
		a.markHolderLost(snapshot)
		return
	}
	a.mu.Lock()
	if current, ok := a.holders[snapshot.key]; ok && current == snapshot.holder {
		current.reserved = true
		current.localOnly = false
		current.lost = false
		current.confirmedAt = time.Now()
	}
	a.mu.Unlock()
	a.recordBackendSuccess()
}

func (a *GlobalAdmission) markHolderLost(snapshot globalAdmissionRenewal) {
	a.mu.Lock()
	if current, ok := a.holders[snapshot.key]; ok && current == snapshot.holder {
		current.lost = true
	}
	a.mu.Unlock()
}

func (a *GlobalAdmission) requestAllowed() bool {
	a.mu.Lock()
	defer a.mu.Unlock()
	return !time.Now().Before(a.breakerUntil)
}

func (a *GlobalAdmission) recordBackendFailure() {
	a.mu.Lock()
	a.breakerFails++
	if a.breakerFails >= globalAdmissionBreakerFailures {
		a.breakerUntil = time.Now().Add(globalAdmissionBreakerCooldown)
	}
	transitioned := !a.backendFailed
	a.backendFailed = true
	a.mu.Unlock()
	if transitioned {
		// Static message only: no raw Redis error, UID, IP or credentials.
		xrayerrors.LogWarning(context.Background(), "global device admission degraded: Redis reservation unavailable")
	}
}

// recordBackendSuccess clears the degraded latch only when no live holder is
// still without a reservation, so one good operation cannot hide an outage.
func (a *GlobalAdmission) recordBackendSuccess() {
	a.mu.Lock()
	a.breakerFails = 0
	a.breakerUntil = time.Time{}
	transitioned := a.backendFailed && !a.anyHolderLostLocked() && !a.policiesStale
	if transitioned {
		a.backendFailed = false
	}
	a.mu.Unlock()
	if transitioned {
		xrayerrors.LogInfo(context.Background(), "global device admission recovered: Redis reservations confirmed")
	}
}

func (a *GlobalAdmission) anyHolderLostLocked() bool {
	for _, holder := range a.holders {
		if holder.lost || holder.localOnly {
			return true
		}
	}
	return false
}

func (a *GlobalAdmission) statusLocked() GlobalAdmissionStatus {
	switch {
	case a.backendFailed:
		return GlobalAdmissionStatus{Degraded: true, Reason: "redis admission unavailable"}
	case time.Now().Before(a.breakerUntil):
		return GlobalAdmissionStatus{Degraded: true, Reason: "redis admission circuit open"}
	case a.policiesStale:
		return GlobalAdmissionStatus{Degraded: true, Reason: "policy registration stale"}
	case a.anyHolderLostLocked():
		return GlobalAdmissionStatus{Degraded: true, Reason: "lease reservation lost"}
	default:
		return GlobalAdmissionStatus{}
	}
}

// GlobalLease is one connection's tentative or committed global hold. Methods
// are idempotent and safe on a nil receiver.
type GlobalLease struct {
	manager *GlobalAdmission
	holder  *globalAdmissionHolder
	uid     int
	ip      string
	limit   int

	mu    sync.Mutex
	state uint8 // 0 pending, 1 committed, 2 finished
}

// Commit marks the hold live. It is local-only: Acquire already performed the
// atomic reservation, so a successful local admission cannot be rejected by a
// second Redis round trip. The renewal worker promotes the reservation state
// and keeps it alive. It returns non-nil only if the manager is already closed.
func (l *GlobalLease) Commit() error {
	if l == nil || l.manager == nil {
		return nil
	}
	manager := l.manager
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.state != 0 {
		return nil
	}
	// State and counts change under both locks so a concurrent Close cannot
	// observe a committed state before the live count exists.
	manager.mu.Lock()
	defer manager.mu.Unlock()
	if manager.closed.Load() {
		return ErrGlobalAdmissionUnavailable
	}
	l.holder.pending--
	l.holder.live++
	l.state = 1
	return nil
}

// GlobalConfirmed reports whether this lease's slot is currently confirmed in
// Redis. False means the caller still gets local-only protection and must
// treat the shared quota as suspended (status is degraded).
func (l *GlobalLease) GlobalConfirmed() bool {
	if l == nil || l.manager == nil {
		return false
	}
	l.manager.mu.Lock()
	defer l.manager.mu.Unlock()
	return l.holder.reserved && !l.holder.lost && !l.holder.localOnly
}

// Abort removes a tentative reservation that was never committed. It removes
// only this holder's token and preserves every other holder, including the
// prior grace lease this instance may hold for the same IP.
func (l *GlobalLease) Abort() error {
	if l == nil || l.manager == nil {
		return nil
	}
	l.mu.Lock()
	if l.state != 0 {
		l.mu.Unlock()
		return nil
	}
	l.state = 2
	uid, token, shouldAbort := l.manager.detachPending(globalAdmissionHolderKey{uid: l.uid, ip: l.ip}, l.holder)
	l.mu.Unlock()

	if !shouldAbort {
		return nil
	}
	return l.manager.abortToken(uid, token)
}

// Close stops this local hold. The normal last close never deletes Redis state;
// the lease expires by TTL. Close on an uncommitted lease behaves like Abort.
func (l *GlobalLease) Close() error {
	if l == nil || l.manager == nil {
		return nil
	}
	manager := l.manager
	key := globalAdmissionHolderKey{uid: l.uid, ip: l.ip}
	l.mu.Lock()
	switch l.state {
	case 2:
		l.mu.Unlock()
		return nil
	case 1:
		manager.detachLive(key, l.holder)
		l.state = 2
		l.mu.Unlock()
		return nil
	default:
		l.state = 2
		uid, token, shouldAbort := manager.detachPending(key, l.holder)
		l.mu.Unlock()
		if !shouldAbort {
			return nil
		}
		return manager.abortToken(uid, token)
	}
}

// Upsert Lua contract: KEYS[1] policy index, KEYS[2] per-UID lease zset.
// ARGV: policy key prefix, uid, token, caller limit, canonical IP, desired
// state (p/l), lease TTL ms.
//
// It prunes expired policy and lease entries using Redis TIME, deduplicates
// normalized IPs, and enforces the positive minimum limit across live instance
// registrations only for a token that is not already present. Existing tokens
// are grandfathered so lowering a limit does not evict live addresses.
const globalAdmissionUpsertLua = `
local index = KEYS[1]
local leases = KEYS[2]
local t = redis.call('TIME')
local now = tonumber(t[1]) * 1000 + math.floor(tonumber(t[2]) / 1000)
redis.call('ZREMRANGEBYSCORE', index, '-inf', now)
redis.call('ZREMRANGEBYSCORE', leases, '-inf', now)

local members = redis.call('ZRANGE', leases, 0, -1)
local ips = {}
local present = false
for _, member in ipairs(members) do
  local state, token, ip = string.match(member, '^(%a):([^:]+):(.*)$')
  if token then
    ips[ip] = true
    if token == ARGV[3] then
      present = true
    end
  end
end

if not present then
  local minimum = nil
  local instances = redis.call('ZRANGEBYSCORE', index, now, '+inf')
  for _, instance in ipairs(instances) do
    local value = redis.call('HGET', ARGV[1] .. instance, ARGV[2])
    if value then
      local parsed = tonumber(value)
      if parsed and parsed > 0 and (minimum == nil or parsed < minimum) then
        minimum = parsed
      end
    end
  end
  local callerLimit = tonumber(ARGV[4])
  if callerLimit and callerLimit > 0 and (minimum == nil or callerLimit < minimum) then
    minimum = callerLimit
  end
  local count = 0
  for _ in pairs(ips) do
    count = count + 1
  end
  if not ips[ARGV[5]] and minimum and count >= minimum then
    return {0, 'quota', minimum, count}
  end
end

for _, member in ipairs(members) do
  local state, token, ip = string.match(member, '^(%a):([^:]+):(.*)$')
  if token == ARGV[3] then
    redis.call('ZREM', leases, member)
  end
end
local ttl = tonumber(ARGV[7])
redis.call('ZADD', leases, now + ttl, ARGV[6] .. ':' .. ARGV[3] .. ':' .. ARGV[5])
-- Bound the lease key itself by its furthest live score so a crashed manager
-- cannot leave dead members in Redis forever. Never shorten a longer entry.
local top = redis.call('ZRANGE', leases, -1, -1, 'WITHSCORES')
if top[2] then
  local remaining = tonumber(top[2]) - now
  if remaining > 0 then
    redis.call('PEXPIRE', leases, remaining)
  end
end
return {1, 'ok', 0, 0}
`

// Policy Lua contract: KEYS[1] index, KEYS[2] this instance's policy hash.
// ARGV: instance, TTL ms, TTL seconds, pair count, then uid/limit pairs.
// Registering replaces the hash atomically; an empty view unregisters. Zero
// limits are stored so they cannot override another instance's positive limit.
const globalAdmissionPolicyLua = `
local index = KEYS[1]
local policyKey = KEYS[2]
local count = tonumber(ARGV[4])
local t = redis.call('TIME')
local now = tonumber(t[1]) * 1000 + math.floor(tonumber(t[2]) / 1000)
redis.call('ZREMRANGEBYSCORE', index, '-inf', now)
redis.call('DEL', policyKey)
if count > 0 then
  for i = 1, count do
    redis.call('HSET', policyKey, ARGV[4 + i * 2 - 1], ARGV[4 + i * 2])
  end
  redis.call('EXPIRE', policyKey, tonumber(ARGV[3]))
  redis.call('ZADD', index, now + tonumber(ARGV[2]), ARGV[1])
else
  redis.call('ZREM', index, ARGV[1])
end
-- Bound the policy index itself when this instance is the last live entry.
local top = redis.call('ZRANGE', index, -1, -1, 'WITHSCORES')
if top[2] then
  local remaining = tonumber(top[2]) - now
  if remaining > 0 then
    redis.call('PEXPIRE', index, remaining)
  end
else
  redis.call('DEL', index)
end
return 1
`

// Abort Lua contract: remove only members whose token matches exactly. Other
// members, including a committed grace lease for the same instance/IP, stay.
const globalAdmissionAbortLua = `
local leases = KEYS[1]
local members = redis.call('ZRANGE', leases, 0, -1)
for _, member in ipairs(members) do
  local state, token, ip = string.match(member, '^(%a):([^:]+):(.*)$')
  if token == ARGV[1] then
    redis.call('ZREM', leases, member)
  end
end
return 1
`

var (
	globalAdmissionUpsertScript = redis.NewScript(globalAdmissionUpsertLua)
	globalAdmissionPolicyScript = redis.NewScript(globalAdmissionPolicyLua)
	globalAdmissionAbortScript  = redis.NewScript(globalAdmissionAbortLua)
)

// globalAdmissionBackendKey stays in memory alongside the Redis client's own
// credentials. It is never logged or used as a Redis key; structured equality
// avoids both password hashing and delimiter collisions between options.
type globalAdmissionBackendKey struct {
	network  string
	address  string
	username string
	password string
	database int
	timeout  time.Duration
}

type globalAdmissionBackend struct {
	key    globalAdmissionBackendKey
	client *redis.Client
	refs   int
}

var globalAdmissionBackendRegistry = struct {
	mu       sync.Mutex
	backends map[globalAdmissionBackendKey]*globalAdmissionBackend
}{backends: make(map[globalAdmissionBackendKey]*globalAdmissionBackend)}

// acquireGlobalAdmissionBackend returns a reference-counted client shared by
// all managers with the same connection configuration. Creating a client does
// not perform network I/O, so no connection is made while the registry lock is
// held. Credentials never appear in logs or Redis keys.
func acquireGlobalAdmissionBackend(config *GlobalDeviceLimitConfig, timeout time.Duration) *globalAdmissionBackend {
	key := globalAdmissionBackendKey{
		network:  config.RedisNetwork,
		address:  config.RedisAddr,
		username: config.RedisUsername,
		password: config.RedisPassword,
		database: config.RedisDB,
		timeout:  timeout,
	}
	globalAdmissionBackendRegistry.mu.Lock()
	defer globalAdmissionBackendRegistry.mu.Unlock()
	if backend, ok := globalAdmissionBackendRegistry.backends[key]; ok {
		backend.refs++
		return backend
	}
	backend := &globalAdmissionBackend{
		key: key,
		client: redis.NewClient(&redis.Options{
			Network:               config.RedisNetwork,
			Addr:                  config.RedisAddr,
			Username:              config.RedisUsername,
			Password:              config.RedisPassword,
			DB:                    config.RedisDB,
			DialTimeout:           timeout,
			ReadTimeout:           timeout,
			WriteTimeout:          timeout,
			PoolTimeout:           timeout + time.Second,
			ContextTimeoutEnabled: true,
			MaxRetries:            -1,
		}),
		refs: 1,
	}
	globalAdmissionBackendRegistry.backends[key] = backend
	return backend
}

func (b *globalAdmissionBackend) release() {
	if b == nil {
		return
	}
	globalAdmissionBackendRegistry.mu.Lock()
	b.refs--
	last := b.refs <= 0
	if last {
		delete(globalAdmissionBackendRegistry.backends, b.key)
	}
	globalAdmissionBackendRegistry.mu.Unlock()
	if last {
		_ = b.client.Close()
	}
}
