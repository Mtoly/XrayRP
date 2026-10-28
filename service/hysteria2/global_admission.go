package hysteria2

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"strings"

	"github.com/Mtoly/XrayRP/api"
	commonlimiter "github.com/Mtoly/XrayRP/common/limiter"
)

// globalAdmission is the service-facing slice of limiter.GlobalAdmission. The
// concrete manager owns Redis state and renewal; this package only acquires one
// lease per authenticated connection.
type globalAdmission interface {
	Acquire(ctx context.Context, uid int, ip string, limit int) (globalLease, error)
	SetUsers(map[int]int)
	Degraded() bool
	Close() error
}

// globalLease is owned by exactly one connection session. Commit turns the
// tentative reservation into a counted one; Abort drops it without counting;
// Close stops renewal after the connection closes and never deletes shared
// state. Close on an uncommitted lease behaves like Abort.
type globalLease interface {
	Commit() error
	Abort() error
	Close() error
}

type limiterGlobalAdmission struct {
	admission *commonlimiter.GlobalAdmission
}

func (a limiterGlobalAdmission) Acquire(ctx context.Context, uid int, ip string, limit int) (globalLease, error) {
	lease, err := a.admission.Acquire(ctx, uid, ip, limit)
	if err != nil || lease == nil {
		return nil, err
	}
	return limiterGlobalLease{lease: lease}, nil
}

func (a limiterGlobalAdmission) SetUsers(limits map[int]int) {
	a.admission.SetUsers(limits)
}

func (a limiterGlobalAdmission) Degraded() bool {
	return a.admission.StatusSnapshot().Degraded
}

func (a limiterGlobalAdmission) Close() error {
	return a.admission.Close()
}

type limiterGlobalLease struct {
	lease *commonlimiter.GlobalLease
}

func (l limiterGlobalLease) Commit() error { return l.lease.Commit() }

func (l limiterGlobalLease) Abort() error { return l.lease.Abort() }

func (l limiterGlobalLease) Close() error { return l.lease.Close() }

func abortGlobalLease(lease globalLease) {
	if lease != nil {
		_ = lease.Abort()
	}
}

func closeGlobalLease(lease globalLease) error {
	if lease == nil {
		return nil
	}
	return lease.Close()
}

// userDeviceLimits collapses credential aliases (UUID/passwd) onto the UID
// that Redis uses as the global identity.
func userDeviceLimits(users map[string]userRecord) map[int]int {
	limits := make(map[int]int, len(users))
	for _, user := range users {
		limits[user.UID] = user.DeviceLimit
	}
	return limits
}

// buildGlobalAdmission creates the shared admission manager when Redis global
// device limiting is enabled. It returns a nil manager for the local-only
// configuration so the existing authentication path stays untouched.
func (h *Hysteria2Service) buildGlobalAdmission(clientInfo api.ClientInfo) (globalAdmission, error) {
	if h.config == nil || h.config.GlobalDeviceLimitConfig == nil || !h.config.GlobalDeviceLimitConfig.Enable {
		return nil, nil
	}
	config := h.config.GlobalDeviceLimitConfig
	panelType := config.PanelType
	if strings.TrimSpace(panelType) == "" {
		panelType = h.config.GlobalPanelType
	}
	apiHost := config.APIHost
	if strings.TrimSpace(apiHost) == "" {
		apiHost = clientInfo.APIHost
	}
	if strings.TrimSpace(config.Namespace) == "" && (strings.TrimSpace(panelType) == "" || strings.TrimSpace(apiHost) == "") {
		return nil, errors.New("global device limit requires panel type and API host, or an explicit Redis namespace")
	}
	admission, err := commonlimiter.NewGlobalAdmission(config, panelType, apiHost)
	if err != nil {
		return nil, err
	}
	if admission == nil {
		return nil, nil
	}
	return limiterGlobalAdmission{admission: admission}, nil
}

// globalDeviceDegraded reports whether shared device enforcement is currently
// unable to guarantee its reservation state.
func (h *Hysteria2Service) globalDeviceDegraded() bool {
	if h == nil {
		return false
	}
	h.mu.RLock()
	admission := h.globalAdmission
	h.mu.RUnlock()
	return admission != nil && admission.Degraded()
}

// newSessionID creates an opaque identifier for one authenticated Hysteria2
// session. It is returned to the core instead of the credential so that
// multiple connections sharing one auth string and source IP remain distinct.
func newSessionID() (string, error) {
	buffer := make([]byte, 16)
	if _, err := rand.Read(buffer); err != nil {
		return "", err
	}
	return "hy2-" + hex.EncodeToString(buffer), nil
}
