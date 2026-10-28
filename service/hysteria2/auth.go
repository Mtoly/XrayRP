package hysteria2

import (
	"context"
	"errors"
	"net"
	"time"

	log "github.com/sirupsen/logrus"

	commonlimiter "github.com/Mtoly/XrayRP/common/limiter"
)

// hyAuthenticator implements server.Authenticator and performs user lookup
// and local device limit enforcement based on SSPanel's UUID.
//
// When Redis global admission is enabled, the returned id is an opaque
// per-connection session identifier rather than the credential. The core
// reuses that id for every later callback, so session state owns the lease and
// same-credential connections from one IP stay distinguishable.
type hyAuthenticator struct {
	svc      *Hysteria2Service
	authGate *runtimeAuthGate
}

func (a *hyAuthenticator) logger() *log.Entry {
	if a.svc != nil && a.svc.logger != nil {
		return a.svc.logger
	}
	return log.NewEntry(log.StandardLogger())
}

func (a *hyAuthenticator) Authenticate(addr net.Addr, auth string, tx uint64) (bool, string) {
	logger := a.logger()
	host := addr.String()
	if h, _, err := net.SplitHostPort(addr.String()); err == nil {
		host = h
	}

	if auth == "" {
		logger.WithField("remote", host).Warn("Hysteria2 auth failed: empty auth string")
		return false, ""
	}
	if !a.authGate.wait() {
		logger.WithField("remote", host).Warn("Hysteria2 auth rejected before runtime publication")
		return false, ""
	}

	if a.svc == nil {
		return false, ""
	}

	a.svc.mu.RLock()
	_, known := a.svc.users[auth]
	admission := a.svc.globalAdmission
	a.svc.mu.RUnlock()
	if !known {
		logger.WithFields(log.Fields{
			"remote":   host,
			"auth_len": len(auth),
		}).Warn("Hysteria2 auth failed: unknown credential")
		return false, ""
	}
	if admission == nil {
		return a.authenticateLocal(host, auth, logger)
	}
	return a.authenticateGlobal(host, auth, admission, logger)
}

// authenticateLocal keeps the pre-Redis behavior: authenticate, enforce the
// local device limit, and return the credential itself as the connection id.
func (a *hyAuthenticator) authenticateLocal(host, auth string, logger *log.Entry) (bool, string) {
	a.svc.mu.Lock()
	defer a.svc.mu.Unlock()

	user, ok := a.svc.users[auth]
	if !ok {
		logger.WithFields(log.Fields{
			"remote":   host,
			"auth_len": len(auth),
		}).Warn("Hysteria2 auth failed: unknown credential")
		return false, ""
	}

	now := time.Now()
	a.svc.cleanupStaleUserIPsLocked(auth, now)

	ipSet := a.svc.trackedIPsLocked(auth)
	if _, exists := ipSet[host]; !exists {
		// New device
		if user.DeviceLimit > 0 && len(ipSet) >= user.DeviceLimit {
			logger.WithFields(log.Fields{
				"uid":         user.UID,
				"deviceLimit": user.DeviceLimit,
				"remote":      host,
			}).Warn("Hysteria2 user exceeded device limit")
			return false, ""
		}
		ipSet[host] = struct{}{}
	}

	a.svc.touchIPLocked(auth, host, now)

	return true, auth
}

// authenticateGlobal reserves the source IP in Redis and records a session that
// owns the lease. The Redis round trip runs without service.mu; the policy is
// revalidated afterwards so a reservation cannot commit against stale users.
func (a *hyAuthenticator) authenticateGlobal(host, auth string, admission globalAdmission, logger *log.Entry) (bool, string) {
	a.svc.mu.RLock()
	user, known := a.svc.users[auth]
	generation := a.svc.userGeneration
	a.svc.mu.RUnlock()
	if !known {
		logger.WithFields(log.Fields{
			"remote":   host,
			"auth_len": len(auth),
		}).Warn("Hysteria2 auth failed: unknown credential")
		return false, ""
	}

	lease, err := admission.Acquire(context.Background(), user.UID, host, user.DeviceLimit)
	if err != nil {
		fields := log.Fields{"uid": user.UID, "remote": host}
		switch {
		case errors.Is(err, commonlimiter.ErrGlobalAdmissionQuota):
			logger.WithFields(fields).Warn("Hysteria2 global device quota reached")
		case errors.Is(err, commonlimiter.ErrGlobalAdmissionUnavailable):
			logger.WithFields(fields).Warn("Hysteria2 global device admission unavailable; rejecting new connection")
		default:
			logger.WithError(err).WithFields(fields).Warn("Hysteria2 global device admission rejected connection")
		}
		return false, ""
	}

	now := time.Now()
	a.svc.mu.Lock()
	current, stillKnown := a.svc.users[auth]
	if !stillKnown || current != user || a.svc.globalAdmission != admission || a.svc.userGeneration != generation {
		a.svc.mu.Unlock()
		abortGlobalLease(lease)
		logger.WithField("remote", host).Warn("Hysteria2 auth rejected: user policy changed during global admission")
		return false, ""
	}

	a.svc.cleanupStaleUserIPsLocked(auth, now)
	ipSet := a.svc.trackedIPsLocked(auth)
	// FailMode=open returns no lease when Redis cannot be verified. Keep the
	// pre-Redis local limit for that degraded window so admission stays bounded
	// on this node; there is no reservation to abort.
	if lease == nil {
		if _, exists := ipSet[host]; !exists && current.DeviceLimit > 0 && len(ipSet) >= current.DeviceLimit {
			a.svc.mu.Unlock()
			logger.WithFields(log.Fields{
				"uid":         current.UID,
				"deviceLimit": current.DeviceLimit,
				"remote":      host,
			}).Warn("Hysteria2 user exceeded local device limit while global admission was unavailable")
			return false, ""
		}
	}

	sessionID, sessionErr := newSessionID()
	if sessionErr != nil {
		a.svc.mu.Unlock()
		abortGlobalLease(lease)
		logger.WithError(sessionErr).WithField("remote", host).Warn("Hysteria2 auth failed: unable to allocate session id")
		return false, ""
	}

	ipSet[host] = struct{}{}
	a.svc.touchIPLocked(auth, host, now)
	if a.svc.sessions == nil {
		a.svc.sessions = make(map[string]*hySession)
	}
	a.svc.sessions[sessionID] = &hySession{
		credential: auth,
		ip:         host,
		lease:      lease,
	}
	a.svc.mu.Unlock()

	if lease != nil {
		if commitErr := lease.Commit(); commitErr != nil {
			a.svc.endSession(sessionID)
			fields := log.Fields{"uid": current.UID, "remote": host}
			logger.WithError(commitErr).WithFields(fields).Warn("Hysteria2 global device admission commit failed; rejecting connection")
			return false, ""
		}
	}

	return true, sessionID
}
