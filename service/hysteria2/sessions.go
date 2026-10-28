package hysteria2

import "time"

// hySession ties one authenticated Hysteria2 connection to the credential it
// used and the global lease it owns. The core treats the returned opaque id as
// the connection id for every later callback, so two connections that share a
// credential and source IP still own independent leases.
type hySession struct {
	credential string
	ip         string
	lease      globalLease
}

// userForIDLocked resolves a core connection id to its user record and
// credential. h.mu must be held.
func (h *Hysteria2Service) userForIDLocked(id string) (userRecord, string, bool) {
	if h == nil {
		return userRecord{}, id, false
	}
	if session, exists := h.sessions[id]; exists && session != nil {
		user, ok := h.users[session.credential]
		return user, session.credential, ok
	}
	user, ok := h.users[id]
	return user, id, ok
}

// lookupUser resolves a core connection id to its user record and credential.
func (h *Hysteria2Service) lookupUser(id string) (userRecord, string, bool) {
	if h == nil {
		return userRecord{}, id, false
	}
	h.mu.RLock()
	defer h.mu.RUnlock()
	return h.userForIDLocked(id)
}

// trackedIPsLocked returns the online-IP set for a credential, creating it on
// first use. h.mu must be held for writing.
func (h *Hysteria2Service) trackedIPsLocked(credential string) map[string]struct{} {
	if h.onlineIPs == nil {
		h.onlineIPs = make(map[string]map[string]struct{})
	}
	ipSet, ok := h.onlineIPs[credential]
	if !ok {
		ipSet = make(map[string]struct{})
		h.onlineIPs[credential] = ipSet
	}
	return ipSet
}

// touchIPLocked marks an IP as active for a credential. h.mu must be held for
// writing.
func (h *Hysteria2Service) touchIPLocked(credential, host string, now time.Time) {
	if h.ipLastActive == nil {
		h.ipLastActive = make(map[string]map[string]time.Time)
	}
	activeMap, ok := h.ipLastActive[credential]
	if !ok {
		activeMap = make(map[string]time.Time)
		h.ipLastActive[credential] = activeMap
	}
	activeMap[host] = now
}

// sessionHoldsIPLocked reports whether another live session still uses the same
// credential and source IP. h.mu must be held.
func (h *Hysteria2Service) sessionHoldsIPLocked(credential, host string) bool {
	for _, session := range h.sessions {
		if session != nil && session.credential == credential && session.ip == host {
			return true
		}
	}
	return false
}

// forgetIPLocked drops one credential/IP online record. It is a no-op when the
// record is absent. h.mu must be held for writing.
func (h *Hysteria2Service) forgetIPLocked(credential, host string) {
	if ipSet, ok := h.onlineIPs[credential]; ok {
		delete(ipSet, host)
		if len(ipSet) == 0 {
			delete(h.onlineIPs, credential)
		}
	}
	if activeMap, ok := h.ipLastActive[credential]; ok {
		delete(activeMap, host)
		if len(activeMap) == 0 {
			delete(h.ipLastActive, credential)
		}
	}
}

// retireSessionLease stops renewal for one session without dropping its
// identity record. The core reports online=false immediately before
// Disconnect; stopping renewal there keeps the disconnect log able to resolve
// the UID while still releasing the lease promptly.
func (h *Hysteria2Service) retireSessionLease(sessionID string) {
	if h == nil {
		return
	}
	h.mu.Lock()
	session := h.sessions[sessionID]
	if session == nil || session.lease == nil {
		h.mu.Unlock()
		return
	}
	lease := session.lease
	session.lease = nil
	h.mu.Unlock()
	_ = closeGlobalLease(lease)
}

// endSession removes a session-owned connection, keeps the online IP while
// another live session still uses it, and stops lease renewal outside h.mu.
func (h *Hysteria2Service) endSession(sessionID string) {
	if h == nil {
		return
	}
	h.mu.Lock()
	session := h.sessions[sessionID]
	if session == nil {
		h.mu.Unlock()
		return
	}
	delete(h.sessions, sessionID)
	delete(h.blockedIDs, sessionID)
	lease := session.lease
	session.lease = nil
	if !h.sessionHoldsIPLocked(session.credential, session.ip) {
		h.forgetIPLocked(session.credential, session.ip)
	}
	h.mu.Unlock()
	_ = closeGlobalLease(lease)
}

// takeSessions detaches the session map and returns every owned lease so the
// caller can close renewal after the runtime has fully stopped.
func (h *Hysteria2Service) takeSessions() ([]globalLease, globalAdmission) {
	h.mu.Lock()
	defer h.mu.Unlock()
	leases := make([]globalLease, 0, len(h.sessions))
	for _, session := range h.sessions {
		if session != nil && session.lease != nil {
			leases = append(leases, session.lease)
		}
	}
	admission := h.globalAdmission
	h.sessions = make(map[string]*hySession)
	h.globalAdmission = nil
	return leases, admission
}

// liveSessionIPsLocked returns the online IPs of committed sessions, resolved
// against the current user policy. Redis admission keeps a lease for idle
// connections, which is the authoritative presence signal in that mode. h.mu
// must be held.
func (h *Hysteria2Service) liveSessionIPsLocked() map[int][]string {
	if len(h.sessions) == 0 {
		return nil
	}
	seen := make(map[int]map[string]struct{}, len(h.sessions))
	for _, session := range h.sessions {
		if session == nil || session.ip == "" {
			continue
		}
		user, ok := h.users[session.credential]
		if !ok {
			continue
		}
		ips, ok := seen[user.UID]
		if !ok {
			ips = make(map[string]struct{})
			seen[user.UID] = ips
		}
		ips[session.ip] = struct{}{}
	}
	live := make(map[int][]string, len(seen))
	for uid, ips := range seen {
		for ip := range ips {
			live[uid] = append(live[uid], ip)
		}
	}
	return live
}
