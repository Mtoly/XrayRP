package hysteria2

import (
	"net"
	"time"

	log "github.com/sirupsen/logrus"
)

// hyEventLogger implements server.EventLogger and prints useful
// diagnostics so that connection and handshake issues can be
// investigated from XrayR's log output.
type hyEventLogger struct {
	svc *Hysteria2Service
}

func (l *hyEventLogger) logger() *log.Entry {
	if l == nil || l.svc == nil || l.svc.logger == nil {
		return log.NewEntry(log.StandardLogger())
	}
	return l.svc.logger
}

// userFields resolves the given Hysteria2 connection ID to a stable,
// non-sensitive user identity such as UID / email for logging purposes. The ID
// is either a credential (local mode) or an opaque session id (global mode).
func (l *hyEventLogger) userFields(id string) log.Fields {
	fields := log.Fields{}
	if l == nil || l.svc == nil {
		return fields
	}

	user, _, ok := l.svc.lookupUser(id)
	if ok {
		fields["uid"] = user.UID
	}
	return fields
}

func (l *hyEventLogger) auditRequest(addr net.Addr, id, reqAddr string) {
	if l == nil || l.svc == nil || l.svc.rules == nil {
		return
	}

	host := addr.String()
	if h, _, err := net.SplitHostPort(host); err == nil {
		host = h
	}

	user, _, ok := l.svc.lookupUser(id)
	if !ok || reqAddr == "" {
		return
	}

	if l.svc.rules.DetectUID(l.svc.appliedTag(), reqAddr, user.UID, host) {
		// Mark this connection ID as blocked. The TrafficLogger will see this
		// flag and return false on the next traffic callback, which instructs
		// the Hysteria2 core to disconnect the client immediately.
		l.svc.mu.Lock()
		if l.svc.blockedIDs == nil {
			l.svc.blockedIDs = make(map[string]bool)
		}
		l.svc.blockedIDs[id] = true
		l.svc.mu.Unlock()

		l.logger().WithFields(log.Fields{
			"remote":  host,
			"reqAddr": reqAddr,
			"uid":     user.UID,
		}).Warn("Hysteria2 audit rule hit, scheduling disconnect")
	}
}

func (l *hyEventLogger) Connect(addr net.Addr, id string, tx uint64) {
	fields := log.Fields{
		"remote": addr.String(),
	}
	for k, v := range l.userFields(id) {
		fields[k] = v
	}
	l.logger().WithFields(fields).Info("Hysteria2 client connected")
}

func (l *hyEventLogger) Disconnect(addr net.Addr, id string, err error) {
	remote := ""
	host := ""
	if addr != nil {
		remote = addr.String()
		host = remote
		if h, _, splitErr := net.SplitHostPort(remote); splitErr == nil {
			host = h
		}
	}

	fields := log.Fields{
		"remote": remote,
	}
	for k, v := range l.userFields(id) {
		fields[k] = v
	}

	// Remove this connection's online IP tracking. In global mode a session
	// owns a lease and the IP stays online while another session still uses it;
	// closing the lease only stops renewal and never deletes shared Redis state.
	if l != nil && l.svc != nil && id != "" {
		l.svc.mu.RLock()
		_, isSession := l.svc.sessions[id]
		l.svc.mu.RUnlock()
		if isSession {
			l.svc.endSession(id)
		} else if host != "" {
			l.svc.mu.Lock()
			l.svc.forgetIPLocked(id, host)
			l.svc.mu.Unlock()
		}
	}

	if err != nil {
		fields["err"] = err
		l.logger().WithFields(fields).Warn("Hysteria2 client disconnected with error")
	} else {
		l.logger().WithFields(fields).Info("Hysteria2 client disconnected")
	}
}

func (l *hyEventLogger) TCPRequest(addr net.Addr, id, reqAddr string) {
	remote := ""
	host := ""
	if addr != nil {
		remote = addr.String()
		host = remote
		if h, _, err := net.SplitHostPort(remote); err == nil {
			host = h
		}
	}

	var (
		user       userRecord
		credential string
		ok         bool
		nodeTag    string
	)

	if l != nil && l.svc != nil {
		nodeTag = l.svc.appliedTag()
		user, credential, ok = l.svc.lookupUser(id)

		// Update last active time and re-add the IP to onlineIPs. This keeps an
		// active connection tracked even after collectUsage() clears the maps,
		// similar to how traditional Xray protocols call GetUserBucket on every
		// traffic event.
		if ok && host != "" && credential != "" {
			l.svc.mu.Lock()
			l.svc.trackedIPsLocked(credential)[host] = struct{}{}
			l.svc.touchIPLocked(credential, host, time.Now())
			l.svc.mu.Unlock()
		}
	}

	if ok {
		l.logger().Infof("from %s accepted tcp:%s [%s] uid: %d",
			remote, reqAddr, nodeTag, user.UID)
	} else {
		l.logger().Infof("from %s accepted tcp:%s [%s]", remote, reqAddr, nodeTag)
	}

	l.auditRequest(addr, id, reqAddr)
}

func (l *hyEventLogger) TCPError(addr net.Addr, id, reqAddr string, err error) {
	fields := log.Fields{
		"remote":  addr.String(),
		"reqAddr": reqAddr,
	}
	for k, v := range l.userFields(id) {
		fields[k] = v
	}
	if err != nil {
		fields["err"] = err
		l.logger().WithFields(fields).Warn("Hysteria2 TCP error")
	} else {
		l.logger().WithFields(fields).Debug("Hysteria2 TCP error")
	}
}

func (l *hyEventLogger) UDPRequest(addr net.Addr, id string, sessionID uint32, reqAddr string) {
	remote := ""
	host := ""
	if addr != nil {
		remote = addr.String()
		host = remote
		if h, _, err := net.SplitHostPort(remote); err == nil {
			host = h
		}
	}

	var (
		user       userRecord
		credential string
		ok         bool
		nodeTag    string
	)

	if l != nil && l.svc != nil {
		nodeTag = l.svc.appliedTag()
		user, credential, ok = l.svc.lookupUser(id)

		if ok && host != "" && credential != "" {
			l.svc.mu.Lock()
			l.svc.trackedIPsLocked(credential)[host] = struct{}{}
			l.svc.touchIPLocked(credential, host, time.Now())
			l.svc.mu.Unlock()
		}
	}

	if ok {
		l.logger().Infof("from %s accepted udp:%s [%s] uid: %d",
			remote, reqAddr, nodeTag, user.UID)
	} else {
		l.logger().Infof("from %s accepted udp:%s [%s]", remote, reqAddr, nodeTag)
	}

	l.auditRequest(addr, id, reqAddr)
}

func (l *hyEventLogger) UDPError(addr net.Addr, id string, sessionID uint32, err error) {
	fields := log.Fields{
		"remote":    addr.String(),
		"sessionID": sessionID,
	}
	for k, v := range l.userFields(id) {
		fields[k] = v
	}
	if err != nil {
		fields["err"] = err
		l.logger().WithFields(fields).Warn("Hysteria2 UDP error")
	} else {
		l.logger().WithFields(fields).Debug("Hysteria2 UDP error")
	}
}
