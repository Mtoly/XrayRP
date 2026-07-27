package tuic

import (
	"context"
	"errors"
	"io"
	"net"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing/common/buf"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
	log "github.com/sirupsen/logrus"
	"golang.org/x/time/rate"

	commonlimiter "github.com/Mtoly/XrayRP/common/limiter"
)

type connCounter struct {
	net.Conn
	svc     *TuicService
	user    string
	blocked bool
	ctx     context.Context
	limiter *rate.Limiter
}

func (c *connCounter) Read(p []byte) (int, error) {
	if c.blocked {
		return 0, io.EOF
	}
	n, readErr := c.Conn.Read(p)
	if n > 0 {
		if c.svc != nil {
			c.svc.addTraffic(c.user, int64(n), 0)
			// Re-add IP to onlineIPs on every traffic event
			// This ensures active connections are tracked even after collectUsage() clears the maps
			c.svc.updateOnlineIP(c.user, c.Conn.RemoteAddr())
		}
		if c.limiter != nil {
			if limitErr := commonlimiter.WaitN(admissionContext(c.ctx), c.limiter, uint64(n)); limitErr != nil {
				return 0, errors.Join(limitErr, readErr, c.Close())
			}
		}
	}
	return n, readErr
}

func (c *connCounter) Write(p []byte) (int, error) {
	if c.blocked {
		return 0, io.EOF
	}
	if len(p) > 0 && c.limiter != nil {
		if err := commonlimiter.WaitN(admissionContext(c.ctx), c.limiter, uint64(len(p))); err != nil {
			return 0, errors.Join(err, c.Close())
		}
	}
	n, writeErr := c.Conn.Write(p)
	if n > 0 {
		if c.svc != nil {
			c.svc.addTraffic(c.user, 0, int64(n))
			// Re-add IP to onlineIPs on every traffic event
			// This ensures active connections are tracked even after collectUsage() clears the maps
			c.svc.updateOnlineIP(c.user, c.Conn.RemoteAddr())
		}
	}
	return n, writeErr
}

func (c *connCounter) Close() error {
	if c.svc != nil && c.user != "" {
		remote := ""
		if addr := c.Conn.RemoteAddr(); addr != nil {
			remote = addr.String()
		}
		host := remote
		if host != "" {
			if h, _, err := net.SplitHostPort(host); err == nil {
				host = h
			}
		}

		c.svc.mu.Lock()
		if ips, ok := c.svc.onlineIPs[c.user]; ok && host != "" {
			delete(ips, host)
			if len(ips) == 0 {
				delete(c.svc.onlineIPs, c.user)
			}
		}
		// Also remove from ipLastActive
		if activeMap, ok := c.svc.ipLastActive[c.user]; ok && host != "" {
			delete(activeMap, host)
			if len(activeMap) == 0 {
				delete(c.svc.ipLastActive, c.user)
			}
		}
		c.svc.mu.Unlock()
	}
	return c.Conn.Close()
}

type packetConnCounter struct {
	N.PacketConn
	svc     *TuicService
	user    string
	host    string
	blocked bool
	ctx     context.Context
	limiter *rate.Limiter
}

func (c *packetConnCounter) ReadPacket(buffer *buf.Buffer) (M.Socksaddr, error) {
	if c.blocked {
		return M.Socksaddr{}, io.EOF
	}
	destination, readErr := c.PacketConn.ReadPacket(buffer)
	if buffer.Len() == 0 || c.limiter == nil {
		return destination, readErr
	}
	if limitErr := commonlimiter.WaitN(admissionContext(c.ctx), c.limiter, uint64(buffer.Len())); limitErr != nil {
		buffer.Reset()
		return M.Socksaddr{}, errors.Join(limitErr, readErr, c.Close())
	}
	return destination, readErr
}

func (c *packetConnCounter) WritePacket(buffer *buf.Buffer, destination M.Socksaddr) error {
	if c.blocked {
		return io.EOF
	}
	if buffer.Len() > 0 && c.limiter != nil {
		if err := commonlimiter.WaitN(admissionContext(c.ctx), c.limiter, uint64(buffer.Len())); err != nil {
			return errors.Join(err, c.Close())
		}
	}
	return c.PacketConn.WritePacket(buffer, destination)
}

func (c *packetConnCounter) Close() error {
	if c.svc != nil && c.user != "" && c.host != "" {
		c.svc.mu.Lock()
		if ips, ok := c.svc.onlineIPs[c.user]; ok {
			delete(ips, c.host)
			if len(ips) == 0 {
				delete(c.svc.onlineIPs, c.user)
			}
		}
		// Also remove from ipLastActive
		if activeMap, ok := c.svc.ipLastActive[c.user]; ok {
			delete(activeMap, c.host)
			if len(activeMap) == 0 {
				delete(c.svc.ipLastActive, c.user)
			}
		}
		c.svc.mu.Unlock()
	}
	return c.PacketConn.Close()
}

type tuicTracker struct {
	svc *TuicService
}

var _ adapter.ConnectionTracker = (*tuicTracker)(nil)

func (t *tuicTracker) ModeList() []string { return nil }

func (t *tuicTracker) RoutedConnection(ctx context.Context, conn net.Conn, m adapter.InboundContext, _ adapter.Rule, _ adapter.Outbound) net.Conn {
	if t.svc == nil {
		return conn
	}
	if m.User == "" {
		return conn
	}

	remote := ""
	if m.Source.Addr.IsValid() {
		remote = m.Source.Addr.String()
	}

	var (
		userRec userRecord
		ok      bool
	)
	t.svc.mu.RLock()
	userRec, ok = t.svc.users[m.User]
	t.svc.mu.RUnlock()

	dest := m.Domain
	if dest == "" {
		dest = m.Destination.String()
	}

	fields := log.Fields{
		"remote": remote,
	}
	if dest != "" {
		fields["dest"] = dest
	}
	if ok {
		fields["uid"] = userRec.UID
	}

	// Access log: only expose UID, not email.
	nodeTag := t.svc.appliedTag()
	if ok {
		t.svc.logger.Infof("from %s accepted tcp:%s [%s] uid: %d",
			remote, dest, nodeTag, userRec.UID)
	} else {
		t.svc.logger.Infof("from %s accepted tcp:%s [%s]",
			remote, dest, nodeTag)
	}

	blocked := false

	// Audit check: if a rule hits, mark this connection as blocked and close it.
	if ok && dest != "" && t.svc.rules != nil {
		srcIP := remote
		if h, _, err := net.SplitHostPort(srcIP); err == nil {
			srcIP = h
		}
		if t.svc.rules.DetectUID(nodeTag, dest, userRec.UID, srcIP) {
			t.svc.logger.WithFields(fields).Warn("TUIC audit rule hit, closing connection")
			blocked = true
		}
	}

	// Device limit check (only if not already blocked by audit).
	if !blocked && !t.svc.allowConnection(m.User, remote) {
		// allowConnection already logs a warning when device limit is exceeded.
		blocked = true
	}

	// Attach per-user rate limiter if configured.
	var limiter *rate.Limiter
	t.svc.mu.RLock()
	if t.svc.rateLimiters != nil {
		limiter = t.svc.rateLimiters[m.User]
	}
	t.svc.mu.RUnlock()

	if blocked {
		_ = conn.Close()
		return &connCounter{Conn: conn, svc: t.svc, user: m.User, blocked: true, ctx: ctx, limiter: limiter}
	}

	return &connCounter{Conn: conn, svc: t.svc, user: m.User, ctx: ctx, limiter: limiter}
}

func (t *tuicTracker) RoutedPacketConnection(ctx context.Context, conn N.PacketConn, m adapter.InboundContext, _ adapter.Rule, _ adapter.Outbound) N.PacketConn {
	if t.svc == nil {
		return conn
	}
	if m.User == "" {
		return conn
	}

	remote := ""
	if m.Source.Addr.IsValid() {
		remote = m.Source.Addr.String()
	}

	host := remote
	if host != "" {
		if h, _, err := net.SplitHostPort(host); err == nil {
			host = h
		}
	}

	var (
		userRec userRecord
		ok      bool
	)
	t.svc.mu.RLock()
	userRec, ok = t.svc.users[m.User]
	t.svc.mu.RUnlock()

	dest := m.Domain
	if dest == "" {
		dest = m.Destination.String()
	}

	fields := log.Fields{
		"remote": remote,
	}
	if dest != "" {
		fields["dest"] = dest
	}
	if ok {
		fields["uid"] = userRec.UID
	}

	nodeTag := t.svc.appliedTag()
	if ok {
		t.svc.logger.Infof("from %s accepted udp:%s [%s] uid: %d",
			remote, dest, nodeTag, userRec.UID)
	} else {
		t.svc.logger.Infof("from %s accepted udp:%s [%s]",
			remote, dest, nodeTag)
	}

	blocked := false

	// Audit check for UDP: if a rule hits, block this logical session.
	if ok && dest != "" && t.svc.rules != nil {
		srcIP := host
		if t.svc.rules.DetectUID(nodeTag, dest, userRec.UID, srcIP) {
			t.svc.logger.WithFields(fields).Warn("TUIC audit rule hit on UDP, closing connection")
			blocked = true
		}
	}

	// Device limit check (only if not already blocked by audit).
	if !blocked && !t.svc.allowConnection(m.User, remote) {
		// allowConnection already logs a warning when device limit is exceeded.
		blocked = true
	}

	var limiter *rate.Limiter
	t.svc.mu.RLock()
	if t.svc.rateLimiters != nil {
		limiter = t.svc.rateLimiters[m.User]
	}
	t.svc.mu.RUnlock()

	if blocked {
		_ = conn.Close()
		return &packetConnCounter{PacketConn: conn, svc: t.svc, user: m.User, host: host, blocked: true, ctx: ctx, limiter: limiter}
	}

	return &packetConnCounter{PacketConn: conn, svc: t.svc, user: m.User, host: host, ctx: ctx, limiter: limiter}
}

func admissionContext(ctx context.Context) context.Context {
	if ctx == nil {
		return context.Background()
	}
	return ctx
}
