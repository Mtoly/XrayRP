package tuic

import "net"

// deviceConnections is a reservation shared by connections from the same IP.
// Pointer identity prevents late closes from retiring a replacement reservation.
// The service mutex protects count and the reservation map.
type deviceConnections struct {
	count int
}

func admissionHost(remote string) string {
	if host, _, err := net.SplitHostPort(remote); err == nil {
		remote = host
	}
	if remote == "" {
		return "unknown"
	}
	return remote
}

// releaseConnection drops one local reference. The caller closes the
// connection's global lease separately, outside the service mutex.
func (s *TuicService) releaseConnection(user, host string, device *deviceConnections) {
	if device == nil {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.connections[user][host] != device {
		return
	}
	device.count--
	if device.count > 0 {
		return
	}
	delete(s.connections[user], host)
	if len(s.connections[user]) == 0 {
		delete(s.connections, user)
	}
	delete(s.onlineIPs[user], host)
	if len(s.onlineIPs[user]) == 0 {
		delete(s.onlineIPs, user)
	}
	delete(s.ipLastActive[user], host)
	if len(s.ipLastActive[user]) == 0 {
		delete(s.ipLastActive, user)
	}
}
