package limiter

import "github.com/Mtoly/XrayRP/api"

// GlobalDeviceDegraded reports the Redis guarantee for applied inbounds only.
func (l *Limiter) GlobalDeviceDegraded() bool {
	if l == nil || l.InboundInfo == nil {
		return false
	}
	degraded := false
	l.InboundInfo.Range(func(key, _ any) bool {
		tag, valid := key.(string)
		if !valid {
			return true
		}
		state, ok := l.loadAppliedInbound(tag)
		if ok && state.GlobalLimit != nil && state.GlobalLimit.admission != nil {
			degraded = state.GlobalLimit.admission.StatusSnapshot().Degraded
		}
		return !degraded
	})
	return degraded
}

func liveGlobalOnlineUsers(state *inboundState) ([]api.OnlineUser, bool) {
	if state == nil || state.GlobalLimit == nil || state.GlobalLimit.admission == nil {
		return nil, false
	}
	known := make(map[int]bool)
	state.UserInfo.Range(func(_, value any) bool {
		known[value.(userPolicy).UID] = true
		return true
	})
	var users []api.OnlineUser
	for uid, ips := range state.GlobalLimit.admission.LiveIPs() {
		if known[uid] {
			for _, ip := range ips {
				users = append(users, api.OnlineUser{UID: uid, IP: ip})
			}
		}
	}
	return users, true
}
