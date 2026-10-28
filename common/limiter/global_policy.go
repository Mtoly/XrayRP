package limiter

// syncGlobalPolicies publishes an owned policy view without doing network I/O.
// Redis registers it on admission and on the manager's renewal worker.
func syncGlobalPolicies(state *inboundState) {
	if state == nil || state.GlobalLimit == nil || state.GlobalLimit.admission == nil {
		return
	}
	users := make(map[int]int)
	state.UserInfo.Range(func(_, value any) bool {
		user := value.(userPolicy)
		users[user.UID] = user.DeviceLimit
		return true
	})
	state.GlobalLimit.admission.SetUsers(users)
}
