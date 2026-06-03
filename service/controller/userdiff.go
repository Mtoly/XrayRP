package controller

import (
	"fmt"

	"github.com/Mtoly/XrayRP/api"
)

type userListDiff struct {
	Deleted        []api.UserInfo
	Added          []api.UserInfo
	LimitOnly      []api.UserInfo
	RuntimeUpdated []api.UserInfo
}

type userIdentityKey struct {
	UID   int
	Email string
}

func diffUserList(oldUsers, newUsers *[]api.UserInfo) userListDiff {
	var diff userListDiff

	oldByKey := make(map[userIdentityKey]api.UserInfo)
	if oldUsers != nil {
		oldByKey = make(map[userIdentityKey]api.UserInfo, len(*oldUsers))
		for _, user := range *oldUsers {
			oldByKey[userIdentityKey{UID: user.UID, Email: user.Email}] = user
		}
	}

	newKeys := make(map[userIdentityKey]struct{})
	if newUsers != nil {
		newKeys = make(map[userIdentityKey]struct{}, len(*newUsers))
		for _, user := range *newUsers {
			key := userIdentityKey{UID: user.UID, Email: user.Email}
			newKeys[key] = struct{}{}

			current, exists := oldByKey[key]
			if !exists {
				diff.Added = append(diff.Added, user)
				continue
			}
			if current == user {
				continue
			}
			if userRuntimeFieldsEqual(current, user) {
				diff.LimitOnly = append(diff.LimitOnly, user)
			} else {
				diff.RuntimeUpdated = append(diff.RuntimeUpdated, user)
			}
		}
	}

	if oldUsers != nil {
		for _, user := range *oldUsers {
			key := userIdentityKey{UID: user.UID, Email: user.Email}
			if _, exists := newKeys[key]; !exists {
				diff.Deleted = append(diff.Deleted, user)
			}
		}
	}

	return diff
}

func userRuntimeFieldsEqual(a, b api.UserInfo) bool {
	a.SpeedLimit = 0
	a.DeviceLimit = 0
	b.SpeedLimit = 0
	b.DeviceLimit = 0
	return a == b
}

func buildRemovedUserKeys(tag string, currentUsers *[]api.UserInfo, targets []api.UserInfo) []string {
	if currentUsers == nil || len(targets) == 0 {
		return nil
	}

	targetKeys := make(map[userIdentityKey]struct{}, len(targets))
	for _, target := range targets {
		targetKeys[userIdentityKey{UID: target.UID, Email: target.Email}] = struct{}{}
	}

	removed := make([]string, 0, len(targets))
	for _, current := range *currentUsers {
		key := userIdentityKey{UID: current.UID, Email: current.Email}
		if _, exists := targetKeys[key]; !exists {
			continue
		}
		removed = append(removed, fmt.Sprintf("%s|%s|%d", tag, current.Email, current.UID))
	}
	return removed
}
