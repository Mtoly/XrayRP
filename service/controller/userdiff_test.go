package controller

import (
	"testing"

	"github.com/Mtoly/XrayRP/api"
)

func TestDiffUserListClassifiesLimitOnlyChanges(t *testing.T) {
	currentUsers := []api.UserInfo{baseDiffUser()}
	nextUsers := []api.UserInfo{baseDiffUser()}
	nextUsers[0].SpeedLimit = 200
	nextUsers[0].DeviceLimit = 2

	diff := diffUserList(&currentUsers, &nextUsers)

	if len(diff.Deleted) != 0 || len(diff.Added) != 0 || len(diff.RuntimeUpdated) != 0 {
		t.Fatalf("expected only limit-only changes, got deleted=%d added=%d runtime=%d", len(diff.Deleted), len(diff.Added), len(diff.RuntimeUpdated))
	}
	if len(diff.LimitOnly) != 1 || diff.LimitOnly[0] != nextUsers[0] {
		t.Fatalf("expected next user in limit-only changes, got %#v", diff.LimitOnly)
	}
}

func TestDiffUserListClassifiesUUIDChangeAsRuntimeAffecting(t *testing.T) {
	currentUsers := []api.UserInfo{baseDiffUser()}
	nextUsers := []api.UserInfo{baseDiffUser()}
	nextUsers[0].UUID = "uuid-2"

	diff := diffUserList(&currentUsers, &nextUsers)

	if len(diff.Deleted) != 0 || len(diff.Added) != 0 || len(diff.LimitOnly) != 0 {
		t.Fatalf("expected only runtime update, got deleted=%d added=%d limitOnly=%d", len(diff.Deleted), len(diff.Added), len(diff.LimitOnly))
	}
	if len(diff.RuntimeUpdated) != 1 || diff.RuntimeUpdated[0] != nextUsers[0] {
		t.Fatalf("expected next user in runtime updates, got %#v", diff.RuntimeUpdated)
	}
}

func TestDiffUserListClassifiesPasswordMethodPortAndAlterIDAsRuntimeAffecting(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(*api.UserInfo)
	}{
		{
			name: "password",
			mutate: func(user *api.UserInfo) {
				user.Passwd = "password-2"
			},
		},
		{
			name: "method",
			mutate: func(user *api.UserInfo) {
				user.Method = "aes-256-gcm"
			},
		},
		{
			name: "port",
			mutate: func(user *api.UserInfo) {
				user.Port = 8443
			},
		},
		{
			name: "alter_id",
			mutate: func(user *api.UserInfo) {
				user.AlterID = 4
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			currentUsers := []api.UserInfo{baseDiffUser()}
			nextUsers := []api.UserInfo{baseDiffUser()}
			tc.mutate(&nextUsers[0])

			diff := diffUserList(&currentUsers, &nextUsers)

			if len(diff.Deleted) != 0 || len(diff.Added) != 0 || len(diff.LimitOnly) != 0 {
				t.Fatalf("expected only runtime update, got deleted=%d added=%d limitOnly=%d", len(diff.Deleted), len(diff.Added), len(diff.LimitOnly))
			}
			if len(diff.RuntimeUpdated) != 1 || diff.RuntimeUpdated[0] != nextUsers[0] {
				t.Fatalf("expected next user in runtime updates, got %#v", diff.RuntimeUpdated)
			}
		})
	}
}

func TestDiffUserListRuntimeFieldsEqualIgnoresOnlySpeedAndDeviceLimits(t *testing.T) {
	current := baseDiffUser()
	limitOnly := baseDiffUser()
	limitOnly.SpeedLimit = 200
	limitOnly.DeviceLimit = 2
	if !userRuntimeFieldsEqual(current, limitOnly) {
		t.Fatalf("expected speed and device limits to be ignored")
	}

	tests := []struct {
		name   string
		mutate func(*api.UserInfo)
	}{
		{
			name: "uid",
			mutate: func(user *api.UserInfo) {
				user.UID = 2
			},
		},
		{
			name: "email",
			mutate: func(user *api.UserInfo) {
				user.Email = "other@example.com"
			},
		},
		{
			name: "uuid",
			mutate: func(user *api.UserInfo) {
				user.UUID = "uuid-2"
			},
		},
		{
			name: "password",
			mutate: func(user *api.UserInfo) {
				user.Passwd = "password-2"
			},
		},
		{
			name: "method",
			mutate: func(user *api.UserInfo) {
				user.Method = "aes-256-gcm"
			},
		},
		{
			name: "port",
			mutate: func(user *api.UserInfo) {
				user.Port = 8443
			},
		},
		{
			name: "alter_id",
			mutate: func(user *api.UserInfo) {
				user.AlterID = 4
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			next := baseDiffUser()
			next.SpeedLimit = 200
			next.DeviceLimit = 2
			tc.mutate(&next)

			if userRuntimeFieldsEqual(current, next) {
				t.Fatalf("expected %s change to be runtime-affecting", tc.name)
			}
		})
	}
}

func TestBuildRemovedUserKeysUsesCurrentUsers(t *testing.T) {
	currentUsers := []api.UserInfo{
		{UID: 1, Email: "user@example.com", UUID: "uuid-1"},
		{UID: 2, Email: "other@example.com", UUID: "uuid-other"},
	}
	targets := []api.UserInfo{
		{UID: 1, Email: "user@example.com", UUID: "uuid-2"},
	}

	got := buildRemovedUserKeys("V2ray_1", &currentUsers, targets)

	if len(got) != 1 || got[0] != "V2ray_1|user@example.com|1" {
		t.Fatalf("expected removal key from current user identity, got %#v", got)
	}
}

func baseDiffUser() api.UserInfo {
	return api.UserInfo{
		UID:         1,
		Email:       "user@example.com",
		UUID:        "uuid-1",
		Passwd:      "password-1",
		Port:        443,
		AlterID:     1,
		Method:      "aes-128-gcm",
		SpeedLimit:  100,
		DeviceLimit: 1,
	}
}
