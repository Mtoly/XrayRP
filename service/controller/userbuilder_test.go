package controller

import (
	"strings"
	"testing"

	"github.com/xtls/xray-core/proxy/vless"

	"github.com/Mtoly/XrayRP/api"
)

func TestFocusedVlessUserBuilderUsesEffectiveFlow(t *testing.T) {
	controller := &Controller{}
	userList := []api.UserInfo{{UID: 1, Email: "user@example.test", UUID: "test-user-id"}}

	users := controller.buildVlessUser(&userList, vlessUserNodeView{
		effectiveFlow: "xtls-rprx-vision",
	}, "node-tag")
	if len(users) != 1 {
		t.Fatalf("users length = %d, want 1", len(users))
	}

	account, err := users[0].Account.GetInstance()
	if err != nil {
		t.Fatal(err)
	}
	if got := account.(*vless.Account).Flow; got != "xtls-rprx-vision" {
		t.Fatalf("VLESS flow = %q, want xtls-rprx-vision", got)
	}
}

func TestRuntimeUserTagDoesNotExposePanelIdentity(t *testing.T) {
	const sentinel = "11111111-2222-3333-4444-555555555555"
	controller := &Controller{}
	user := api.UserInfo{
		UID:    17,
		Email:  sentinel + "@v2board.user",
		UUID:   sentinel,
		Passwd: "test-secret-password",
	}

	users := controller.buildVlessUser(&[]api.UserInfo{user}, vlessUserNodeView{}, "node-tag")
	if len(users) != 1 {
		t.Fatalf("users length = %d, want 1", len(users))
	}
	if got := users[0].Email; got != "node-tag|17" {
		t.Fatalf("runtime user tag = %q, want node-tag|17", got)
	}
	if strings.Contains(users[0].Email, sentinel) || strings.Contains(users[0].Email, user.Passwd) {
		t.Fatalf("runtime user tag contains panel credential: %q", users[0].Email)
	}

	account, err := users[0].Account.GetInstance()
	if err != nil {
		t.Fatal(err)
	}
	if got := account.(*vless.Account).Id; got != sentinel {
		t.Fatalf("VLESS account ID = %q, want original authentication UUID", got)
	}
}

func TestRuntimeLimiterUsersOwnOpaqueRuntimeTags(t *testing.T) {
	const sentinel = "11111111-2222-3333-4444-555555555555"
	controller := &Controller{}
	input := []api.UserInfo{{UID: 17, Email: sentinel + "@v2board.user", UUID: sentinel}}

	got := controller.runtimeLimiterUsers("node-tag", &input)
	if got == &input || got == nil || len(*got) != 1 {
		t.Fatalf("runtimeLimiterUsers did not return an owned copy: %#v", got)
	}
	if (*got)[0].Email != "node-tag|17" {
		t.Fatalf("runtime limiter key = %q, want node-tag|17", (*got)[0].Email)
	}
	if input[0].Email != sentinel+"@v2board.user" {
		t.Fatal("runtimeLimiterUsers mutated the panel-owned input")
	}
}

func TestAuditUIDFromUserTagAcceptsSeparatorInEmail(t *testing.T) {
	uid, ok := auditUIDFromUserTag(
		"VLESS_127.0.0.1_443_9",
		"VLESS_127.0.0.1_443_9|mail|alias@example.test|17",
	)
	if !ok || uid != 17 {
		t.Fatalf("auditUIDFromUserTag() = (%d, %v), want (17, true)", uid, ok)
	}
}

func TestAuditUIDFromUserTagRejectsMixedOrMalformedIdentity(t *testing.T) {
	tests := []string{
		"",
		"17",
		"other-node|user@example.test|17",
		"node|user@example.test|",
		"node|user@example.test|invalid",
	}
	for _, userTag := range tests {
		t.Run(userTag, func(t *testing.T) {
			if uid, ok := auditUIDFromUserTag("node", userTag); ok {
				t.Fatalf("auditUIDFromUserTag() = (%d, true), want invalid", uid)
			}
		})
	}
}
