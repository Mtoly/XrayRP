package controller

import (
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
