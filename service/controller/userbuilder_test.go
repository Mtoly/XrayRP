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
