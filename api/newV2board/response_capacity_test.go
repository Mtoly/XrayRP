package newV2board

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/Mtoly/XrayRP/api"
	"github.com/Mtoly/XrayRP/api/internal/panelhttp"
)

func TestGetUserListAcceptsFiveThousandUsersNearResponseLimit(t *testing.T) {
	users := make([]user, 5000)
	for i := range users {
		users[i] = user{
			Id:          i + 1,
			Uuid:        fmt.Sprintf("12345678-1234-1234-1234-%012d", i),
			SpeedLimit:  1000,
			DeviceLimit: 32,
		}
	}
	usersJSON, err := json.Marshal(users)
	if err != nil {
		t.Fatal(err)
	}
	const prefix = `{"users":`
	const paddingPrefix = `,"padding":"`
	const suffix = `"}`
	paddingLength := panelhttp.MaxResponseBodyBytes - 1024 - len(prefix) - len(usersJSON) - len(paddingPrefix) - len(suffix)
	if paddingLength <= 0 {
		t.Fatalf("5000-user envelope leaves no compatibility padding: users = %d bytes", len(usersJSON))
	}
	body := prefix + string(usersJSON) + paddingPrefix + strings.Repeat("p", paddingLength) + suffix
	if len(body) >= panelhttp.MaxResponseBodyBytes || len(body) < panelhttp.MaxResponseBodyBytes-2048 {
		t.Fatalf("large valid response = %d bytes, want just below %d", len(body), panelhttp.MaxResponseBodyBytes)
	}

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(body))
	}))
	defer server.Close()

	client := New(&api.Config{
		APIHost:  server.URL,
		Key:      "panel-token",
		NodeID:   1,
		NodeType: "V2ray",
	})
	got, err := client.GetUserList()
	if err != nil {
		t.Fatalf("large valid response failed: %v", err)
	}
	if got == nil || len(*got) != 5000 {
		t.Fatalf("users = %#v, want 5000 decoded users", got)
	}
}
