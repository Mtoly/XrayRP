package newV2board

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/Mtoly/XrayRP/api"
)

const benchmarkUserCount = 5000

func benchmarkUserListBody(tb testing.TB) []byte {
	tb.Helper()
	var builder strings.Builder
	builder.WriteString(`{"users":[`)
	for i := 0; i < benchmarkUserCount; i++ {
		if i > 0 {
			builder.WriteByte(',')
		}
		fmt.Fprintf(&builder, `{"id":%d,"uuid":"%08x-0000-4000-8000-%012x","speed_limit":%d,"device_limit":%d}`,
			i+1, i, i, i%100, i%5)
	}
	builder.WriteString(`]}`)
	return []byte(builder.String())
}

// BenchmarkGetUserList5000Users measures one full HTTP 200 user poll over
// loopback, including transport, response checks, decoding and conversion.
func BenchmarkGetUserList5000Users(b *testing.B) {
	body := benchmarkUserListBody(b)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write(body)
	}))
	defer server.Close()

	client := New(&api.Config{APIHost: server.URL, NodeID: 1, NodeType: "V2ray"})
	users, err := client.GetUserListContext(context.Background())
	if err != nil {
		b.Fatalf("GetUserListContext() error = %v", err)
	}
	if len(*users) != benchmarkUserCount {
		b.Fatalf("GetUserListContext() returned %d users, want %d", len(*users), benchmarkUserCount)
	}

	b.SetBytes(int64(len(body)))
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, err := client.GetUserListContext(context.Background()); err != nil {
			b.Fatal(err)
		}
	}
}

// BenchmarkUserListDecode5000Users isolates the current decode steps used by
// GetUserListContext after the HTTP response is received.
func BenchmarkUserListDecode5000Users(b *testing.B) {
	body := benchmarkUserListBody(b)

	b.Run("current", func(b *testing.B) {
		b.SetBytes(int64(len(body)))
		b.ReportAllocs()
		for i := 0; i < b.N; i++ {
			response, err := newJSONResponse(body)
			if err != nil {
				b.Fatal(err)
			}
			usersJSON, ok, err := response.field("users")
			if err != nil || !ok {
				b.Fatalf("field(users) ok=%v err=%v", ok, err)
			}
			var users []*user
			if err := json.Unmarshal(usersJSON, &users); err != nil {
				b.Fatal(err)
			}
			if len(users) != benchmarkUserCount {
				b.Fatalf("decoded %d users, want %d", len(users), benchmarkUserCount)
			}
		}
	})

	// single-unmarshal is a lower bound for comparison, not the production path.
	b.Run("single-unmarshal", func(b *testing.B) {
		b.SetBytes(int64(len(body)))
		b.ReportAllocs()
		for i := 0; i < b.N; i++ {
			var payload struct {
				Users []*user `json:"users"`
			}
			if err := json.Unmarshal(body, &payload); err != nil {
				b.Fatal(err)
			}
			if len(payload.Users) != benchmarkUserCount {
				b.Fatalf("decoded %d users, want %d", len(payload.Users), benchmarkUserCount)
			}
		}
	})
}
