package newV2board

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/go-resty/resty/v2"

	"github.com/Mtoly/XrayRP/api"
)

func TestNewAppliesSharedHTTPMechanics(t *testing.T) {
	client := New(&api.Config{APIHost: "https://panel.example", Key: "secret", Timeout: 7})

	if client.client.RetryCount != 3 {
		t.Fatalf("retry count = %d, want 3", client.client.RetryCount)
	}
	if got := client.client.GetClient().Timeout; got != 7*time.Second {
		t.Fatalf("timeout = %s, want 7s", got)
	}
}

func TestGetUserListPreRequestFailureDoesNotPanic(t *testing.T) {
	sentinel := errors.New("pre-request failed")
	client := New(&api.Config{
		APIHost:  "https://panel.example",
		Key:      "secret",
		NodeID:   17,
		NodeType: "V2ray",
	})
	client.client.OnBeforeRequest(func(*resty.Client, *resty.Request) error {
		return sentinel
	})

	_, err := client.GetUserList()
	if !errors.Is(err, sentinel) {
		t.Fatalf("error = %v, want pre-request failure identity", err)
	}
}

func TestGetUserListTransportFailurePreservesCauseAndRedactsToken(t *testing.T) {
	secret := "xboard token/+?"
	sentinel := errors.New("transport failed")
	client := newHTTPMechanicsClient(secret)
	client.client.SetTransport(newV2boardRoundTripFunc(func(*http.Request) (*http.Response, error) {
		return nil, sentinel
	}))

	_, err := client.GetUserList()
	assertSafeTransportError(t, err, sentinel, secret)
}

func TestPostXboardReportTransportFailureRedactsToken(t *testing.T) {
	secret := "xboard token/+?"
	sentinel := errors.New("transport failed")
	client := newHTTPMechanicsClient(secret)
	client.client.SetTransport(newV2boardRoundTripFunc(func(*http.Request) (*http.Response, error) {
		return nil, sentinel
	}))

	err := client.postXboardReport(map[string]any{"type": "status"})
	assertSafeTransportError(t, err, sentinel, secret)
}

func TestGetUserListRejectsInvalidUsersWithoutPublishingETag(t *testing.T) {
	tests := []struct {
		name string
		body string
	}{
		{name: "invalid field type", body: `{"users":[{"id":1,"uuid":"valid"},{"id":"invalid","uuid":"partial"}]}`},
		{name: "null user", body: `{"users":[null]}`},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if got := r.Header.Get("If-None-Match"); got != "old-etag" {
					t.Errorf("If-None-Match = %q, want old-etag", got)
				}
				w.Header().Set("Content-Type", "application/json")
				w.Header().Set("Etag", "invalid-etag")
				_, _ = w.Write([]byte(tc.body))
			}))
			defer server.Close()

			client := New(&api.Config{
				APIHost:  server.URL,
				Key:      "secret",
				NodeID:   17,
				NodeType: "V2ray",
			})
			client.eTags.Publish("users", "old-etag")

			users, err := client.GetUserList()

			if err == nil {
				t.Fatalf("users = %#v, want invalid payload error", users)
			}
			if users != nil {
				t.Fatalf("invalid payload returned partial users: %#v", users)
			}
			if got := client.eTags.Get("users"); got != "old-etag" {
				t.Fatalf("etag after invalid payload = %q, want old-etag", got)
			}
		})
	}
}

func newHTTPMechanicsClient(secret string) *APIClient {
	client := New(&api.Config{
		APIHost:  "https://panel.example",
		Key:      secret,
		NodeID:   17,
		NodeType: "V2ray",
	})
	client.client.SetRetryWaitTime(time.Nanosecond)
	client.client.SetRetryMaxWaitTime(time.Nanosecond)
	return client
}

func assertSafeTransportError(t *testing.T, err, sentinel error, secret string) {
	t.Helper()
	if !errors.Is(err, sentinel) {
		t.Fatalf("error = %v, want transport failure identity", err)
	}
	for _, forbidden := range []string{secret, url.QueryEscape(secret)} {
		if strings.Contains(err.Error(), forbidden) {
			t.Fatalf("error contains credential %q: %v", forbidden, err)
		}
	}
}

type newV2boardRoundTripFunc func(*http.Request) (*http.Response, error)

func (f newV2boardRoundTripFunc) RoundTrip(req *http.Request) (*http.Response, error) {
	return f(req)
}
