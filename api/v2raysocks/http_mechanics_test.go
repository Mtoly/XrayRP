package v2raysocks

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/bitly/go-simplejson"
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

func TestGetUserListPreservesAuthenticationAndETagContract(t *testing.T) {
	const (
		secret = "panel-token"
		etag   = "users-v1"
	)
	var requests int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		attempt := atomic.AddInt32(&requests, 1)
		query := r.URL.Query()
		if query.Get("token") != secret || query.Get("node_id") != "17" ||
			query.Get("act") != "user" || query.Get("node_type") != "v2ray" {
			t.Errorf("unexpected query: %s", r.URL.RawQuery)
		}
		if got := r.Header.Get("User-Agent"); got != "XrayR/0.9.6" {
			t.Errorf("User-Agent = %q, want XrayR/0.9.6", got)
		}

		switch attempt {
		case 1:
			if got := r.Header.Get("If-None-Match"); got != "" {
				t.Errorf("first If-None-Match = %q, want empty", got)
			}
			w.Header().Set("Content-Type", "application/json")
			w.Header().Set("Etag", etag)
			_, _ = w.Write([]byte(`{"data":[{"id":1,"uuid":"user-uuid","st":0,"dt":0}]}`))
		case 2:
			if got := r.Header.Get("If-None-Match"); got != etag {
				t.Errorf("second If-None-Match = %q, want %q", got, etag)
			}
			w.WriteHeader(http.StatusNotModified)
		default:
			t.Errorf("unexpected request %d", attempt)
			w.WriteHeader(http.StatusInternalServerError)
		}
	}))
	defer server.Close()

	client := New(&api.Config{
		APIHost:  server.URL,
		Key:      secret,
		NodeID:   17,
		NodeType: "V2ray",
	})
	users, err := client.GetUserList()
	if err != nil {
		t.Fatalf("first user request failed: %v", err)
	}
	if users == nil || len(*users) != 1 || (*users)[0].UUID != "user-uuid" {
		t.Fatalf("users = %#v, want parsed user", users)
	}

	_, err = client.GetUserList()
	if !errors.Is(err, api.ErrUserNotModified) {
		t.Fatalf("second error = %v, want ErrUserNotModified", err)
	}
	if got := atomic.LoadInt32(&requests); got != 2 {
		t.Fatalf("requests = %d, want 2", got)
	}
}

func TestGetNodeInfoPreRequestFailureDoesNotPanic(t *testing.T) {
	sentinel := errors.New("pre-request failed")
	client := New(&api.Config{
		APIHost:  "https://panel.example/api",
		Key:      "secret",
		NodeID:   17,
		NodeType: "V2ray",
	})
	client.client.OnBeforeRequest(func(*resty.Client, *resty.Request) error {
		return sentinel
	})

	_, err := client.GetNodeInfo()
	if !errors.Is(err, sentinel) {
		t.Fatalf("error = %v, want pre-request failure identity", err)
	}
}

func TestGetNodeInfoTransportFailurePreservesCauseAndRedactsToken(t *testing.T) {
	secret := "socks token/+?"
	sentinel := errors.New("transport failed")
	client := New(&api.Config{
		APIHost:  "https://panel.example/api",
		Key:      secret,
		NodeID:   17,
		NodeType: "V2ray",
	})
	client.client.SetRetryWaitTime(time.Nanosecond)
	client.client.SetRetryMaxWaitTime(time.Nanosecond)
	client.client.SetTransport(v2raySocksRoundTripFunc(func(*http.Request) (*http.Response, error) {
		return nil, sentinel
	}))

	_, err := client.GetNodeInfo()
	if !errors.Is(err, sentinel) {
		t.Fatalf("error = %v, want transport failure identity", err)
	}
	for _, forbidden := range []string{secret, url.QueryEscape(secret)} {
		if strings.Contains(err.Error(), forbidden) {
			t.Fatalf("error contains credential %q: %v", forbidden, err)
		}
	}
}

func TestGetNodeInfoKeepsAppliedConfigAndETagAfterInvalidPayload(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if got := r.Header.Get("If-None-Match"); got != "old-etag" {
			t.Errorf("If-None-Match = %q, want old-etag", got)
		}
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Etag", "invalid-etag")
		_, _ = w.Write([]byte(`{"inbounds":[]}`))
	}))
	defer server.Close()

	client := New(&api.Config{
		APIHost:  server.URL,
		Key:      "secret",
		NodeID:   17,
		NodeType: "V2ray",
	})
	appliedConfig, err := simplejson.NewJson([]byte(`{"marker":"last-known-good"}`))
	if err != nil {
		t.Fatal(err)
	}
	client.eTags.Publish("config", "old-etag")
	client.ConfigResp = appliedConfig

	node, err := client.GetNodeInfo()

	if err == nil {
		t.Fatalf("node = %#v, want invalid payload error", node)
	}
	if node != nil {
		t.Fatalf("invalid payload returned partial node: %#v", node)
	}
	if client.ConfigResp != appliedConfig {
		t.Fatal("invalid payload replaced the last-known-good config response")
	}
	if got := client.eTags.Get("config"); got != "old-etag" {
		t.Fatalf("etag after invalid payload = %q, want old-etag", got)
	}
}

func TestGetUserListRejectsInvalidShapeWithoutPublishingETag(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if got := r.Header.Get("If-None-Match"); got != "old-etag" {
			t.Errorf("If-None-Match = %q, want old-etag", got)
		}
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Etag", "invalid-etag")
		_, _ = w.Write([]byte(`{"data":"invalid"}`))
	}))
	defer server.Close()

	client := New(&api.Config{
		APIHost:  server.URL,
		Key:      "secret",
		NodeID:   17,
		NodeType: "V2ray",
	})
	client.eTags.Publish("user", "old-etag")

	users, err := client.GetUserList()

	if err == nil {
		t.Fatalf("users = %#v, want invalid payload error", users)
	}
	if users != nil {
		t.Fatalf("invalid payload returned partial users: %#v", users)
	}
	if got := client.eTags.Get("user"); got != "old-etag" {
		t.Fatalf("etag after invalid payload = %q, want old-etag", got)
	}
}

type v2raySocksRoundTripFunc func(*http.Request) (*http.Response, error)

func (f v2raySocksRoundTripFunc) RoundTrip(req *http.Request) (*http.Response, error) {
	return f(req)
}
