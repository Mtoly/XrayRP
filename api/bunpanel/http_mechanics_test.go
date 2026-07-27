package bunpanel

import (
	"errors"
	"fmt"
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

func TestParseResponsePreservesCauseAndRedactsCredential(t *testing.T) {
	secret := "bun token/+?"
	sentinel := errors.New("transport failed")
	client := New(&api.Config{APIHost: "https://panel.example", Key: secret})
	cause := fmt.Errorf("token=%s escaped=%s: %w", secret, url.QueryEscape(secret), sentinel)

	_, err := client.parseResponse(nil, "/v2/server/1/get", cause)

	if !errors.Is(err, sentinel) {
		t.Fatalf("error = %v, want transport failure identity", err)
	}
	for _, forbidden := range []string{secret, url.QueryEscape(secret)} {
		if strings.Contains(err.Error(), forbidden) {
			t.Fatalf("error contains credential %q: %v", forbidden, err)
		}
	}
}

func TestParseResponseRejectsWrongTypedResultWithoutPanic(t *testing.T) {
	client := New(&api.Config{APIHost: "https://panel.example", Key: "secret"})
	res := &resty.Response{
		RawResponse: &http.Response{StatusCode: http.StatusOK},
		Request:     &resty.Request{Result: &struct{}{}},
	}

	_, err := client.parseResponse(res, "/v2/server/1/get", nil)

	if err == nil || !strings.Contains(err.Error(), "invalid typed result") {
		t.Fatalf("error = %v, want safe typed-result failure", err)
	}
}

func TestFetchKeepsETagAfterInvalidPayload(t *testing.T) {
	tests := []struct {
		name    string
		path    string
		etagKey string
		body    string
		run     func(*APIClient) error
	}{
		{
			name:    "node",
			path:    "/v2/server/17/get",
			etagKey: "node",
			body:    `{"statusCode":200,"datas":{"serverPort":8443,"network":"ws","wsSettings":"invalid"}}`,
			run:     func(client *APIClient) error { _, err := client.GetNodeInfo(); return err },
		},
		{
			name:    "users",
			path:    "/v2/user/get",
			etagKey: "users",
			body:    `{"statusCode":200,"datas":"invalid"}`,
			run:     func(client *APIClient) error { _, err := client.GetUserList(); return err },
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path != test.path {
					t.Errorf("path = %q, want %q", r.URL.Path, test.path)
				}
				if got := r.Header.Get("If-None-Match"); got != "old-etag" {
					t.Errorf("If-None-Match = %q, want old-etag", got)
				}
				w.Header().Set("Content-Type", "application/json")
				w.Header().Set("ETag", "invalid-etag")
				_, _ = w.Write([]byte(test.body))
			}))
			defer server.Close()

			client := New(&api.Config{
				APIHost:  server.URL,
				Key:      "secret",
				NodeID:   17,
				NodeType: "V2ray",
			})
			client.eTags.Publish(test.etagKey, "old-etag")

			if err := test.run(client); err == nil {
				t.Fatal("invalid payload returned nil error")
			}
			if got := client.eTags.Get(test.etagKey); got != "old-etag" {
				t.Fatalf("etag after invalid payload = %q, want old-etag", got)
			}
		})
	}
}
