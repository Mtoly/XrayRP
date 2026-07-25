package bunpanel

import (
	"errors"
	"fmt"
	"net/http"
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
