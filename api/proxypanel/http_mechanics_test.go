package proxypanel

import (
	"errors"
	"net/http"
	"net/http/httptrace"
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

func TestCommonRequestPreservesProxyPanelTrace(t *testing.T) {
	client := New(&api.Config{APIHost: "https://panel.example", Key: "secret"})
	traceInstalled := false
	client.client.SetTransport(proxyPanelRoundTripFunc(func(req *http.Request) (*http.Response, error) {
		traceInstalled = httptrace.ContextClientTrace(req.Context()) != nil
		return &http.Response{
			StatusCode: http.StatusOK,
			Status:     "200 OK",
			Header:     make(http.Header),
			Body:       http.NoBody,
			Request:    req,
		}, nil
	}))

	if _, err := client.createCommonRequest().Get("/trace"); err != nil {
		t.Fatalf("request failed: %v", err)
	}
	if !traceInstalled {
		t.Fatal("proxy panel request did not install HTTP trace hooks")
	}
}

func TestParseResponsePreservesTransportCause(t *testing.T) {
	sentinel := errors.New("transport failed")
	client := New(&api.Config{APIHost: "https://panel.example", Key: "secret"})

	_, err := client.parseResponse(nil, "/api/v2ray/v1/node/1", sentinel)

	if !errors.Is(err, sentinel) {
		t.Fatalf("error = %v, want transport failure identity", err)
	}
}

func TestParseResponseRejectsWrongTypedResultWithoutPanic(t *testing.T) {
	client := New(&api.Config{APIHost: "https://panel.example", Key: "secret"})
	res := &resty.Response{
		RawResponse: &http.Response{StatusCode: http.StatusOK},
		Request:     &resty.Request{Result: &struct{}{}},
	}

	_, err := client.parseResponse(res, "/api/v2ray/v1/node/1", nil)

	if err == nil || !strings.Contains(err.Error(), "invalid typed result") {
		t.Fatalf("error = %v, want safe typed-result failure", err)
	}
}

type proxyPanelRoundTripFunc func(*http.Request) (*http.Response, error)

func (f proxyPanelRoundTripFunc) RoundTrip(req *http.Request) (*http.Response, error) {
	return f(req)
}
