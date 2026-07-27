package newV2board

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/Mtoly/XrayRP/api/internal/panelhttp"
)

func TestNewMachineClientPreservesRetryAndTimeoutPolicy(t *testing.T) {
	client, _ := newMachineClient("https://panel.example", 0)
	if client.RetryCount != 0 {
		t.Fatalf("default retry count = %d, want machine policy 0", client.RetryCount)
	}
	if client.GetClient().Timeout != 0 {
		t.Fatalf("default timeout = %s, want machine policy with no timeout", client.GetClient().Timeout)
	}

	client, _ = newMachineClient("https://panel.example", 750*time.Millisecond)
	if client.RetryCount != 0 {
		t.Fatalf("configured retry count = %d, want machine policy 0", client.RetryCount)
	}
	if client.GetClient().Timeout != 750*time.Millisecond {
		t.Fatalf("configured timeout = %s, want 750ms", client.GetClient().Timeout)
	}
}

func TestDiscoverMachineNodesRejectsOversizedResponseWithoutPartialResult(t *testing.T) {
	const token = "machine-token-secret"
	const bodySecret = "response-body-secret"
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(strings.Repeat("x", panelhttp.MaxResponseBodyBytes) + bodySecret))
	}))
	defer server.Close()

	result, err := DiscoverMachineNodes(MachineDiscoveryConfig{
		APIHost:   server.URL,
		MachineID: 7,
		Token:     token,
	})

	if !errors.Is(err, panelhttp.ErrResponseBodyTooLarge) {
		t.Fatalf("result = %#v, error = %v, want typed response limit error", result, err)
	}
	if result != nil {
		t.Fatalf("oversized response returned partial result: %#v", result)
	}
	if strings.Contains(err.Error(), token) || strings.Contains(err.Error(), bodySecret) {
		t.Fatalf("response limit error leaked credentials or response body: %v", err)
	}
}
