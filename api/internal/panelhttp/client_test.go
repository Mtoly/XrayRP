package panelhttp

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/go-resty/resty/v2"
	log "github.com/sirupsen/logrus"
)

func TestNewClientAppliesSharedRetryAndTimeoutPolicy(t *testing.T) {
	tests := []struct {
		name           string
		timeoutSeconds int
		wantTimeout    time.Duration
	}{
		{name: "default timeout", wantTimeout: 5 * time.Second},
		{name: "configured timeout", timeoutSeconds: 17, wantTimeout: 17 * time.Second},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			client, _ := NewClient(ClientConfig{
				BaseURL:        "https://panel.example",
				TimeoutSeconds: tt.timeoutSeconds,
			})

			if client.RetryCount != 3 {
				t.Fatalf("retry count = %d, want 3", client.RetryCount)
			}
			if got := client.GetClient().Timeout; got != tt.wantTimeout {
				t.Fatalf("timeout = %s, want %s", got, tt.wantTimeout)
			}
			if client.BaseURL != "https://panel.example" {
				t.Fatalf("base URL = %q, want configured URL", client.BaseURL)
			}
		})
	}
}

func TestCheckResponsePreservesCauseAndRedactsCredentials(t *testing.T) {
	secret := "raw token/+?"
	_, policy := NewClient(ClientConfig{
		BaseURL:     "https://panel.example",
		Credentials: []string{secret},
	})
	cause := fmt.Errorf("dial token=%s escaped=%s: %w", secret, url.QueryEscape(secret), context.Canceled)

	err := policy.CheckResponse(nil, "/resource?token="+url.QueryEscape(secret), cause)

	if err == nil {
		t.Fatal("error = nil, want transport failure")
	}
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("error %v does not preserve context cancellation", err)
	}
	assertRedacted(t, err.Error(), secret)
	if !strings.Contains(err.Error(), "request https://panel.example/resource") {
		t.Fatalf("error = %q, want sanitized request context", err)
	}
}

func TestCheckResponseRejectsEmptyAndHTTPErrorResponses(t *testing.T) {
	_, policy := NewClient(ClientConfig{BaseURL: "https://panel.example"})

	tests := []struct {
		name    string
		res     *resty.Response
		wantErr string
	}{
		{name: "nil response", wantErr: "empty response"},
		{name: "missing raw response", res: &resty.Response{}, wantErr: "empty response"},
		{name: "server error", res: responseWithStatus(http.StatusInternalServerError), wantErr: "status 500"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := policy.CheckResponse(tt.res, "/resource", nil)
			if err == nil || !strings.Contains(err.Error(), tt.wantErr) {
				t.Fatalf("error = %v, want text %q", err, tt.wantErr)
			}
		})
	}
}

func TestCheckResponseLeaves304ForAdapterSemantics(t *testing.T) {
	_, policy := NewClient(ClientConfig{BaseURL: "https://panel.example"})

	if err := policy.CheckResponse(responseWithStatus(http.StatusNotModified), "/resource", nil); err != nil {
		t.Fatalf("304 response rejected before adapter handling: %v", err)
	}
}

func TestCheckResponseUses400ErrorThreshold(t *testing.T) {
	_, policy := NewClient(ClientConfig{BaseURL: "https://panel.example"})

	if err := policy.CheckResponse(responseWithStatus(399), "/resource", nil); err != nil {
		t.Fatalf("399 response rejected: %v", err)
	}
	for _, status := range []int{http.StatusBadRequest, http.StatusUnauthorized} {
		err := policy.CheckResponse(responseWithStatus(status), "/resource", nil)
		if err == nil || !strings.Contains(err.Error(), fmt.Sprintf("status %d", status)) {
			t.Fatalf("status %d error = %v, want exact HTTP failure", status, err)
		}
	}
}

func TestTypedResultRejectsAbsentWrongAndTypedNilValues(t *testing.T) {
	type payload struct {
		Value string
	}
	_, policy := NewClient(ClientConfig{BaseURL: "https://panel.example"})
	var typedNil *payload

	tests := []struct {
		name   string
		result any
	}{
		{name: "absent"},
		{name: "wrong type", result: &struct{}{}},
		{name: "typed nil", result: typedNil},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			res := responseWithStatus(http.StatusOK)
			res.Request = &resty.Request{Result: tt.result}

			got, err := TypedResult[payload](policy, res, "/resource", nil)
			if err == nil {
				t.Fatalf("result = %#v, want safe result error", got)
			}
		})
	}

	res := responseWithStatus(http.StatusOK)
	got, err := TypedResult[payload](policy, res, "/resource", nil)
	if err == nil {
		t.Fatalf("result = %#v, want missing request metadata failure", got)
	}

	want := &payload{Value: "ok"}
	res = responseWithStatus(http.StatusOK)
	res.Request = &resty.Request{Result: want}
	got, err = TypedResult[payload](policy, res, "/resource", nil)
	if err != nil {
		t.Fatalf("valid result failed: %v", err)
	}
	if got != want {
		t.Fatalf("result = %#v, want original typed result %#v", got, want)
	}
}

func TestClientStopsRetryingAfterTransportRecovery(t *testing.T) {
	client, _ := NewClient(ClientConfig{BaseURL: "https://panel.example"})
	client.SetRetryWaitTime(time.Nanosecond)
	client.SetRetryMaxWaitTime(time.Nanosecond)

	attempts := 0
	transportFailure := errors.New("dial failed")
	client.SetTransport(roundTripFunc(func(req *http.Request) (*http.Response, error) {
		attempts++
		if attempts < 3 {
			return nil, transportFailure
		}
		return &http.Response{
			StatusCode: http.StatusOK,
			Status:     "200 OK",
			Header:     make(http.Header),
			Body:       http.NoBody,
			Request:    req,
		}, nil
	}))

	res, err := client.R().Get("/retry")
	if err != nil {
		t.Fatalf("request did not recover: %v", err)
	}
	if res.StatusCode() != http.StatusOK {
		t.Fatalf("status = %d, want 200", res.StatusCode())
	}
	if attempts != 3 {
		t.Fatalf("attempts = %d, want two failures followed by one success", attempts)
	}
}

func TestClientDoesNotRetryCanceledContext(t *testing.T) {
	client, _ := NewClient(ClientConfig{BaseURL: "https://panel.example"})
	client.SetRetryWaitTime(time.Nanosecond)
	client.SetRetryMaxWaitTime(time.Nanosecond)

	ctx, cancel := context.WithCancel(context.Background())
	entered := make(chan struct{}, 1)
	done := make(chan error, 1)
	attempts := 0
	client.SetTransport(roundTripFunc(func(req *http.Request) (*http.Response, error) {
		attempts++
		if attempts == 1 {
			entered <- struct{}{}
		}
		<-req.Context().Done()
		return nil, req.Context().Err()
	}))

	go func() {
		_, err := client.R().SetContext(ctx).Get("/retry")
		done <- err
	}()
	select {
	case <-entered:
		cancel()
	case <-time.After(time.Second):
		t.Fatal("transport was not entered")
	}

	select {
	case err := <-done:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("error = %v, want context cancellation", err)
		}
	case <-time.After(time.Second):
		t.Fatal("request did not stop after context cancellation")
	}
	if attempts != 1 {
		t.Fatalf("attempts = %d, want cancellation to stop after first attempt", attempts)
	}
}

func TestClientRedactsRetryAndDebugLogs(t *testing.T) {
	secret := "raw token/+?"
	headerSecret := "dynamic-header-secret"
	proxySecret := "dynamic-proxy-secret"
	apiKeySecret := "dynamic-api-key"
	clientSecret := "dynamic-client-secret"
	accessToken := "dynamic-access-token"
	requestCookie := "session=request-cookie-secret"
	responseCookie := "session=response-cookie-secret"
	logs := captureLogrus(t)
	client, policy := NewClient(ClientConfig{
		BaseURL:     "https://panel.example",
		Credentials: []string{secret},
	})
	client.SetQueryParam("token", secret)
	client.SetRetryWaitTime(time.Nanosecond)
	client.SetRetryMaxWaitTime(time.Nanosecond)

	attempts := 0
	transportFailure := errors.New("dial failed")
	client.SetTransport(roundTripFunc(func(*http.Request) (*http.Response, error) {
		attempts++
		return nil, transportFailure
	}))
	res, requestErr := client.R().Get("/retry")
	err := policy.CheckResponse(res, "/retry", requestErr)
	if err == nil || !errors.Is(err, transportFailure) {
		t.Fatalf("error = %v, want transport failure identity", err)
	}
	if attempts != 4 {
		t.Fatalf("attempts = %d, want initial request plus 3 retries", attempts)
	}
	if got := strings.Count(logs.String(), "level=warning"); got != 4 {
		t.Fatalf("retry warnings logged %d times, want one per attempt: %s", got, logs.String())
	}
	if got := strings.Count(logs.String(), "level=error"); got != 1 {
		t.Fatalf("terminal transport errors logged %d times, want 1: %s", got, logs.String())
	}
	assertRedacted(t, logs.String(), secret)
	assertRedacted(t, err.Error(), secret)

	logs.Reset()
	client.SetDebug(true)
	client.SetTransport(roundTripFunc(func(req *http.Request) (*http.Response, error) {
		return &http.Response{
			StatusCode: http.StatusOK,
			Status:     "200 OK",
			Header: http.Header{
				"Content-Type": []string{"application/json"},
				"Set-Cookie":   []string{responseCookie},
			},
			Body:    io.NopCloser(strings.NewReader(`{"private":"response-only-secret"}`)),
			Request: req,
		}, nil
	}))
	_, requestErr = client.R().
		SetHeader("Authorization", "Bearer "+headerSecret).
		SetHeader("Proxy-Authorization", "Bearer "+proxySecret).
		SetHeader("X-API-Key", apiKeySecret).
		SetHeader("X-Client-Secret", clientSecret).
		SetHeader("X-Access-Token", accessToken).
		SetHeader("X-Request-ID", "trace-123").
		SetHeader("Cookie", requestCookie).
		SetBody(map[string]string{"credential": secret, "private": "request-only-secret"}).
		Post("/debug")
	if requestErr != nil {
		t.Fatalf("debug request failed: %v", requestErr)
	}

	debugLog := logs.String()
	assertRedacted(t, debugLog, secret)
	for _, privateValue := range []string{
		headerSecret,
		proxySecret,
		apiKeySecret,
		clientSecret,
		accessToken,
		requestCookie,
		responseCookie,
		"request-only-secret",
		"response-only-secret",
	} {
		if strings.Contains(debugLog, privateValue) {
			t.Fatalf("debug log contains body value %q: %s", privateValue, debugLog)
		}
	}
	if !strings.Contains(debugLog, "POST") || !strings.Contains(debugLog, "200 OK") {
		t.Fatalf("debug log lost non-sensitive request context: %s", debugLog)
	}
	if !strings.Contains(debugLog, "trace-123") {
		t.Fatalf("debug log lost safe header context: %s", debugLog)
	}
}

func TestDebugRedactionDoesNotMutateHTTPHeaders(t *testing.T) {
	secret := "header credential"
	headerValue := "trace=" + secret
	logs := captureLogrus(t)
	client, _ := NewClient(ClientConfig{
		BaseURL:     "https://panel.example",
		Credentials: []string{secret},
	})
	client.SetDebug(true)

	var receivedHeader string
	client.SetTransport(roundTripFunc(func(req *http.Request) (*http.Response, error) {
		receivedHeader = req.Header.Get("X-Panel-Trace")
		return &http.Response{
			StatusCode: http.StatusOK,
			Status:     "200 OK",
			Header: http.Header{
				"X-Panel-Trace": []string{headerValue},
			},
			Body:    http.NoBody,
			Request: req,
		}, nil
	}))

	res, err := client.R().SetHeader("X-Panel-Trace", headerValue).Get("/debug")
	if err != nil {
		t.Fatalf("debug request failed: %v", err)
	}
	if receivedHeader != headerValue {
		t.Errorf("transport received header %q, want original %q", receivedHeader, headerValue)
	}
	if got := res.Header().Get("X-Panel-Trace"); got != headerValue {
		t.Errorf("response header = %q, want original %q", got, headerValue)
	}
	assertRedacted(t, logs.String(), secret)
}

func TestRedactingLoggerPreservesSeverity(t *testing.T) {
	logger := log.StandardLogger()
	oldOutput := logger.Out
	oldHooks := logger.ReplaceHooks(make(log.LevelHooks))
	oldLevel := logger.Level
	hook := new(levelCaptureHook)
	logger.SetOutput(io.Discard)
	logger.SetLevel(log.DebugLevel)
	logger.AddHook(hook)
	t.Cleanup(func() {
		logger.SetOutput(oldOutput)
		logger.ReplaceHooks(oldHooks)
		logger.SetLevel(oldLevel)
	})

	safeLogger := redactingLogger{}
	safeLogger.Errorf("error")
	safeLogger.Warnf("warning")
	safeLogger.Debugf("debug")

	want := []log.Level{log.ErrorLevel, log.WarnLevel, log.DebugLevel}
	if len(hook.levels) != len(want) {
		t.Fatalf("logged levels = %v, want %v", hook.levels, want)
	}
	for i := range want {
		if hook.levels[i] != want[i] {
			t.Fatalf("logged levels = %v, want %v", hook.levels, want)
		}
	}
}

func responseWithStatus(status int) *resty.Response {
	return &resty.Response{RawResponse: &http.Response{StatusCode: status}}
}

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(req *http.Request) (*http.Response, error) {
	return f(req)
}

type levelCaptureHook struct {
	levels []log.Level
}

func (h *levelCaptureHook) Levels() []log.Level {
	return log.AllLevels
}

func (h *levelCaptureHook) Fire(entry *log.Entry) error {
	h.levels = append(h.levels, entry.Level)
	return nil
}

func captureLogrus(t *testing.T) *bytes.Buffer {
	t.Helper()

	logger := log.StandardLogger()
	oldOutput := logger.Out
	oldFormatter := logger.Formatter
	oldLevel := logger.Level
	var output bytes.Buffer
	logger.SetOutput(&output)
	logger.SetFormatter(&log.TextFormatter{DisableColors: true, DisableTimestamp: true})
	logger.SetLevel(log.DebugLevel)
	t.Cleanup(func() {
		logger.SetOutput(oldOutput)
		logger.SetFormatter(oldFormatter)
		logger.SetLevel(oldLevel)
	})
	return &output
}

func assertRedacted(t *testing.T, text, secret string) {
	t.Helper()

	for _, forbidden := range []string{secret, url.QueryEscape(secret), url.PathEscape(secret)} {
		if forbidden != "" && strings.Contains(text, forbidden) {
			t.Fatalf("text contains credential %q: %s", forbidden, text)
		}
	}
}
