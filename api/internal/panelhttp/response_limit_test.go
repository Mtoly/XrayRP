package panelhttp

import (
	"bytes"
	"compress/gzip"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/Mtoly/XrayRP/api"
	"github.com/go-resty/resty/v2"
)

func TestResponseBodyBudgetFitsModeledPanelPayloads(t *testing.T) {
	users := make([]api.UserInfo, 5000)
	for i := range users {
		users[i] = api.UserInfo{
			UID:         i + 1,
			Email:       strings.Repeat("u", 96) + "@example.invalid",
			UUID:        "12345678-1234-1234-1234-123456789abc",
			Passwd:      strings.Repeat("p", 128),
			Port:        65535,
			AlterID:     65535,
			Method:      "2022-blake3-aes-256-gcm",
			SpeedLimit:  999999999,
			DeviceLimit: 99,
		}
	}
	devices := make(map[string][]string, 5000)
	for userIndex := 0; userIndex < 5000; userIndex++ {
		ips := make([]string, 32)
		for deviceIndex := range ips {
			ips[deviceIndex] = fmt.Sprintf("2001:db8:%x:%x::%x", userIndex, deviceIndex, userIndex+deviceIndex)
		}
		devices[strconv.Itoa(userIndex+1)] = ips
	}
	routes := make([]struct {
		ID     int      `json:"id"`
		Match  []string `json:"match"`
		Action string   `json:"action"`
	}, 5000)
	for i := range routes {
		routes[i].ID = i + 1
		routes[i].Match = []string{fmt.Sprintf("domain-%d.example.invalid", i)}
		routes[i].Action = "block"
	}
	nodeSnapshot := struct {
		ServerPort  int    `json:"server_port"`
		Network     string `json:"network"`
		CertContent string `json:"cert_content"`
		KeyContent  string `json:"key_content"`
		Routes      any    `json:"routes"`
	}{
		ServerPort:  443,
		Network:     "tcp",
		CertContent: strings.Repeat("certificate", 64*1024),
		KeyContent:  strings.Repeat("private-key", 32*1024),
		Routes:      routes,
	}

	payloads := map[string]any{
		"5000 large users": struct {
			Users []api.UserInfo `json:"users"`
		}{Users: users},
		"5000 users with 32 devices": struct {
			Alive map[string][]string `json:"alive"`
		}{Alive: devices},
		"large node snapshot": nodeSnapshot,
		"large error envelope": struct {
			Code    int    `json:"code"`
			Message string `json:"message"`
		}{Code: 500, Message: strings.Repeat("diagnostic", 64*1024/10)},
	}
	for name, payload := range payloads {
		body, err := json.Marshal(payload)
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		if len(body) > MaxResponseBodyBytes/4 {
			t.Fatalf("%s = %d bytes, want at least 4x headroom within %d-byte limit", name, len(body), MaxResponseBodyBytes)
		}
		t.Logf("%s = %d bytes (%.2f MiB), response limit = %.0f MiB", name, len(body), float64(len(body))/(1<<20), float64(MaxResponseBodyBytes)/(1<<20))
	}
}

func TestNewClientAppliesResponseBodyLimit(t *testing.T) {
	client, _ := NewClient(ClientConfig{BaseURL: "https://panel.example"})

	if client.ResponseBodyLimit != MaxResponseBodyBytes {
		t.Fatalf("response body limit = %d, want %d", client.ResponseBodyLimit, MaxResponseBodyBytes)
	}
}

func TestCheckResponseReturnsTypedBodyLimitErrorWithoutBodyContents(t *testing.T) {
	_, policy := NewClient(ClientConfig{
		BaseURL:     "https://panel.example",
		Credentials: []string{"panel-secret"},
	})

	err := policy.CheckResponse(nil, "/users", errors.Join(
		errors.New("panel-secret"),
		resty.ErrResponseBodyTooLarge,
		errors.New("response-body-secret"),
	))

	if !errors.Is(err, ErrResponseBodyTooLarge) {
		t.Fatalf("error = %v, want ErrResponseBodyTooLarge", err)
	}
	if strings.Contains(err.Error(), "panel-secret") || strings.Contains(err.Error(), "response-body-secret") {
		t.Fatalf("body limit error leaked credentials or response body: %v", err)
	}
}

func TestCheckResponsePreservesHTTPStatusWithBodyLimitIdentity(t *testing.T) {
	_, policy := NewClient(ClientConfig{BaseURL: "https://panel.example"})
	res := responseWithStatus(http.StatusUnauthorized)

	err := policy.CheckResponse(res, "/users", resty.ErrResponseBodyTooLarge)

	if !errors.Is(err, ErrResponseBodyTooLarge) {
		t.Fatalf("error = %v, want ErrResponseBodyTooLarge identity", err)
	}
	if !strings.Contains(err.Error(), "status 401") {
		t.Fatalf("error = %v, want original HTTP status priority", err)
	}
}

func TestClientDoesNotRetryResponseBodyLimit(t *testing.T) {
	client, _ := NewClient(ClientConfig{BaseURL: "https://panel.example"})
	client.SetRetryWaitTime(time.Nanosecond)
	client.SetRetryMaxWaitTime(time.Nanosecond)

	attempts := 0
	client.SetTransport(roundTripFunc(func(req *http.Request) (*http.Response, error) {
		attempts++
		return &http.Response{
			StatusCode:    http.StatusOK,
			Status:        "200 OK",
			Header:        make(http.Header),
			Body:          io.NopCloser(strings.NewReader(strings.Repeat("x", 65))),
			ContentLength: 65,
			Request:       req,
		}, nil
	}))

	_, err := client.R().SetResponseBodyLimit(64).Get("/users")

	if !errors.Is(err, resty.ErrResponseBodyTooLarge) {
		t.Fatalf("error = %v, want Resty response limit error", err)
	}
	if attempts != 1 {
		t.Fatalf("attempts = %d, want oversized response to fail without retry", attempts)
	}
}

func TestClientLimitsRawGzipInputBeforeHeaderParsing(t *testing.T) {
	raw := oversizedEmptyGzipMembers(t)
	attempts := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		attempts++
		w.Header().Set("Content-Encoding", "gzip")
		w.Header().Set("Content-Length", strconv.Itoa(len(raw)))
		_, _ = w.Write(raw)
	}))
	defer server.Close()

	client, policy := NewClient(ClientConfig{BaseURL: server.URL})
	res, requestErr := client.R().Get("/gzip-header")
	err := policy.CheckResponse(res, "/gzip-header", requestErr)

	if !errors.Is(err, ErrResponseBodyTooLarge) {
		t.Fatalf("error = %v, want raw gzip input limit error", err)
	}
	if attempts != 1 {
		t.Fatalf("attempts = %d, want raw gzip limit to stop without retry", attempts)
	}
}

func TestClientRejectsGzipExpansionBeforeDecode(t *testing.T) {
	const limit = 256
	compressed := gzipBytes(t, `{"value":"`+strings.Repeat("response-body-secret", 512)+`"}`)
	if compressed.Len() >= limit {
		t.Fatalf("compressed fixture = %d bytes, want less than %d to prove decompressed limit", compressed.Len(), limit)
	}

	client, policy := NewClient(ClientConfig{BaseURL: "https://panel.example"})
	client.SetRetryCount(0)
	client.SetTransport(roundTripFunc(func(req *http.Request) (*http.Response, error) {
		return &http.Response{
			StatusCode:    http.StatusOK,
			Status:        "200 OK",
			Header:        http.Header{"Content-Encoding": []string{"gzip"}},
			Body:          io.NopCloser(bytes.NewReader(compressed.Bytes())),
			ContentLength: int64(compressed.Len()),
			Request:       req,
		}, nil
	}))
	target := struct {
		Value string `json:"value"`
	}{Value: "last-known-good"}

	res, requestErr := client.R().
		SetResponseBodyLimit(limit).
		SetResult(&target).
		Get("/users")
	err := policy.CheckResponse(res, "/users", requestErr)

	if !errors.Is(err, ErrResponseBodyTooLarge) {
		t.Fatalf("error = %v, want decompressed response limit error", err)
	}
	if target.Value != "last-known-good" {
		t.Fatalf("decode published partial value %q", target.Value)
	}
	if strings.Contains(err.Error(), "response-body-secret") {
		t.Fatalf("response limit error leaked response body: %v", err)
	}
}

func TestReadResponseBodyUsesExactLimitAndBoundsReads(t *testing.T) {
	t.Run("at limit", func(t *testing.T) {
		body, err := readResponseBody(strings.NewReader("12345678"), 8)
		if err != nil {
			t.Fatalf("exact-limit body failed: %v", err)
		}
		if string(body) != "12345678" {
			t.Fatalf("body = %q, want exact content", body)
		}
	})

	t.Run("over limit", func(t *testing.T) {
		reader := &countingReader{reader: strings.NewReader(strings.Repeat("x", 1024))}
		body, err := readResponseBody(reader, 8)
		if !errors.Is(err, ErrResponseBodyTooLarge) {
			t.Fatalf("body = %q, error = %v, want typed limit error", body, err)
		}
		if body != nil {
			t.Fatalf("oversized body returned partial bytes: %q", body)
		}
		if reader.read > 9 {
			t.Fatalf("read %d bytes, want at most limit+1", reader.read)
		}
	})

	t.Run("over limit with concurrent read error", func(t *testing.T) {
		readErr := errors.New("connection reset after bytes arrived")
		body, err := readResponseBody(&singleReadErrorReader{
			body: []byte("123456789"),
			err:  readErr,
		}, 8)
		if !errors.Is(err, ErrResponseBodyTooLarge) {
			t.Fatalf("body = %q, error = %v, want limit error to take precedence over %v", body, err, readErr)
		}
		if body != nil {
			t.Fatalf("oversized body returned partial bytes: %q", body)
		}
	})

	t.Run("over limit after zero-length read", func(t *testing.T) {
		body, err := readResponseBody(&zeroThenReader{
			first: []byte("12345678"),
			rest:  strings.NewReader("9"),
		}, 8)
		if !errors.Is(err, ErrResponseBodyTooLarge) {
			t.Fatalf("body = %q, error = %v, want limit error after zero-length read", body, err)
		}
		if body != nil {
			t.Fatalf("oversized body returned partial bytes: %q", body)
		}
	})
}

func TestReadResponseBodyRejectsNegativeLimitWithoutReading(t *testing.T) {
	reader := &countingReader{reader: strings.NewReader("response-body-secret")}

	body, err := readResponseBody(reader, -1)

	if !errors.Is(err, ErrResponseBodyTooLarge) {
		t.Fatalf("body = %q, error = %v, want typed limit error", body, err)
	}
	if body != nil {
		t.Fatalf("negative limit returned partial bytes: %q", body)
	}
	if reader.read != 0 {
		t.Fatalf("negative limit read %d bytes, want 0", reader.read)
	}
}

func TestReadResponseBodyHandlesMaxInt64LimitWithoutOverflow(t *testing.T) {
	body, err := readResponseBody(strings.NewReader("valid"), math.MaxInt64)

	if err != nil {
		t.Fatalf("max-int64 limit failed: %v", err)
	}
	if string(body) != "valid" {
		t.Fatalf("body = %q, want valid", body)
	}
}

func gzipBytes(t *testing.T, value string) *bytes.Buffer {
	t.Helper()
	var compressed bytes.Buffer
	writer := gzip.NewWriter(&compressed)
	if _, err := writer.Write([]byte(value)); err != nil {
		t.Fatal(err)
	}
	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}
	return &compressed
}

func oversizedEmptyGzipMembers(t *testing.T) []byte {
	t.Helper()
	var member bytes.Buffer
	writer := gzip.NewWriter(&member)
	writer.Header.Extra = bytes.Repeat([]byte("x"), 65535)
	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}
	count := MaxResponseBodyBytes/member.Len() + 2
	return bytes.Repeat(member.Bytes(), count)
}

type countingReader struct {
	reader io.Reader
	read   int
}

func (r *countingReader) Read(p []byte) (int, error) {
	n, err := r.reader.Read(p)
	r.read += n
	return n, err
}

type singleReadErrorReader struct {
	body []byte
	err  error
}

func (r *singleReadErrorReader) Read(p []byte) (int, error) {
	n := copy(p, r.body)
	r.body = r.body[n:]
	if len(r.body) == 0 {
		return n, r.err
	}
	return n, nil
}

type zeroThenReader struct {
	first    []byte
	rest     io.Reader
	returned bool
}

func (r *zeroThenReader) Read(p []byte) (int, error) {
	if len(r.first) > 0 {
		n := copy(p, r.first)
		r.first = r.first[n:]
		return n, nil
	}
	if !r.returned {
		r.returned = true
		return 0, nil
	}
	return r.rest.Read(p)
}
