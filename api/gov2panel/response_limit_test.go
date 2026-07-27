package gov2panel_test

import (
	"bytes"
	"compress/gzip"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"

	"github.com/Mtoly/XrayRP/api/internal/panelhttp"
)

func TestGetUserListRejectsOversizedGzipResponseWithoutPartialResult(t *testing.T) {
	const key = "gov2-panel-secret"
	const bodySecret = "response-body-secret"
	var compressed bytes.Buffer
	writer := gzip.NewWriter(&compressed)
	if _, err := writer.Write([]byte(strings.Repeat("x", panelhttp.MaxResponseBodyBytes) + bodySecret)); err != nil {
		t.Fatal(err)
	}
	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.Copy(io.Discard, r.Body)
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Content-Encoding", "gzip")
		w.Header().Set("Content-Length", strconv.Itoa(compressed.Len()))
		_, _ = w.Write(compressed.Bytes())
	}))
	defer server.Close()

	client := newContractClient(server, "V2ray")
	client.Key = key
	result, err := client.GetUserList()

	if !errors.Is(err, panelhttp.ErrResponseBodyTooLarge) {
		t.Fatalf("result = %#v, error = %v, want typed decompressed response limit error", result, err)
	}
	if result != nil {
		t.Fatalf("oversized response returned partial result: %#v", result)
	}
	if strings.Contains(err.Error(), key) || strings.Contains(err.Error(), bodySecret) {
		t.Fatalf("response limit error leaked credentials or response body: %v", err)
	}
}

func TestGetUserListLimitsRawGzipInputBeforeHeaderParsing(t *testing.T) {
	var member bytes.Buffer
	writer := gzip.NewWriter(&member)
	writer.Header.Extra = bytes.Repeat([]byte("x"), 65535)
	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}
	raw := bytes.Repeat(member.Bytes(), panelhttp.MaxResponseBodyBytes/member.Len()+2)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.Copy(io.Discard, r.Body)
		w.Header().Set("Content-Encoding", "gzip")
		w.Header().Set("Content-Length", strconv.Itoa(len(raw)))
		_, _ = w.Write(raw)
	}))
	defer server.Close()

	result, err := newContractClient(server, "V2ray").GetUserList()

	if !errors.Is(err, panelhttp.ErrResponseBodyTooLarge) {
		t.Fatalf("result = %#v, error = %v, want raw gzip input limit error", result, err)
	}
	if result != nil {
		t.Fatalf("raw oversized response returned partial result: %#v", result)
	}
}

func TestGetUserListAcceptsFiveThousandUsersNearResponseLimit(t *testing.T) {
	users := make([]struct {
		ID         int    `json:"id"`
		UUID       string `json:"uuid"`
		SpeedLimit int    `json:"speed_limit"`
	}, 5000)
	for i := range users {
		users[i].ID = i + 1
		users[i].UUID = fmt.Sprintf("12345678-1234-1234-1234-%012d", i)
		users[i].SpeedLimit = 1000
	}
	usersJSON, err := json.Marshal(users)
	if err != nil {
		t.Fatal(err)
	}
	const prefix = `{"code":0,"data":{"users":`
	const paddingPrefix = `},"padding":"`
	const suffix = `"}`
	paddingLength := panelhttp.MaxResponseBodyBytes - 1024 - len(prefix) - len(usersJSON) - len(paddingPrefix) - len(suffix)
	if paddingLength <= 0 {
		t.Fatalf("5000-user envelope leaves no compatibility padding: users = %d bytes", len(usersJSON))
	}
	body := prefix + string(usersJSON) + paddingPrefix + strings.Repeat("p", paddingLength) + suffix
	if len(body) >= panelhttp.MaxResponseBodyBytes || len(body) < panelhttp.MaxResponseBodyBytes-2048 {
		t.Fatalf("large valid response = %d bytes, want just below %d", len(body), panelhttp.MaxResponseBodyBytes)
	}

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.Copy(io.Discard, r.Body)
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(body))
	}))
	defer server.Close()

	got, err := newContractClient(server, "V2ray").GetUserList()
	if err != nil {
		t.Fatalf("large valid response failed: %v", err)
	}
	if got == nil || len(*got) != 5000 {
		t.Fatalf("users = %#v, want 5000 decoded users", got)
	}
}
