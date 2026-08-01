package newV2board

import (
	"encoding/json"
	"go/parser"
	"go/token"
	"net/http"
	"net/http/httptest"
	"os"
	"strconv"
	"strings"
	"testing"

	"github.com/Mtoly/XrayRP/api"
)

func TestJSONResponseFieldPreservesPresenceSemantics(t *testing.T) {
	tests := []struct {
		name        string
		body        string
		wantPresent bool
		wantValue   string
	}{
		{name: "present object", body: `{"alive":{}}`, wantPresent: true, wantValue: `{}`},
		{name: "present null", body: `{"alive":null}`, wantPresent: true, wantValue: `null`},
		{name: "missing", body: `{}`},
		{name: "top-level array", body: `[]`},
		{name: "top-level scalar", body: `42`},
		{name: "top-level null", body: `null`},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			response, err := newJSONResponse([]byte(test.body))
			if err != nil {
				t.Fatalf("newJSONResponse returned error: %v", err)
			}
			value, present, err := response.field("alive")
			if err != nil {
				t.Fatalf("field returned error: %v", err)
			}
			if present != test.wantPresent {
				t.Fatalf("present = %v, want %v", present, test.wantPresent)
			}
			if got := string(value); got != test.wantValue {
				t.Fatalf("value = %q, want %q", got, test.wantValue)
			}
		})
	}
}

func TestJSONResponseOwnsValidatedBody(t *testing.T) {
	body := []byte(`{"value":"first"}`)
	response, err := newJSONResponse(body)
	if err != nil {
		t.Fatalf("newJSONResponse returned error: %v", err)
	}
	copy(body, []byte(`{"value":"other"}`))

	var decoded struct {
		Value string `json:"value"`
	}
	if err := response.decode(&decoded); err != nil {
		t.Fatalf("decode returned error: %v", err)
	}
	if decoded.Value != "first" {
		t.Fatalf("decoded value = %q, want owned value first", decoded.Value)
	}
}

func TestTransportHeaderHostPreservesSimpleJSONFallbacks(t *testing.T) {
	tests := []struct {
		name string
		body string
		want string
	}{
		{name: "exact Host string", body: `{"Host":"edge.example"}`, want: "edge.example"},
		{name: "lowercase host ignored", body: `{"host":"lower.example"}`},
		{name: "wrong Host type ignored", body: `{"Host":42}`},
		{name: "null Host ignored", body: `{"Host":null}`},
		{name: "array ignored", body: `[]`},
		{name: "null object ignored", body: `null`},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			raw := json.RawMessage(test.body)
			got, err := transportHeaderHost(&raw)
			if err != nil {
				t.Fatalf("transportHeaderHost returned error: %v", err)
			}
			if got != test.want {
				t.Fatalf("host = %q, want %q", got, test.want)
			}
		})
	}
}

func TestSimpleObfsHeaderEncodingRemainsStable(t *testing.T) {
	client := &APIClient{NodeID: 1, NodeType: "Shadowsocks"}
	config := &serverConfig{
		ServerPort: 8388,
		shadowsocks: shadowsocks{
			Plugin:     "simple-obfs",
			PluginOpts: "obfs=http;obfs-host=edge.example;obfs-uri=/edge",
		},
	}

	nodeInfo, err := client.parseSSNodeResponse(config)
	if err != nil {
		t.Fatalf("parseSSNodeResponse returned error: %v", err)
	}
	if got, want := string(nodeInfo.Header), `{"request":{"path":"/edge"},"type":"http"}`; got != want {
		t.Fatalf("header = %s, want %s", got, want)
	}
}

func TestPostXboardReportAcceptsAnyValidJSONResponse(t *testing.T) {
	tests := []string{
		`{"data":true}`,
		`[]`,
		`null`,
		`"ok"`,
		`42`,
		`true`,
	}

	for _, body := range tests {
		t.Run(body, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				w.Header().Set("Content-Type", "application/json")
				_, _ = w.Write([]byte(body))
			}))
			defer server.Close()

			client := New(&api.Config{APIHost: server.URL, Key: "secret", NodeID: 1, NodeType: "V2ray"})
			if err := client.postXboardReport(map[string]any{"type": "status"}); err != nil {
				t.Fatalf("postXboardReport returned error: %v", err)
			}
		})
	}
}

func TestMalformedJSONErrorDoesNotExposeResponseOrToken(t *testing.T) {
	const (
		token        = "panel-token-secret"
		responseBody = "not-json-response-secret"
	)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(responseBody))
	}))
	defer server.Close()

	client := New(&api.Config{
		APIHost:  server.URL,
		Key:      token,
		NodeID:   1,
		NodeType: "V2ray",
	})
	_, err := client.GetUserList()
	if err == nil {
		t.Fatal("GetUserList returned nil error")
	}
	if !strings.Contains(err.Error(), "returned invalid JSON") {
		t.Fatalf("error = %v, want fixed invalid JSON diagnostic", err)
	}
	for _, forbidden := range []string{token, responseBody} {
		if strings.Contains(err.Error(), forbidden) {
			t.Fatalf("error contains sensitive response data %q: %v", forbidden, err)
		}
	}
}

func TestNewV2boardProductionDoesNotImportSimpleJSON(t *testing.T) {
	entries, err := os.ReadDir(".")
	if err != nil {
		t.Fatal(err)
	}

	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".go") || strings.HasSuffix(entry.Name(), "_test.go") {
			continue
		}
		file, err := parser.ParseFile(token.NewFileSet(), entry.Name(), nil, parser.ImportsOnly)
		if err != nil {
			t.Fatalf("parse %s: %v", entry.Name(), err)
		}
		for _, spec := range file.Imports {
			path, err := strconv.Unquote(spec.Path.Value)
			if err != nil {
				t.Fatalf("unquote import %s in %s: %v", spec.Path.Value, entry.Name(), err)
			}
			if path == "github.com/bitly/go-simplejson" {
				t.Fatalf("go-simplejson import escaped V2RaySocks compatibility ownership into %s", entry.Name())
			}
		}
	}
}
