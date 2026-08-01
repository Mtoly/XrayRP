package gov2panel

import (
	"go/parser"
	"go/token"
	"os"
	"reflect"
	"strconv"
	"strings"
	"testing"
	"time"
)

func TestPanelResponsePreservesGoFrameAccessSemantics(t *testing.T) {
	response := newPanelResponse([]byte(`{
		"code": "7",
		"data": {
			"name": "node-a",
			"port": "8443"
		},
		"empty": null
	}`))

	if got := response.stringAt("data.name"); got != "node-a" {
		t.Fatalf("data.name = %q, want node-a", got)
	}
	if got := response.stringAt("empty"); got != "" {
		t.Fatalf("empty = %q, want empty string", got)
	}
	if got := response.intAt("code"); got != 7 {
		t.Fatalf("code = %d, want 7", got)
	}
	if got := response.intAt("data.port"); got != 8443 {
		t.Fatalf("data.port = %d, want 8443", got)
	}

	var target struct {
		Name string `json:"name"`
		Port int    `json:"port"`
	}
	if err := response.scanAt("data", &target); err != nil {
		t.Fatalf("scan data: %v", err)
	}
	if target.Name != "node-a" || target.Port != 8443 {
		t.Fatalf("scanned data = %#v", target)
	}
}

func TestGoFrameTransportPolicyRemainsCompatible(t *testing.T) {
	tests := []struct {
		name           string
		timeoutSeconds int
		wantTimeout    time.Duration
	}{
		{name: "default timeout", wantTimeout: 5 * time.Second},
		{name: "configured timeout", timeoutSeconds: 17, wantTimeout: 17 * time.Second},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			client := newGoFrameClient(test.timeoutSeconds)
			if client.Client.Timeout != test.wantTimeout {
				t.Fatalf("timeout = %s, want %s", client.Client.Timeout, test.wantTimeout)
			}

			value := reflect.ValueOf(client).Elem()
			if got := int(value.FieldByName("retryCount").Int()); got != 0 {
				t.Fatalf("retry count = %d, want compatibility value 0", got)
			}
			if got := time.Duration(value.FieldByName("retryInterval").Int()); got != 0 {
				t.Fatalf("retry interval = %s, want compatibility value 0", got)
			}
		})
	}
}

func TestGoFrameImportsRemainInsideTransportBoundary(t *testing.T) {
	entries, err := os.ReadDir(".")
	if err != nil {
		t.Fatal(err)
	}

	importCount := 0
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
			if !strings.HasPrefix(path, "github.com/gogf/gf/v2/") {
				continue
			}
			importCount++
			if entry.Name() != "transport_goframe.go" {
				t.Fatalf("GoFrame import %q escaped transport_goframe.go into %s", path, entry.Name())
			}
		}
	}
	if importCount == 0 {
		t.Fatal("GoFrame transport dependency disappeared without an approved removal")
	}
}
