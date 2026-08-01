package mylego

import (
	"go/parser"
	"go/token"
	"os"
	"strconv"
	"strings"
	"testing"
)

func TestFullDNSRegistryImportRemainsIsolated(t *testing.T) {
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
			if path != "github.com/go-acme/lego/v4/providers/dns" {
				continue
			}
			importCount++
			if entry.Name() != "dns_registry_full.go" {
				t.Fatalf("full DNS registry import escaped dns_registry_full.go into %s", entry.Name())
			}
		}
	}
	if importCount != 1 {
		t.Fatalf("full DNS registry import count = %d, want 1 until an approved support change", importCount)
	}
}
