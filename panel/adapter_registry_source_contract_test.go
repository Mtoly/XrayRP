package panel

import (
	"go/ast"
	"go/parser"
	"go/token"
	"io/fs"
	"path"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

const adapterRegistrySource = "panel/adapter_registry.go"

var reviewedAdapterImports = map[string]bool{
	"github.com/Mtoly/XrayRP/api/bunpanel":   true,
	"github.com/Mtoly/XrayRP/api/gov2panel":  true,
	"github.com/Mtoly/XrayRP/api/newV2board": false,
	"github.com/Mtoly/XrayRP/api/pmpanel":    true,
	"github.com/Mtoly/XrayRP/api/proxypanel": true,
	"github.com/Mtoly/XrayRP/api/sspanel":    true,
	"github.com/Mtoly/XrayRP/api/v2raysocks": true,
}

func TestPanelAdapterConstructionRemainsIsolated(t *testing.T) {
	root := filepath.Clean("..")
	constructorCount := make(map[string]int, len(reviewedAdapterImports))
	for _, directory := range []string{"api", "app", "cmd", "common", "internal", "panel", "service", "tools"} {
		walkProductionGoFiles(t, filepath.Join(root, directory), func(filePath string) {
			file, err := parser.ParseFile(token.NewFileSet(), filePath, nil, 0)
			if err != nil {
				t.Fatalf("parse %s: %v", filePath, err)
			}
			relativePath, err := filepath.Rel(root, filePath)
			if err != nil {
				t.Fatal(err)
			}
			relativePath = filepath.ToSlash(relativePath)

			importsByName := make(map[string]string)
			for _, spec := range file.Imports {
				importPath, err := strconv.Unquote(spec.Path.Value)
				if err != nil {
					t.Fatalf("unquote import %s in %s: %v", spec.Path.Value, relativePath, err)
				}
				staticOnly, reviewed := reviewedAdapterImports[importPath]
				if !reviewed {
					continue
				}
				if staticOnly && relativePath != adapterRegistrySource {
					t.Fatalf("static-only adapter import %q escaped registry into %s", importPath, relativePath)
				}
				name := path.Base(importPath)
				if spec.Name != nil {
					name = spec.Name.Name
				}
				importsByName[name] = importPath
			}

			ast.Inspect(file, func(node ast.Node) bool {
				call, ok := node.(*ast.CallExpr)
				if !ok {
					return true
				}
				selector, ok := call.Fun.(*ast.SelectorExpr)
				if !ok || selector.Sel.Name != "New" {
					return true
				}
				identifier, ok := selector.X.(*ast.Ident)
				if !ok {
					return true
				}
				importPath, reviewed := importsByName[identifier.Name]
				if !reviewed {
					return true
				}
				constructorCount[importPath]++
				if relativePath != adapterRegistrySource {
					t.Fatalf("adapter constructor %s.New escaped registry into %s", identifier.Name, relativePath)
				}
				return true
			})
		})
	}

	for importPath := range reviewedAdapterImports {
		if constructorCount[importPath] != 1 {
			t.Fatalf("adapter constructor %q count = %d, want exactly 1 in %s", importPath, constructorCount[importPath], adapterRegistrySource)
		}
	}
}

func walkProductionGoFiles(t *testing.T, root string, visit func(string)) {
	t.Helper()
	if err := filepath.WalkDir(root, func(filePath string, entry fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if entry.IsDir() {
			return nil
		}
		if filepath.Ext(filePath) != ".go" || strings.HasSuffix(filePath, "_test.go") {
			return nil
		}
		visit(filePath)
		return nil
	}); err != nil {
		t.Fatal(err)
	}
}
