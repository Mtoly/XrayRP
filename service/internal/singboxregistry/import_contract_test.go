package singboxregistry

import (
	"go/parser"
	"go/token"
	"io/fs"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

const (
	fullRegistryImport = "github.com/sagernet/sing-box/include"
	registryFacadePath = "github.com/Mtoly/XrayRP/service/internal/singboxregistry"
)

func TestFullRegistryImportRemainsIsolated(t *testing.T) {
	serviceRoot := filepath.Clean(filepath.Join("..", ".."))
	includeOwners := findProductionImportOwners(t, serviceRoot, fullRegistryImport)
	if len(includeOwners) != 1 || includeOwners[0] != filepath.FromSlash("internal/singboxregistry/full.go") {
		t.Fatalf("full sing-box registry import owners = %v, want [internal/singboxregistry/full.go]", includeOwners)
	}

	facadeOwners := findProductionImportOwners(t, serviceRoot, registryFacadePath)
	wantFacadeOwners := []string{
		filepath.FromSlash("anytls/config.go"),
		filepath.FromSlash("tuic/config.go"),
	}
	if strings.Join(facadeOwners, "\n") != strings.Join(wantFacadeOwners, "\n") {
		t.Fatalf("sing-box registry facade owners = %v, want %v", facadeOwners, wantFacadeOwners)
	}
}

func findProductionImportOwners(t *testing.T, root, importPath string) []string {
	t.Helper()
	var owners []string
	err := filepath.WalkDir(root, func(path string, entry fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".go") || strings.HasSuffix(entry.Name(), "_test.go") {
			return nil
		}
		file, err := parser.ParseFile(token.NewFileSet(), path, nil, parser.ImportsOnly)
		if err != nil {
			return err
		}
		for _, spec := range file.Imports {
			value, err := strconv.Unquote(spec.Path.Value)
			if err != nil {
				return err
			}
			if value == importPath {
				relative, err := filepath.Rel(root, path)
				if err != nil {
					return err
				}
				owners = append(owners, relative)
			}
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	return owners
}
