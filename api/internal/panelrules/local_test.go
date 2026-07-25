package panelrules

import (
	"bufio"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestDiagnosticErrorPreservesExistingMessages(t *testing.T) {
	sentinel := errors.New("sentinel")
	tests := []struct {
		name string
		kind DiagnosticKind
		want string
	}{
		{
			name: "open",
			kind: DiagnosticOpen,
			want: "Error when opening file: sentinel",
		},
		{
			name: "invalid regex",
			kind: DiagnosticInvalidRegex,
			want: "Invalid rule regex: sentinel, skipping",
		},
		{
			name: "scan",
			kind: DiagnosticScan,
			want: "Error while reading file: sentinel",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := (Diagnostic{Kind: tt.kind, Err: sentinel}).Error(); got != tt.want {
				t.Fatalf("diagnostic = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestLoadEmptyPathReturnsNonNilEmptyRules(t *testing.T) {
	rules, diagnostics := Load("")

	if rules == nil {
		t.Fatal("rules = nil, want non-nil empty slice")
	}
	if len(rules) != 0 {
		t.Fatalf("len(rules) = %d, want 0", len(rules))
	}
	if len(diagnostics) != 0 {
		t.Fatalf("diagnostics = %#v, want none", diagnostics)
	}
}

func TestLoadMissingFileReturnsOpenDiagnostic(t *testing.T) {
	path := filepath.Join(t.TempDir(), "missing-rules.txt")

	rules, diagnostics := Load(path)

	if rules == nil {
		t.Fatal("rules = nil, want non-nil empty slice")
	}
	if len(rules) != 0 {
		t.Fatalf("len(rules) = %d, want 0", len(rules))
	}
	if len(diagnostics) != 1 {
		t.Fatalf("diagnostics = %#v, want one open diagnostic", diagnostics)
	}
	if diagnostics[0].Kind != DiagnosticOpen {
		t.Fatalf("diagnostic kind = %v, want %v", diagnostics[0].Kind, DiagnosticOpen)
	}
	if diagnostics[0].Err == nil {
		t.Fatal("diagnostic error = nil")
	}
	if got := diagnostics[0].Error(); !strings.HasPrefix(got, "Error when opening file: ") {
		t.Fatalf("diagnostic = %q, want existing open-error prefix", got)
	}
}

func TestLoadPreservesLineSemanticsAndOrder(t *testing.T) {
	path := writeRuleFile(t, "first\\.example\r\n\r\n  spaced  \n#not-comment\nsecond\\.example")

	rules, diagnostics := Load(path)

	if len(diagnostics) != 0 {
		t.Fatalf("diagnostics = %#v, want none", diagnostics)
	}
	wantPatterns := []string{
		"first\\.example",
		"",
		"  spaced  ",
		"#not-comment",
		"second\\.example",
	}
	if len(rules) != len(wantPatterns) {
		t.Fatalf("len(rules) = %d, want %d", len(rules), len(wantPatterns))
	}
	for i, want := range wantPatterns {
		if rules[i].ID != -1 {
			t.Fatalf("rules[%d].ID = %d, want -1", i, rules[i].ID)
		}
		if got := rules[i].Pattern.String(); got != want {
			t.Fatalf("rules[%d].Pattern = %q, want %q", i, got, want)
		}
	}
	if !rules[1].Pattern.MatchString("anything") {
		t.Fatal("empty line no longer produces a match-all empty regex")
	}
}

func TestLoadSkipsInvalidRegexAndContinues(t *testing.T) {
	path := writeRuleFile(t, "first\\.example\n[\nsecond\\.example\n")

	rules, diagnostics := Load(path)

	if len(rules) != 2 {
		t.Fatalf("len(rules) = %d, want 2", len(rules))
	}
	if rules[0].Pattern.String() != "first\\.example" || rules[1].Pattern.String() != "second\\.example" {
		t.Fatalf("rules = %#v, want valid rules in file order", rules)
	}
	if len(diagnostics) != 1 {
		t.Fatalf("diagnostics = %#v, want one invalid-regex diagnostic", diagnostics)
	}
	if diagnostics[0].Kind != DiagnosticInvalidRegex {
		t.Fatalf("diagnostic kind = %v, want %v", diagnostics[0].Kind, DiagnosticInvalidRegex)
	}
	if diagnostics[0].Err == nil {
		t.Fatal("diagnostic error = nil")
	}
	got := diagnostics[0].Error()
	if !strings.HasPrefix(got, "Invalid rule regex: ") || !strings.HasSuffix(got, ", skipping") {
		t.Fatalf("diagnostic = %q, want existing invalid-regex message", got)
	}
}

func TestLoadScannerErrorReturnsPartialRules(t *testing.T) {
	content := "first\\.example\n" +
		strings.Repeat("x", bufio.MaxScanTokenSize+1) +
		"\nsecond\\.example\n"
	path := writeRuleFile(t, content)

	rules, diagnostics := Load(path)

	if len(rules) != 1 || rules[0].ID != -1 || rules[0].Pattern.String() != "first\\.example" {
		t.Fatalf("rules = %#v, want valid prefix only", rules)
	}
	if len(diagnostics) != 1 {
		t.Fatalf("diagnostics = %#v, want one scanner diagnostic", diagnostics)
	}
	if diagnostics[0].Kind != DiagnosticScan {
		t.Fatalf("diagnostic kind = %v, want %v", diagnostics[0].Kind, DiagnosticScan)
	}
	if diagnostics[0].Err == nil {
		t.Fatal("diagnostic error = nil")
	}
	if got := diagnostics[0].Error(); !strings.HasPrefix(got, "Error while reading file: ") {
		t.Fatalf("diagnostic = %q, want existing scanner-error prefix", got)
	}
}

func writeRuleFile(t *testing.T, content string) string {
	t.Helper()

	path := filepath.Join(t.TempDir(), "rules.txt")
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}
