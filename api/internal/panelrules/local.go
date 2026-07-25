// Package panelrules loads panel-neutral local detection rules.
package panelrules

import (
	"bufio"
	"fmt"
	"os"

	"github.com/Mtoly/XrayRP/api"
	"github.com/Mtoly/XrayRP/common"
)

// DiagnosticKind identifies a non-fatal local rule loading problem.
type DiagnosticKind uint8

const (
	DiagnosticOpen DiagnosticKind = iota + 1
	DiagnosticInvalidRegex
	DiagnosticScan
)

// Diagnostic preserves a loading problem for the adapter's logging policy.
type Diagnostic struct {
	Kind DiagnosticKind
	Err  error
}

func (d Diagnostic) Error() string {
	switch d.Kind {
	case DiagnosticOpen:
		return fmt.Sprintf("Error when opening file: %s", d.Err)
	case DiagnosticInvalidRegex:
		return fmt.Sprintf("Invalid rule regex: %s, skipping", d.Err)
	case DiagnosticScan:
		return fmt.Sprintf("Error while reading file: %s", d.Err)
	default:
		return fmt.Sprint(d.Err)
	}
}

// Load reads local detection rules while preserving valid prefix results.
func Load(path string) ([]api.DetectRule, []Diagnostic) {
	rules := make([]api.DetectRule, 0)
	if path == "" {
		return rules, nil
	}

	file, err := os.Open(path)
	if err != nil {
		return rules, []Diagnostic{{Kind: DiagnosticOpen, Err: err}}
	}
	defer file.Close()

	var diagnostics []Diagnostic
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		pattern, err := common.SafeCompileRegex(scanner.Text())
		if err != nil {
			diagnostics = append(diagnostics, Diagnostic{
				Kind: DiagnosticInvalidRegex,
				Err:  err,
			})
			continue
		}
		rules = append(rules, api.DetectRule{
			ID:      -1,
			Pattern: pattern,
		})
	}
	if err := scanner.Err(); err != nil {
		diagnostics = append(diagnostics, Diagnostic{
			Kind: DiagnosticScan,
			Err:  err,
		})
	}

	return rules, diagnostics
}
