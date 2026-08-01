package buildinfo

import (
	"strings"
	"testing"

	"golang.org/x/mod/semver"
)

func TestResolveInjectedReleaseMetadata(t *testing.T) {
	const commit = "0123456789abcdef0123456789abcdef01234567"

	info := resolve(
		"v1.2.3-rc.4",
		commit,
		"2026-07-30T12:34:56+08:00",
		"false",
		map[string]string{
			"vcs.revision": "ffffffffffffffffffffffffffffffffffffffff",
			"vcs.modified": "true",
		},
	)

	if info.Version != "1.2.3-rc.4" {
		t.Fatalf("Version = %q, want 1.2.3-rc.4", info.Version)
	}
	if info.Tag != "v1.2.3-rc.4" || info.Commit != commit {
		t.Fatalf("source identity = tag %q commit %q", info.Tag, info.Commit)
	}
	if info.BuildTime != "2026-07-30T04:34:56Z" {
		t.Fatalf("BuildTime = %q, want UTC timestamp", info.BuildTime)
	}
	if info.Dirty != "false" {
		t.Fatalf("Dirty = %q, want false", info.Dirty)
	}
}

func TestResolveDevelopmentMetadataFromGoVCSSettings(t *testing.T) {
	const commit = "fedcba9876543210fedcba9876543210fedcba98"

	info := resolve("", "", "", "", map[string]string{
		"vcs.revision": commit,
		"vcs.modified": "true",
	})

	if info.Version != "0.0.0-dev+gfedcba987654.dirty" {
		t.Fatalf("Version = %q, want traceable development version", info.Version)
	}
	if info.Tag != unknownValue || info.Commit != commit || info.Dirty != "true" {
		t.Fatalf("development identity = %#v", info)
	}
	if !semver.IsValid("v" + info.Version) {
		t.Fatalf("development version %q is not SemVer", info.Version)
	}
}

func TestResolveRejectsInvalidInjectedValues(t *testing.T) {
	info := resolve(
		"v1.2",
		"not-a-commit",
		"not-a-time",
		"maybe",
		nil,
	)

	if info.Version != developmentVersion {
		t.Fatalf("Version = %q, want %q", info.Version, developmentVersion)
	}
	if info.Tag != unknownValue || info.Commit != unknownValue ||
		info.BuildTime != unknownValue || info.Dirty != unknownValue {
		t.Fatalf("invalid values were published: %#v", info)
	}
}

func TestInfoStringIncludesTraceabilityFields(t *testing.T) {
	text := (Info{
		Product:   Product,
		Version:   "1.2.3",
		Tag:       "v1.2.3",
		Commit:    "0123456789abcdef0123456789abcdef01234567",
		BuildTime: "2026-07-30T00:00:00Z",
		Dirty:     "false",
		GoVersion: "go1.26.5",
	}).String()

	for _, value := range []string{
		"XrayR 1.2.3",
		"tag: v1.2.3",
		"commit: 0123456789abcdef0123456789abcdef01234567",
		"build_time: 2026-07-30T00:00:00Z",
		"dirty: false",
		"go: go1.26.5",
	} {
		if !strings.Contains(text, value) {
			t.Fatalf("version text missing %q:\n%s", value, text)
		}
	}
}
