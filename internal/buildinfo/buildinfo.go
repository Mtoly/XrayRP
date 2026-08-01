package buildinfo

import (
	"fmt"
	"runtime"
	"runtime/debug"
	"strings"
	"time"

	"golang.org/x/mod/semver"
)

const (
	Product            = "XrayR"
	developmentVersion = "0.0.0-dev"
	unknownValue       = "unknown"
)

// These values are set by release builds with -ldflags=-X.
var (
	BuildTag    string
	BuildCommit string
	BuildTime   string
	BuildDirty  string
)

// Info is the immutable source and build identity published by the binary.
type Info struct {
	Product   string `json:"product"`
	Version   string `json:"version"`
	Tag       string `json:"tag"`
	Commit    string `json:"commit"`
	BuildTime string `json:"build_time"`
	Dirty     string `json:"dirty"`
	GoVersion string `json:"go_version"`
}

// Current resolves injected release metadata first and Go VCS settings second.
func Current() Info {
	settings := map[string]string{}
	if info, ok := debug.ReadBuildInfo(); ok {
		for _, setting := range info.Settings {
			settings[setting.Key] = setting.Value
		}
	}
	return resolve(BuildTag, BuildCommit, BuildTime, BuildDirty, settings)
}

// UserAgent returns a credential-free, bounded identifier for panel requests.
func UserAgent() string {
	return Product + "/" + Current().Version
}

// String renders the complete source identity for the version command.
func (i Info) String() string {
	return fmt.Sprintf(
		"%s %s\n"+
			"tag: %s\n"+
			"commit: %s\n"+
			"build_time: %s\n"+
			"dirty: %s\n"+
			"go: %s\n",
		i.Product,
		i.Version,
		i.Tag,
		i.Commit,
		i.BuildTime,
		i.Dirty,
		i.GoVersion,
	)
}

func resolve(tag, commit, buildTime, dirty string, settings map[string]string) Info {
	tag = normalizeTag(tag)
	commit = normalizeCommit(commit)
	if commit == unknownValue {
		commit = normalizeCommit(settings["vcs.revision"])
	}

	dirty = normalizeDirty(dirty)
	if dirty == unknownValue {
		dirty = normalizeDirty(settings["vcs.modified"])
	}

	buildTime = normalizeBuildTime(buildTime)

	return Info{
		Product:   Product,
		Version:   resolveVersion(tag, commit, dirty),
		Tag:       tag,
		Commit:    commit,
		BuildTime: buildTime,
		Dirty:     dirty,
		GoVersion: runtime.Version(),
	}
}

func resolveVersion(tag, commit, dirty string) string {
	if tag != unknownValue {
		return strings.TrimPrefix(tag, "v")
	}

	version := developmentVersion
	if commit != unknownValue {
		shortCommit := commit
		if len(shortCommit) > 12 {
			shortCommit = shortCommit[:12]
		}
		version += "+g" + shortCommit
		if dirty == "true" {
			version += ".dirty"
		}
	}
	return version
}

func normalizeTag(value string) string {
	value = strings.TrimSpace(value)
	if value == "" {
		return unknownValue
	}
	if !strings.HasPrefix(value, "v") {
		value = "v" + value
	}
	if !semver.IsValid(value) || semver.Canonical(value) != value || strings.Contains(value, "+") {
		return unknownValue
	}
	return value
}

func normalizeCommit(value string) string {
	value = strings.ToLower(strings.TrimSpace(value))
	if len(value) != 40 {
		return unknownValue
	}
	for _, char := range value {
		if (char < '0' || char > '9') && (char < 'a' || char > 'f') {
			return unknownValue
		}
	}
	return value
}

func normalizeBuildTime(value string) string {
	value = strings.TrimSpace(value)
	if value == "" {
		return unknownValue
	}
	parsed, err := time.Parse(time.RFC3339, value)
	if err != nil {
		return unknownValue
	}
	return parsed.UTC().Format(time.RFC3339)
}

func normalizeDirty(value string) string {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "true":
		return "true"
	case "false":
		return "false"
	default:
		return unknownValue
	}
}
