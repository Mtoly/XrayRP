package common

import (
	"os"
	"strings"
	"sync/atomic"
)

const ShowErrorDetailsEnv = "XRAYR_SHOW_ERROR_DETAILS"

var showErrorDetails atomic.Bool

func init() {
	showErrorDetails.Store(parseShowErrorDetails(os.Getenv(ShowErrorDetailsEnv)))
}

func SetShowErrorDetails(enabled bool) {
	showErrorDetails.Store(enabled || parseShowErrorDetails(os.Getenv(ShowErrorDetailsEnv)))
}

func ShowErrorDetails() bool {
	return showErrorDetails.Load()
}

func parseShowErrorDetails(value string) bool {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "1", "t", "true", "y", "yes", "on":
		return true
	default:
		return false
	}
}
