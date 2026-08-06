package panel

import (
	"errors"
	"net"
	"net/url"
	"strings"
)

var ErrRemotePanelRequiresHTTPS = errors.New("remote panel API host must use HTTPS")

func validatePanelAPIHost(raw string) error {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return nil
	}

	parsed, err := url.Parse(raw)
	if err != nil || !parsed.IsAbs() || parsed.Host == "" {
		return errors.New("panel API host must be an absolute HTTP or HTTPS URL")
	}

	switch strings.ToLower(parsed.Scheme) {
	case "https":
		return nil
	case "http":
		if isLoopbackHostname(parsed.Hostname()) {
			return nil
		}
		return ErrRemotePanelRequiresHTTPS
	default:
		return errors.New("panel API host must use HTTP or HTTPS")
	}
}

func isLoopbackHostname(host string) bool {
	host = strings.TrimSuffix(strings.ToLower(strings.TrimSpace(host)), ".")
	if host == "localhost" || strings.HasSuffix(host, ".localhost") {
		return true
	}
	address := net.ParseIP(host)
	return address != nil && address.IsLoopback()
}
