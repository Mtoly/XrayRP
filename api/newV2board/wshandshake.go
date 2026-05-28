package newV2board

import (
	"net/http"
	"strings"
)

type wsHandshakeResponse struct {
	WebSocket struct {
		Enabled bool   `json:"enabled"`
		WSURL   string `json:"ws_url"`
	} `json:"websocket"`
}

// DiscoverWSEndpoint asks current Xboard panels for the preferred websocket URL.
// It returns an empty endpoint on unsupported/disabled/malformed handshakes so
// callers can fall back to the legacy UniProxy websocket endpoint.
func (c *APIClient) DiscoverWSEndpoint() (string, error) {
	if c == nil || c.client == nil {
		return "", nil
	}

	var payload wsHandshakeResponse
	res, err := c.client.R().
		SetResult(&payload).
		ForceContentType("application/json").
		Get("/api/v2/server/handshake")
	if err != nil {
		return "", nil
	}
	if res == nil || res.StatusCode() == http.StatusNotFound || res.StatusCode() > 399 {
		return "", nil
	}

	endpoint := strings.TrimSpace(payload.WebSocket.WSURL)
	if !payload.WebSocket.Enabled || endpoint == "" {
		return "", nil
	}
	return endpoint, nil
}
