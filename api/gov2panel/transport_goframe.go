package gov2panel

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/Mtoly/XrayRP/api/internal/panelhttp"
	"github.com/gogf/gf/v2/encoding/gjson"
	"github.com/gogf/gf/v2/frame/g"
	"github.com/gogf/gf/v2/net/gclient"
)

const (
	defaultRequestTimeout = 5 * time.Second
)

type panelResponse struct {
	json *gjson.Json
}

func newPanelResponse(body []byte) *panelResponse {
	return &panelResponse{json: gjson.New(body)}
}

func (r *panelResponse) stringAt(path string) string {
	return r.json.Get(path).String()
}

func (r *panelResponse) intAt(path string) int {
	return r.json.Get(path).Int()
}

func (r *panelResponse) scanAt(path string, target any) error {
	return r.json.Get(path).Scan(target)
}

func newGoFrameClient(timeoutSeconds int) *gclient.Client {
	client := gclient.New()
	if timeoutSeconds > 0 {
		client.SetTimeout(time.Duration(timeoutSeconds) * time.Second)
	} else {
		client.SetTimeout(defaultRequestTimeout)
	}
	// The legacy adapter ignored the clone returned by gclient.Retry, so its
	// effective retry count was zero. Preserve that behavior in this batch.
	return client
}

func (c *APIClient) sendRequestContext(
	ctx context.Context,
	headerM map[string]string,
	method string,
	path string,
	data map[string]any,
) (*panelResponse, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}

	requestURL := c.APIHost + path
	client := newGoFrameClient(c.Timeout)
	client.SetHeaderMap(headerM)
	client.SetHeader("Content-Type", "application/json")
	client.SetHeader("Accept-Encoding", "gzip")

	data["token"] = c.Key
	data["node_id"] = c.NodeID

	var (
		response *gclient.Response
		err      error
	)
	switch method {
	case "GET":
		response, err = client.Get(ctx, requestURL, g.Map(data))
	case "POST":
		response, err = client.Post(ctx, requestURL, g.Map(data))
	default:
		return nil, fmt.Errorf("unsupported method: %s", method)
	}
	if err != nil {
		return nil, err
	}
	defer response.Close()

	if response.StatusCode >= 400 {
		return nil, fmt.Errorf("request %s failed: status %d", requestURL, response.StatusCode)
	}
	body, err := panelhttp.ReadEncodedResponseBody(response.Body, response.Header.Get("Content-Encoding"))
	if err != nil {
		return nil, fmt.Errorf("http response read failed: %w", err)
	}
	if !json.Valid(body) {
		return nil, errors.New("http response is not valid JSON")
	}

	result := newPanelResponse(body)
	if result.intAt("code") != 0 {
		return nil, errors.New(result.stringAt("message"))
	}
	return result, nil
}
