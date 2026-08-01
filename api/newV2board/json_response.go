package newV2board

import (
	"bytes"
	"encoding/json"
	"fmt"

	"github.com/go-resty/resty/v2"
)

type jsonResponse struct {
	body []byte
}

func newJSONResponse(body []byte) (*jsonResponse, error) {
	if !json.Valid(body) {
		return nil, fmt.Errorf("invalid JSON")
	}
	return &jsonResponse{body: append([]byte(nil), body...)}, nil
}

func (r *jsonResponse) decode(target any) error {
	if r == nil {
		return fmt.Errorf("JSON response is nil")
	}
	return json.Unmarshal(r.body, target)
}

func (r *jsonResponse) field(name string) (json.RawMessage, bool, error) {
	if r == nil {
		return nil, false, fmt.Errorf("JSON response is nil")
	}

	body := bytes.TrimSpace(r.body)
	if len(body) == 0 || body[0] != '{' {
		return nil, false, nil
	}

	fields := make(map[string]json.RawMessage)
	if err := json.Unmarshal(body, &fields); err != nil {
		return nil, false, err
	}
	value, ok := fields[name]
	return value, ok, nil
}

func (c *APIClient) parseResponse(res *resty.Response, path string, err error) (*jsonResponse, error) {
	if err := c.httpPolicy.CheckResponse(res, path, err); err != nil {
		return nil, err
	}

	response, err := newJSONResponse(res.Body())
	if err != nil {
		return nil, fmt.Errorf("request %s returned invalid JSON", c.assembleURL(path))
	}
	return response, nil
}

func transportHeaderHost(headers *json.RawMessage) (string, error) {
	if headers == nil {
		return "", nil
	}

	body, err := headers.MarshalJSON()
	if err != nil {
		return "", err
	}
	response, err := newJSONResponse(body)
	if err != nil {
		return "", err
	}
	value, ok, err := response.field("Host")
	if err != nil || !ok {
		return "", err
	}

	var host string
	if err := json.Unmarshal(value, &host); err != nil {
		return "", nil
	}
	return host, nil
}

type httpObfsHeader struct {
	Request struct {
		Path string `json:"path"`
	} `json:"request"`
	Type string `json:"type"`
}

func marshalHTTPObfsHeader(path string) (json.RawMessage, error) {
	header := httpObfsHeader{Type: "http"}
	header.Request.Path = path
	body, err := json.Marshal(header)
	if err != nil {
		return nil, err
	}
	return json.RawMessage(body), nil
}
