package panelhttp

import (
	"bytes"
	"compress/gzip"
	"errors"
	"io"
	"net/http"
	"strings"
)

// MaxResponseBodyBytes leaves at least 4x headroom over the conservative
// 5000-user compatibility payload while bounding decompression and decode.
const MaxResponseBodyBytes = 16 << 20

var ErrResponseBodyTooLarge = errors.New("panel response body exceeds 16 MiB limit")

// ReadResponseBody reads an untrusted, already decompressed response stream.
// The caller retains ownership of closing the reader.
func ReadResponseBody(reader io.Reader) ([]byte, error) {
	return readResponseBody(reader, MaxResponseBodyBytes)
}

// ReadEncodedResponseBody bounds the wire representation before decoding and
// applies the same bound again to the decoded representation.
func ReadEncodedResponseBody(reader io.Reader, contentEncoding string) ([]byte, error) {
	raw, err := readResponseBody(reader, MaxResponseBodyBytes)
	if err != nil {
		return nil, err
	}
	if !strings.EqualFold(strings.TrimSpace(contentEncoding), "gzip") {
		return raw, nil
	}

	decoded, err := gzip.NewReader(bytes.NewReader(raw))
	if err != nil {
		return nil, err
	}
	defer decoded.Close()
	return readResponseBody(decoded, MaxResponseBodyBytes)
}

func readResponseBody(reader io.Reader, limit int64) ([]byte, error) {
	if limit < 0 {
		return nil, ErrResponseBodyTooLarge
	}

	limited := &io.LimitedReader{R: reader, N: limit}
	body, err := io.ReadAll(limited)
	if err != nil {
		return nil, err
	}

	extra, err := io.ReadAll(&io.LimitedReader{R: reader, N: 1})
	if len(extra) > 0 {
		if err != nil {
			return nil, errors.Join(ErrResponseBodyTooLarge, err)
		}
		return nil, ErrResponseBodyTooLarge
	}
	if err != nil && !errors.Is(err, io.EOF) {
		return nil, err
	}
	return body, nil
}

type responseLimitTransport struct {
	base  http.RoundTripper
	limit int64
}

func (t responseLimitTransport) RoundTrip(request *http.Request) (*http.Response, error) {
	base := t.base
	if base == nil {
		base = http.DefaultTransport
	}
	response, err := base.RoundTrip(request)
	if response != nil && response.Body != nil {
		response.Body = &responseLimitReadCloser{
			body:      response.Body,
			remaining: t.limit,
		}
	}
	return response, err
}

type responseLimitReadCloser struct {
	body      io.ReadCloser
	remaining int64
}

func (r *responseLimitReadCloser) Read(p []byte) (int, error) {
	if r.remaining < 0 {
		return 0, ErrResponseBodyTooLarge
	}
	if int64(len(p)) > r.remaining+1 {
		p = p[:r.remaining+1]
	}
	n, err := r.body.Read(p)
	r.remaining -= int64(n)
	if r.remaining < 0 {
		if err != nil {
			return n, errors.Join(ErrResponseBodyTooLarge, err)
		}
		return n, ErrResponseBodyTooLarge
	}
	return n, err
}

func (r *responseLimitReadCloser) Close() error {
	return r.body.Close()
}
