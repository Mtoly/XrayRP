package panelhttp

import (
	"fmt"
	"net/url"
	"sort"
	"strings"
	"time"

	"github.com/go-resty/resty/v2"
	log "github.com/sirupsen/logrus"
)

const (
	defaultTimeout = 5 * time.Second
	retryCount     = 3
	redactedValue  = "[REDACTED]"
)

type ClientConfig struct {
	BaseURL        string
	TimeoutSeconds int
	Credentials    []string
}

type Policy struct {
	baseURL  string
	redactor redactor
}

func NewClient(config ClientConfig) (*resty.Client, Policy) {
	policy := Policy{
		baseURL:  config.BaseURL,
		redactor: newRedactor(config.Credentials),
	}
	logger := redactingLogger{redactor: policy.redactor}
	timeout := defaultTimeout
	if config.TimeoutSeconds > 0 {
		timeout = time.Duration(config.TimeoutSeconds) * time.Second
	}

	client := resty.New().
		SetRetryCount(retryCount).
		SetTimeout(timeout).
		SetDebugBodyLimit(0).
		SetLogger(logger)
	client.OnRequestLog(func(entry *resty.RequestLog) error {
		redactHeaders(entry.Header, policy.redactor)
		return nil
	})
	client.OnResponseLog(func(entry *resty.ResponseLog) error {
		redactHeaders(entry.Header, policy.redactor)
		return nil
	})
	if config.BaseURL != "" {
		client.SetBaseURL(config.BaseURL)
	}

	return client, policy
}

func (p Policy) CheckResponse(res *resty.Response, path string, err error) error {
	requestURL := p.redactor.redact(p.baseURL + path)
	if err != nil {
		return &requestError{
			message: fmt.Sprintf("request %s failed: %s", requestURL, p.redactor.redact(err.Error())),
			cause:   err,
		}
	}
	if res == nil || res.RawResponse == nil {
		return fmt.Errorf("request %s failed: empty response", requestURL)
	}
	if res.StatusCode() >= 400 {
		return fmt.Errorf("request %s failed: status %d", requestURL, res.StatusCode())
	}
	return nil
}

func TypedResult[T any](policy Policy, res *resty.Response, path string, err error) (*T, error) {
	if err := policy.CheckResponse(res, path, err); err != nil {
		return nil, err
	}
	if res.Request == nil {
		return nil, policy.resultError(path)
	}
	result, ok := res.Result().(*T)
	if !ok || result == nil {
		return nil, policy.resultError(path)
	}
	return result, nil
}

func (p Policy) resultError(path string) error {
	return fmt.Errorf("request %s returned an invalid typed result", p.redactor.redact(p.baseURL+path))
}

type requestError struct {
	message string
	cause   error
}

func (e *requestError) Error() string {
	return e.message
}

func (e *requestError) Unwrap() error {
	return e.cause
}

type redactor struct {
	replacer *strings.Replacer
}

func newRedactor(credentials []string) redactor {
	seen := make(map[string]struct{})
	values := make([]string, 0, len(credentials)*4)
	for _, credential := range credentials {
		if credential == "" {
			continue
		}
		for _, value := range []string{
			credential,
			url.QueryEscape(credential),
			strings.ReplaceAll(url.QueryEscape(credential), "+", "%20"),
			url.PathEscape(credential),
		} {
			if value == "" {
				continue
			}
			if _, exists := seen[value]; exists {
				continue
			}
			seen[value] = struct{}{}
			values = append(values, value)
		}
	}
	sort.Slice(values, func(i, j int) bool {
		return len(values[i]) > len(values[j])
	})
	if len(values) == 0 {
		return redactor{}
	}

	replacements := make([]string, 0, len(values)*2)
	for _, value := range values {
		replacements = append(replacements, value, redactedValue)
	}
	return redactor{replacer: strings.NewReplacer(replacements...)}
}

func (r redactor) redact(value string) string {
	if r.replacer == nil {
		return value
	}
	return r.replacer.Replace(value)
}

func redactHeaders(header map[string][]string, redactor redactor) {
	for name, values := range header {
		if isSensitiveHeader(name) {
			header[name] = []string{redactedValue}
			continue
		}
		redactedValues := make([]string, len(values))
		for i, value := range values {
			redactedValues[i] = redactor.redact(value)
		}
		header[name] = redactedValues
	}
}

func isSensitiveHeader(name string) bool {
	name = strings.ToLower(strings.TrimSpace(name))
	switch name {
	case "authorization", "proxy-authorization", "cookie", "set-cookie", "key", "mukey", "token":
		return true
	}
	return strings.HasSuffix(name, "-key") ||
		strings.HasSuffix(name, "-secret") ||
		strings.HasSuffix(name, "-token")
}

type redactingLogger struct {
	redactor redactor
}

func (l redactingLogger) Errorf(format string, values ...interface{}) {
	log.Errorf("%s", l.message("ERROR", format, values...))
}

func (l redactingLogger) Warnf(format string, values ...interface{}) {
	log.Warnf("%s", l.message("WARN", format, values...))
}

func (l redactingLogger) Debugf(format string, values ...interface{}) {
	log.Debugf("%s", l.message("DEBUG", format, values...))
}

func (l redactingLogger) message(level, format string, values ...interface{}) string {
	return fmt.Sprintf("%s RESTY %s", level, l.redactor.redact(fmt.Sprintf(format, values...)))
}
