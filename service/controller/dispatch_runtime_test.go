package controller

import (
	"context"
	"testing"

	logtest "github.com/sirupsen/logrus/hooks/test"
	"github.com/xtls/xray-core/common/serial"
	"github.com/xtls/xray-core/features"
	"github.com/xtls/xray-core/features/outbound"
	"github.com/xtls/xray-core/transport"

	"github.com/Mtoly/XrayRP/api"
)

type fakeOutboundHandler struct {
	tag        string
	dispatched bool
}

func (f *fakeOutboundHandler) Start() error                                      { return nil }
func (f *fakeOutboundHandler) Close() error                                      { return nil }
func (f *fakeOutboundHandler) Type() interface{}                                 { return (*fakeOutboundHandler)(nil) }
func (f *fakeOutboundHandler) Tag() string                                       { return f.tag }
func (f *fakeOutboundHandler) Dispatch(ctx context.Context, link *transport.Link) { f.dispatched = true }
func (f *fakeOutboundHandler) SenderSettings() *serial.TypedMessage              { return nil }
func (f *fakeOutboundHandler) ProxySettings() *serial.TypedMessage               { return nil }

var _ outbound.Handler = (*fakeOutboundHandler)(nil)
var _ features.Feature = (*fakeOutboundHandler)(nil)

type fakeOutboundManager struct {
	handlers map[string]outbound.Handler
}

func (m *fakeOutboundManager) Start() error                     { return nil }
func (m *fakeOutboundManager) Close() error                     { return nil }
func (m *fakeOutboundManager) Type() interface{}                { return (*fakeOutboundManager)(nil) }
func (m *fakeOutboundManager) GetHandler(tag string) outbound.Handler {
	if m.handlers == nil {
		return nil
	}
	return m.handlers[tag]
}
func (m *fakeOutboundManager) GetDefaultHandler() outbound.Handler { return nil }
func (m *fakeOutboundManager) AddHandler(ctx context.Context, handler outbound.Handler) error {
	if m.handlers == nil {
		m.handlers = map[string]outbound.Handler{}
	}
	m.handlers[handler.Tag()] = handler
	return nil
}
func (m *fakeOutboundManager) RemoveHandler(ctx context.Context, tag string) error {
	delete(m.handlers, tag)
	return nil
}
func (m *fakeOutboundManager) ListHandlers(ctx context.Context) []outbound.Handler {
	result := make([]outbound.Handler, 0, len(m.handlers))
	for _, h := range m.handlers {
		result = append(result, h)
	}
	return result
}

func TestSelectDispatchHandlerUsesFallbackHandler(t *testing.T) {
	base := &fakeOutboundHandler{tag: "proxy-node"}
	direct := &fakeOutboundHandler{tag: "direct"}
	mgr := &fakeOutboundManager{handlers: map[string]outbound.Handler{
		"direct": direct,
	}}
	logger, _ := logtest.NewNullLogger()
	wrapper := &dataPathWrapper{
		Handler: base,
		tag:     "proxy-node",
		obm:     mgr,
		logger:  logger.WithField("test", "fallback"),
		routePolicy: &api.PanelRoutePolicy{
			Outbound: api.OutboundFilterPolicy{
				Candidates: []string{"test-dead", "direct"},
				Include:    []string{"hk-"},
				Exclude:    []string{"dead"},
				Fallback:   []string{"direct"},
			},
		},
	}

	handler, err := wrapper.selectDispatchHandler(context.Background())
	if err != nil {
		t.Fatalf("selectDispatchHandler returned error: %v", err)
	}
	if handler.Tag() != "direct" {
		t.Fatalf("expected direct handler, got %s", handler.Tag())
	}
}

func TestSelectDispatchHandlerFailsWhenNoHandlerAvailable(t *testing.T) {
	base := &fakeOutboundHandler{tag: "proxy-node"}
	mgr := &fakeOutboundManager{handlers: map[string]outbound.Handler{}}
	logger, _ := logtest.NewNullLogger()
	wrapper := &dataPathWrapper{
		Handler: base,
		tag:     "proxy-node",
		obm:     mgr,
		logger:  logger.WithField("test", "missing-handler"),
		routePolicy: &api.PanelRoutePolicy{
			Outbound: api.OutboundFilterPolicy{
				Candidates: []string{"missing-tag"},
				Include:    []string{"missing"},
			},
		},
	}

	_, err := wrapper.selectDispatchHandler(context.Background())
	if err == nil {
		t.Fatal("expected missing handler error")
	}
}

func TestSelectDispatchHandlerReturnsPolicySelectionError(t *testing.T) {
	base := &fakeOutboundHandler{tag: "proxy-node"}
	mgr := &fakeOutboundManager{handlers: map[string]outbound.Handler{}}
	logger, _ := logtest.NewNullLogger()
	wrapper := &dataPathWrapper{
		Handler: base,
		tag:     "proxy-node",
		obm:     mgr,
		logger:  logger.WithField("test", "policy-error"),
		routePolicy: &api.PanelRoutePolicy{
			Outbound: api.OutboundFilterPolicy{
				Candidates: []string{"test-dead"},
				Include:    []string{"hk-"},
				Exclude:    []string{"dead"},
				Fallback:   []string{"direct"},
			},
		},
	}

	_, err := wrapper.selectDispatchHandler(context.Background())
	if err == nil {
		t.Fatal("expected outbound selection error")
	}
}
