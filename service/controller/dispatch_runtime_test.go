package controller

import (
	"context"
	"testing"

	logtest "github.com/sirupsen/logrus/hooks/test"
	"github.com/xtls/xray-core/common/serial"
	"github.com/xtls/xray-core/common/session"
	"github.com/xtls/xray-core/features"
	"github.com/xtls/xray-core/features/outbound"
	"github.com/xtls/xray-core/transport"

	"github.com/Mtoly/XrayRP/api"
)

type fakeOutboundHandler struct {
	tag        string
	dispatched bool
}

func (f *fakeOutboundHandler) Start() error      { return nil }
func (f *fakeOutboundHandler) Close() error      { return nil }
func (f *fakeOutboundHandler) Type() interface{} { return (*fakeOutboundHandler)(nil) }
func (f *fakeOutboundHandler) Tag() string       { return f.tag }
func (f *fakeOutboundHandler) Dispatch(ctx context.Context, link *transport.Link) {
	f.dispatched = true
}
func (f *fakeOutboundHandler) SenderSettings() *serial.TypedMessage { return nil }
func (f *fakeOutboundHandler) ProxySettings() *serial.TypedMessage  { return nil }

var _ outbound.Handler = (*fakeOutboundHandler)(nil)
var _ features.Feature = (*fakeOutboundHandler)(nil)

type fakeOutboundManager struct {
	handlers map[string]outbound.Handler
}

func (m *fakeOutboundManager) Start() error      { return nil }
func (m *fakeOutboundManager) Close() error      { return nil }
func (m *fakeOutboundManager) Type() interface{} { return (*fakeOutboundManager)(nil) }
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

func TestRuntimeRoutingDecisionUsesMatchingManagedInbound(t *testing.T) {
	base := &fakeOutboundHandler{tag: "VLESS_10.0.0.1_443_1"}
	otherBase := &fakeOutboundHandler{tag: "VLESS_10.0.0.1_443_2"}
	otherNode := &dataPathWrapper{Handler: otherBase, tag: otherBase.tag}
	selector := runtimeRoutingSelector{
		baseTag:     base.tag,
		baseHandler: base,
		obm: &fakeOutboundManager{handlers: map[string]outbound.Handler{
			otherNode.tag: otherNode,
		}},
	}
	ctx := session.ContextWithInbound(context.Background(), &session.Inbound{Tag: otherNode.tag})

	decision := selector.selectDispatch(ctx)
	if decision.rejectReason != "" {
		t.Fatalf("expected managed inbound routing decision, got rejection %q", decision.rejectReason)
	}
	if decision.handler != otherNode || !decision.managedHandoff {
		t.Fatalf("expected matching managed wrapper handoff, got %#v", decision)
	}
}

func TestRuntimeRoutingDecisionRejectsRawManagedHandler(t *testing.T) {
	base := &fakeOutboundHandler{tag: "VLESS_10.0.0.1_443_1"}
	rawManaged := &fakeOutboundHandler{tag: "VLESS_10.0.0.1_443_2"}
	selector := runtimeRoutingSelector{
		baseTag:     base.tag,
		baseHandler: base,
		obm: &fakeOutboundManager{handlers: map[string]outbound.Handler{
			rawManaged.tag: rawManaged,
		}},
	}
	ctx := session.ContextWithInbound(context.Background(), &session.Inbound{Tag: rawManaged.tag})

	decision := selector.selectDispatch(ctx)
	if decision.handler != nil || decision.rejectReason == "" {
		t.Fatalf("expected raw managed handler rejection, got %#v", decision)
	}
}

func TestRuntimeRoutingDecisionRejectsCurrentWrapperHandoff(t *testing.T) {
	base := &fakeOutboundHandler{tag: "VLESS_10.0.0.1_443_1"}
	current := &dataPathWrapper{Handler: base, tag: base.tag}
	requestedTag := "VLESS_10.0.0.1_443_2"
	selector := runtimeRoutingSelector{
		baseTag:        base.tag,
		baseHandler:    base,
		currentWrapper: current,
		obm: &fakeOutboundManager{handlers: map[string]outbound.Handler{
			requestedTag: current,
		}},
	}
	ctx := session.ContextWithInbound(context.Background(), &session.Inbound{Tag: requestedTag})

	decision := selector.selectDispatch(ctx)
	if decision.handler != nil || decision.rejectReason == "" {
		t.Fatalf("expected recursive handoff rejection, got %#v", decision)
	}
}

func TestRuntimeRoutingDecisionRejectsMissingManagedInbound(t *testing.T) {
	base := &fakeOutboundHandler{tag: "VLESS_10.0.0.1_443_1"}
	selector := runtimeRoutingSelector{
		baseTag:     base.tag,
		baseHandler: base,
		obm:         &fakeOutboundManager{handlers: map[string]outbound.Handler{}},
	}
	ctx := session.ContextWithInbound(context.Background(), &session.Inbound{Tag: "VLESS_10.0.0.1_443_2"})

	decision := selector.selectDispatch(ctx)
	if decision.handler != nil {
		t.Fatalf("expected missing managed inbound to reject, got %s", decision.handler.Tag())
	}
	if decision.rejectReason == "" {
		t.Fatal("expected explicit managed inbound rejection reason")
	}
}

func TestRuntimeRoutingDecisionFallsBackToPolicyForMatchingInbound(t *testing.T) {
	base := &fakeOutboundHandler{tag: "VLESS_10.0.0.1_443_1"}
	direct := &fakeOutboundHandler{tag: "direct"}
	selector := runtimeRoutingSelector{
		baseTag:     base.tag,
		baseHandler: base,
		obm: &fakeOutboundManager{handlers: map[string]outbound.Handler{
			"direct": direct,
		}},
		routePolicy: &api.PanelRoutePolicy{Outbound: api.OutboundFilterPolicy{
			Candidates: []string{"missing", "direct"},
		}},
	}
	ctx := session.ContextWithInbound(context.Background(), &session.Inbound{Tag: base.tag})

	decision := selector.selectDispatch(ctx)
	if decision.rejectReason != "" {
		t.Fatalf("expected policy routing decision, got rejection %q", decision.rejectReason)
	}
	if decision.handler != direct {
		t.Fatalf("expected direct policy handler, got %#v", decision.handler)
	}
}

func TestRuntimeRoutingSelectorUsesDirectHandlerFromOutboundManager(t *testing.T) {
	base := &fakeOutboundHandler{tag: "proxy-node"}
	direct := &fakeOutboundHandler{tag: "direct"}
	selector := runtimeRoutingSelector{
		baseTag:     "proxy-node",
		baseHandler: base,
		obm: &fakeOutboundManager{handlers: map[string]outbound.Handler{
			"direct": direct,
		}},
		routePolicy: &api.PanelRoutePolicy{
			Outbound: api.OutboundFilterPolicy{
				Candidates: []string{"test-dead", "direct"},
				Include:    []string{"hk-"},
				Exclude:    []string{"dead"},
				Fallback:   []string{"direct"},
			},
		},
	}

	handler, err := selector.selectHandler(context.Background())
	if err != nil {
		t.Fatalf("selectHandler returned error: %v", err)
	}
	if handler != direct {
		t.Fatalf("expected selector to return outbound manager direct handler, got %s", handler.Tag())
	}
}

func TestRuntimeRoutingSelectorRejectsOtherManagedNodeTag(t *testing.T) {
	base := &fakeOutboundHandler{tag: "VLESS_10.0.0.1_443_1"}
	otherNode := &fakeOutboundHandler{tag: "VLESS_10.0.0.1_443_2"}
	selector := runtimeRoutingSelector{
		baseTag:     "VLESS_10.0.0.1_443_1",
		baseHandler: base,
		obm: &fakeOutboundManager{handlers: map[string]outbound.Handler{
			"VLESS_10.0.0.1_443_2": otherNode,
		}},
		routePolicy: &api.PanelRoutePolicy{
			Outbound: api.OutboundFilterPolicy{
				Candidates: []string{"VLESS_10.0.0.1_443_2"},
			},
		},
	}

	_, err := selector.selectHandler(context.Background())
	if err == nil {
		t.Fatal("expected selector to reject another XrayR-managed node tag")
	}
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
