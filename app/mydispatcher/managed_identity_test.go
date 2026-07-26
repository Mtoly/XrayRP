package mydispatcher

import (
	"context"
	"testing"

	xraynet "github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/serial"
	"github.com/xtls/xray-core/common/session"
	"github.com/xtls/xray-core/features"
	"github.com/xtls/xray-core/features/outbound"
	"github.com/xtls/xray-core/transport"

	"github.com/Mtoly/XrayRP/internal/managednode"
)

type managedIdentityTestHandler struct {
	tag        string
	dispatched bool
}

func (*managedIdentityTestHandler) Start() error      { return nil }
func (*managedIdentityTestHandler) Close() error      { return nil }
func (*managedIdentityTestHandler) Type() interface{} { return (*managedIdentityTestHandler)(nil) }
func (h *managedIdentityTestHandler) Tag() string     { return h.tag }
func (h *managedIdentityTestHandler) Dispatch(context.Context, *transport.Link) {
	h.dispatched = true
}
func (*managedIdentityTestHandler) SenderSettings() *serial.TypedMessage { return nil }
func (*managedIdentityTestHandler) ProxySettings() *serial.TypedMessage  { return nil }

var _ outbound.Handler = (*managedIdentityTestHandler)(nil)
var _ features.Feature = (*managedIdentityTestHandler)(nil)

type managedIdentityTestManager struct {
	handlers map[string]outbound.Handler
}

func (*managedIdentityTestManager) Start() error      { return nil }
func (*managedIdentityTestManager) Close() error      { return nil }
func (*managedIdentityTestManager) Type() interface{} { return (*managedIdentityTestManager)(nil) }
func (m *managedIdentityTestManager) GetHandler(tag string) outbound.Handler {
	return m.handlers[tag]
}
func (*managedIdentityTestManager) GetDefaultHandler() outbound.Handler { return nil }
func (m *managedIdentityTestManager) AddHandler(_ context.Context, handler outbound.Handler) error {
	if m.handlers == nil {
		m.handlers = make(map[string]outbound.Handler)
	}
	m.handlers[handler.Tag()] = handler
	return nil
}
func (m *managedIdentityTestManager) RemoveHandler(_ context.Context, tag string) error {
	delete(m.handlers, tag)
	return nil
}
func (m *managedIdentityTestManager) ListHandlers(context.Context) []outbound.Handler {
	handlers := make([]outbound.Handler, 0, len(m.handlers))
	for _, handler := range m.handlers {
		handlers = append(handlers, handler)
	}
	return handlers
}

func TestDispatcherRecognizesEveryManagedNodeTag(t *testing.T) {
	tags := []string{
		"VLESS_127.0.0.1_443_1",
		"Trojan_127.0.0.1_443_1",
		"Vmess_127.0.0.1_443_1",
		"Shadowsocks_127.0.0.1_443_1",
		"Socks_127.0.0.1_443_1",
		"HTTP_127.0.0.1_443_1",
	}

	for _, tag := range tags {
		t.Run(tag, func(t *testing.T) {
			if !managednode.IsTag(tag) {
				t.Fatalf("managednode.IsTag(%q) = false, want true", tag)
			}
		})
	}
}

func TestDispatcherRoutesSocksAndHTTPToMatchingManagedNode(t *testing.T) {
	tags := []string{
		"Socks_127.0.0.1_1080_1",
		"HTTP_127.0.0.1_8080_1",
	}

	for _, tag := range tags {
		t.Run(tag, func(t *testing.T) {
			managed := &managedIdentityTestHandler{tag: tag}
			forced := &managedIdentityTestHandler{tag: "direct"}
			dispatcher := &DefaultDispatcher{
				ohm: &managedIdentityTestManager{handlers: map[string]outbound.Handler{
					tag:      managed,
					"direct": forced,
				}},
			}
			ctx := session.ContextWithInbound(context.Background(), &session.Inbound{Tag: tag})
			ctx = session.ContextWithOutbounds(ctx, []*session.Outbound{{}})
			ctx = session.SetForcedOutboundTagToContext(ctx, "direct")

			dispatcher.routedDispatch(ctx, &transport.Link{}, xraynet.Destination{})

			if !managed.dispatched {
				t.Fatalf("managed tag %q did not use its matching outbound", tag)
			}
			if forced.dispatched {
				t.Fatalf("managed tag %q incorrectly used the forced outbound", tag)
			}
		})
	}
}

func TestDispatcherRejectsMalformedManagedNodeLookalikes(t *testing.T) {
	tags := []string{
		"VLESS_",
		"VLESS_127.0.0.1_bad_1",
		"VLESS_127.0.0.1_443_bad",
		"VLESS_127.0.0.1_443_1_extra",
		"VLESSish_127.0.0.1_443_1",
		"vless_127.0.0.1_443_1",
	}

	for _, tag := range tags {
		t.Run(tag, func(t *testing.T) {
			if managednode.IsTag(tag) {
				t.Fatalf("managednode.IsTag(%q) = true, want false", tag)
			}
		})
	}
}
