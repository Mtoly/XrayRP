package controller

import (
	"context"
	"errors"
	"testing"

	"github.com/xtls/xray-core/common/serial"
	"github.com/xtls/xray-core/features/inbound"
	"github.com/xtls/xray-core/features/outbound"

	"github.com/Mtoly/XrayRP/api"
)

// managedFakeOutboundHandler marks a fake handler as controller-owned so the
// default-promotion filter treats it differently from custom outbounds.
type managedFakeOutboundHandler struct {
	fakeOutboundHandler
}

func (*managedFakeOutboundHandler) isManagedDataPathWrapper() {}

type promotingFakeOutboundManager struct {
	handlers    map[string]outbound.Handler
	defaultTag  string
	addFailures map[string]int
}

func (m *promotingFakeOutboundManager) Start() error { return nil }
func (m *promotingFakeOutboundManager) Close() error { return nil }
func (m *promotingFakeOutboundManager) Type() interface{} {
	return (*promotingFakeOutboundManager)(nil)
}

func (m *promotingFakeOutboundManager) GetHandler(tag string) outbound.Handler {
	return m.handlers[tag]
}

func (m *promotingFakeOutboundManager) GetDefaultHandler() outbound.Handler {
	if m.defaultTag == "" {
		return nil
	}
	return m.handlers[m.defaultTag]
}

func (m *promotingFakeOutboundManager) AddHandler(_ context.Context, handler outbound.Handler) error {
	tag := handler.Tag()
	if m.addFailures[tag] > 0 {
		m.addFailures[tag]--
		return errors.New("injected add failure")
	}
	if _, exists := m.handlers[tag]; exists {
		return errors.New("existing tag found: " + tag)
	}
	m.handlers[tag] = handler
	if m.defaultTag == "" {
		m.defaultTag = tag
	}
	return nil
}

func (m *promotingFakeOutboundManager) RemoveHandler(_ context.Context, tag string) error {
	delete(m.handlers, tag)
	if m.defaultTag == tag {
		m.defaultTag = ""
	}
	return nil
}

func (m *promotingFakeOutboundManager) ListHandlers(context.Context) []outbound.Handler {
	handlers := make([]outbound.Handler, 0, len(m.handlers))
	for _, handler := range m.handlers {
		handlers = append(handlers, handler)
	}
	return handlers
}

type fakeInboundHandler struct {
	tag string
}

func (*fakeInboundHandler) Start() error                           { return nil }
func (*fakeInboundHandler) Close() error                           { return nil }
func (h *fakeInboundHandler) Tag() string                          { return h.tag }
func (*fakeInboundHandler) ReceiverSettings() *serial.TypedMessage { return nil }
func (*fakeInboundHandler) ProxySettings() *serial.TypedMessage    { return nil }

var _ inbound.Handler = (*fakeInboundHandler)(nil)

type promotingFakeInboundManager struct {
	handlers    map[string]inbound.Handler
	getCalls    int
	vanishAfter int
}

func (m *promotingFakeInboundManager) Start() error      { return nil }
func (m *promotingFakeInboundManager) Close() error      { return nil }
func (m *promotingFakeInboundManager) Type() interface{} { return (*promotingFakeInboundManager)(nil) }

func (m *promotingFakeInboundManager) GetHandler(_ context.Context, tag string) (inbound.Handler, error) {
	m.getCalls++
	if m.vanishAfter > 0 && m.getCalls > m.vanishAfter {
		return nil, errors.New("no such inbound: " + tag)
	}
	if handler, ok := m.handlers[tag]; ok {
		return handler, nil
	}
	return nil, errors.New("no such inbound: " + tag)
}

func (m *promotingFakeInboundManager) AddHandler(_ context.Context, handler inbound.Handler) error {
	m.handlers[handler.Tag()] = handler
	return nil
}

func (m *promotingFakeInboundManager) RemoveHandler(_ context.Context, tag string) error {
	delete(m.handlers, tag)
	return nil
}

func (m *promotingFakeInboundManager) ListHandlers(context.Context) []inbound.Handler {
	handlers := make([]inbound.Handler, 0, len(m.handlers))
	for _, handler := range m.handlers {
		handlers = append(handlers, handler)
	}
	return handlers
}

// newPromotingTestController wires the controller fields the lifecycle cleanup
// path needs. Each tag in liveInbounds simulates a running managed inbound.
func newPromotingTestController(manager *promotingFakeOutboundManager, liveInbounds ...string) *Controller {
	handlers := make(map[string]inbound.Handler, len(liveInbounds))
	for _, tag := range liveInbounds {
		handlers[tag] = &fakeInboundHandler{tag: tag}
	}
	return &Controller{obm: manager, ibm: &promotingFakeInboundManager{handlers: handlers}}
}

// TestPromoteManagedDefaultOutboundSkipsCustomHandlers verifies that custom
// outbounds are never promoted, even when their tag sorts first.
func TestPromoteManagedDefaultOutboundSkipsCustomHandlers(t *testing.T) {
	custom := &fakeOutboundHandler{tag: "aaa-custom"}
	managed := &managedFakeOutboundHandler{fakeOutboundHandler{tag: "zzz-managed"}}
	manager := &promotingFakeOutboundManager{handlers: map[string]outbound.Handler{
		custom.Tag():  custom,
		managed.Tag(): managed,
	}}
	apply := nodeRuntimeStateApplyModule{controller: newPromotingTestController(manager, managed.Tag())}

	if err := apply.promoteManagedDefaultOutbound("closed-owner"); err != nil {
		t.Fatalf("promote default: %v", err)
	}
	if manager.defaultTag != managed.Tag() {
		t.Fatalf("default outbound = %q, want managed %q (custom handler must not be promoted)", manager.defaultTag, managed.Tag())
	}
	if manager.GetHandler(custom.Tag()) == nil {
		t.Fatalf("custom outbound %q was removed during promotion", custom.Tag())
	}
}

// TestPromoteManagedDefaultOutboundRestoresCandidateWhenAddFails verifies the
// promotion rollback: a failed re-add leaves the candidate registered and the
// caller sees the error.
func TestPromoteManagedDefaultOutboundRestoresCandidateWhenAddFails(t *testing.T) {
	managed := &managedFakeOutboundHandler{fakeOutboundHandler{tag: "only-managed"}}
	manager := &promotingFakeOutboundManager{
		handlers:    map[string]outbound.Handler{managed.Tag(): managed},
		addFailures: map[string]int{managed.Tag(): 1},
	}
	apply := nodeRuntimeStateApplyModule{controller: newPromotingTestController(manager, managed.Tag())}

	err := apply.promoteManagedDefaultOutbound("closed-owner")
	if err == nil {
		t.Fatalf("promote default unexpectedly succeeded")
	}
	if manager.GetHandler(managed.Tag()) == nil {
		t.Fatalf("candidate %q was lost after failed promotion", managed.Tag())
	}
	if manager.GetDefaultHandler() == nil {
		t.Fatalf("default outbound is missing after the restored candidate was re-added")
	}
}

// TestLifecycleCleanupPromotesDefaultDespiteCleanupError verifies the shutdown
// path keeps remaining nodes reachable even when another cleanup step fails
// after the owner outbound was removed.
func TestLifecycleCleanupPromotesDefaultDespiteCleanupError(t *testing.T) {
	owner := &managedFakeOutboundHandler{fakeOutboundHandler{tag: "closed-owner"}}
	managed := &managedFakeOutboundHandler{fakeOutboundHandler{tag: "remaining-node"}}
	manager := &promotingFakeOutboundManager{
		handlers: map[string]outbound.Handler{
			owner.Tag():   owner,
			managed.Tag(): managed,
		},
		defaultTag: owner.Tag(),
	}
	injected := errors.New("injected inbound cleanup failure")
	apply := nodeRuntimeStateApplyModule{
		controller: newPromotingTestController(manager, managed.Tag()),
		hooks: syncApplyHooks{runtime: syncApplyRuntimeHooks{
			cleanupTagSnapshot: func(_ *api.NodeSnapshot, tag string) error {
				if err := manager.RemoveHandler(context.Background(), tag); err != nil {
					return err
				}
				return injected
			},
		}},
	}

	err := apply.cleanupRuntimeTagForLifecycle(&api.NodeSnapshot{}, owner.Tag())
	if !errors.Is(err, injected) {
		t.Fatalf("cleanup error = %v, want injected failure", err)
	}
	if manager.defaultTag != managed.Tag() {
		t.Fatalf("default outbound = %q, want remaining managed %q", manager.defaultTag, managed.Tag())
	}
}

// TestLifecycleCleanupDoesNotFillUnrelatedEmptyDefault covers the port-update
// window (or any state) where the default is already empty: closing a
// non-default node must not hand default ownership to another node.
func TestLifecycleCleanupDoesNotFillUnrelatedEmptyDefault(t *testing.T) {
	managed := &managedFakeOutboundHandler{fakeOutboundHandler{tag: "remaining-node"}}
	manager := &promotingFakeOutboundManager{handlers: map[string]outbound.Handler{
		managed.Tag(): managed,
	}}
	apply := nodeRuntimeStateApplyModule{
		controller: newPromotingTestController(manager, managed.Tag()),
		hooks: syncApplyHooks{runtime: syncApplyRuntimeHooks{
			cleanupTagSnapshot: func(*api.NodeSnapshot, string) error { return nil },
		}},
	}

	if err := apply.cleanupRuntimeTagForLifecycle(&api.NodeSnapshot{}, "closed-non-default"); err != nil {
		t.Fatalf("cleanup runtime: %v", err)
	}
	if manager.defaultTag != "" {
		t.Fatalf("default outbound = %q, want no default when the closed node did not own it", manager.defaultTag)
	}
	if manager.GetHandler(managed.Tag()) == nil {
		t.Fatalf("untouched managed outbound %q was removed", managed.Tag())
	}
}

// TestPromoteManagedDefaultOutboundSkipsNodeAlreadyClosing verifies that an
// outbound whose controller already removed its inbound is not revived.
func TestPromoteManagedDefaultOutboundSkipsNodeAlreadyClosing(t *testing.T) {
	managed := &managedFakeOutboundHandler{fakeOutboundHandler{tag: "closing-node"}}
	manager := &promotingFakeOutboundManager{handlers: map[string]outbound.Handler{
		managed.Tag(): managed,
	}}
	apply := nodeRuntimeStateApplyModule{controller: newPromotingTestController(manager)}

	if err := apply.promoteManagedDefaultOutbound("closed-owner"); err != nil {
		t.Fatalf("promote default: %v", err)
	}
	if manager.defaultTag != "" {
		t.Fatalf("default outbound = %q, want no default while every candidate is closing", manager.defaultTag)
	}
	if manager.GetHandler(managed.Tag()) == nil {
		t.Fatalf("closing outbound %q was removed but should have been left untouched", managed.Tag())
	}
}

// TestPromoteManagedDefaultOutboundRollsBackNodeClosingDuringPromotion covers
// the interleaving where the candidate's inbound disappears between selection
// and re-add: the re-added outbound must be removed again, not resurrected.
func TestPromoteManagedDefaultOutboundRollsBackNodeClosingDuringPromotion(t *testing.T) {
	managed := &managedFakeOutboundHandler{fakeOutboundHandler{tag: "vanish-during-promotion"}}
	manager := &promotingFakeOutboundManager{handlers: map[string]outbound.Handler{
		managed.Tag(): managed,
	}}
	inboundManager := &promotingFakeInboundManager{
		handlers:    map[string]inbound.Handler{managed.Tag(): &fakeInboundHandler{tag: managed.Tag()}},
		vanishAfter: 1,
	}
	apply := nodeRuntimeStateApplyModule{controller: &Controller{obm: manager, ibm: inboundManager}}

	if err := apply.promoteManagedDefaultOutbound("closed-owner"); err != nil {
		t.Fatalf("promote default: %v", err)
	}
	if manager.defaultTag != "" {
		t.Fatalf("default outbound = %q after the candidate vanished, want no default", manager.defaultTag)
	}
	if manager.GetHandler(managed.Tag()) != nil {
		t.Fatalf("outbound %q was resurrected after its controller closed", managed.Tag())
	}
}
