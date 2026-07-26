package machine

import (
	"errors"
	"reflect"
	"strconv"
	"sync"
	"testing"
	"time"

	"github.com/Mtoly/XrayRP/api/newV2board"
	"github.com/Mtoly/XrayRP/service"
)

type concurrencyDiscoverer struct {
	mu        sync.Mutex
	responses []*newV2board.MachineNodesResponse
}

func (d *concurrencyDiscoverer) DiscoverMachineNodes() (*newV2board.MachineNodesResponse, error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	if len(d.responses) == 0 {
		return machineNodesResponse(), nil
	}
	response := d.responses[0]
	d.responses = d.responses[1:]
	return response, nil
}

type gatedMachineService struct {
	mu sync.Mutex

	startEntered chan struct{}
	startRelease chan struct{}
	closeEntered chan struct{}
	closeRelease chan struct{}

	starts int
	closes int
}

func (s *gatedMachineService) Start() error {
	s.mu.Lock()
	s.starts++
	s.mu.Unlock()
	if s.startEntered != nil {
		s.startEntered <- struct{}{}
	}
	if s.startRelease != nil {
		<-s.startRelease
	}
	return nil
}

func (s *gatedMachineService) Close() error {
	s.mu.Lock()
	s.closes++
	s.mu.Unlock()
	if s.closeEntered != nil {
		s.closeEntered <- struct{}{}
	}
	if s.closeRelease != nil {
		<-s.closeRelease
	}
	return nil
}

func (s *gatedMachineService) counts() (starts, closes int) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.starts, s.closes
}

type reconcileOperationGate struct {
	mu sync.Mutex

	attempts int
	entries  int
	events   []string

	firstEntered    chan struct{}
	releaseFirst    chan struct{}
	secondAttempted chan struct{}
	secondExited    chan struct{}
}

func newReconcileOperationGate() *reconcileOperationGate {
	return &reconcileOperationGate{
		firstEntered:    make(chan struct{}),
		releaseFirst:    make(chan struct{}),
		secondAttempted: make(chan struct{}),
		secondExited:    make(chan struct{}),
	}
}

func (g *reconcileOperationGate) observe(operation supervisorOperation, phase supervisorOperationPhase) {
	if operation != supervisorOperationReconcile {
		return
	}

	g.mu.Lock()
	switch phase {
	case supervisorOperationAttempted:
		g.attempts++
		g.events = append(g.events, operationEvent("attempt", g.attempts))
		current := g.attempts
		g.mu.Unlock()
		if current == 2 {
			close(g.secondAttempted)
		}
	case supervisorOperationEntered:
		g.entries++
		g.events = append(g.events, operationEvent("enter", g.entries))
		current := g.entries
		g.mu.Unlock()
		if current == 1 {
			close(g.firstEntered)
			<-g.releaseFirst
		}
	case supervisorOperationExited:
		g.events = append(g.events, operationEvent("exit", g.entries))
		current := g.entries
		g.mu.Unlock()
		if current == 2 {
			close(g.secondExited)
		}
	default:
		g.mu.Unlock()
	}
}

func (g *reconcileOperationGate) eventSnapshot() []string {
	g.mu.Lock()
	defer g.mu.Unlock()
	return append([]string(nil), g.events...)
}

func expectedSerializedReconcileEvents() []string {
	return []string{
		"attempt.1",
		"enter.1",
		"attempt.2",
		"exit.1",
		"enter.2",
		"exit.2",
	}
}

func TestSupervisorReconcileAndCloseOwnStartedRuntimeExactlyOnce(t *testing.T) {
	startEntered := make(chan struct{}, 1)
	startRelease := make(chan struct{})
	closeAttempted := make(chan struct{}, 1)
	candidate := &gatedMachineService{
		startEntered: startEntered,
		startRelease: startRelease,
	}
	discoverer := &concurrencyDiscoverer{responses: []*newV2board.MachineNodesResponse{
		machineNodesResponse(newV2board.MachineNode{ID: 1, Type: "vless", Name: "first"}),
	}}
	supervisor, err := NewSupervisor(SupervisorConfig{}, discoverer, func(NodeBinding) (service.Service, error) {
		return candidate, nil
	})
	if err != nil {
		t.Fatalf("NewSupervisor() error = %v", err)
	}
	supervisor.observeOperation = func(operation supervisorOperation, phase supervisorOperationPhase) {
		if operation == supervisorOperationClose && phase == supervisorOperationAttempted {
			closeAttempted <- struct{}{}
		}
	}

	reconcileDone := make(chan error, 1)
	go func() {
		reconcileDone <- supervisor.ReconcileNow()
	}()
	<-startEntered

	closeDone := make(chan error, 1)
	go func() {
		closeDone <- supervisor.Close()
	}()
	<-closeAttempted
	close(startRelease)

	if err := <-reconcileDone; err != nil {
		t.Fatalf("ReconcileNow() error = %v", err)
	}
	if err := <-closeDone; err != nil {
		t.Fatalf("Close() error = %v", err)
	}
	if starts, closes := candidate.counts(); starts != 1 || closes != 1 {
		t.Fatalf("candidate lifecycle = start %d close %d, want 1/1", starts, closes)
	}
	if !supervisor.closed || len(supervisor.running) != 0 {
		t.Fatalf("closed supervisor retained runtime state: closed=%t running=%d", supervisor.closed, len(supervisor.running))
	}
}

func TestSupervisorStartDuringCloseCannotPublishReplacementLoop(t *testing.T) {
	oldCancelCalled := make(chan struct{})
	oldDone := make(chan struct{})
	supervisor := &Supervisor{
		discoverer: &concurrencyDiscoverer{},
		factory: func(NodeBinding) (service.Service, error) {
			return nil, errors.New("unexpected factory call")
		},
		running:           make(map[int]*nodeRuntime),
		cancel:            func() { close(oldCancelCalled) },
		done:              oldDone,
		discoveryInterval: time.Hour,
		started:           true,
	}

	closeResult := make(chan error, 1)
	go func() {
		closeResult <- supervisor.Close()
	}()
	<-oldCancelCalled

	startErr := supervisor.Start()

	supervisor.mu.Lock()
	replacementCancel := supervisor.cancel
	replacementDone := supervisor.done
	supervisor.mu.Unlock()
	if replacementCancel != nil {
		replacementCancel()
	}
	if replacementDone != nil {
		<-replacementDone
	}
	close(oldDone)
	if err := <-closeResult; err != nil {
		t.Fatalf("Close() error = %v", err)
	}

	if startErr == nil {
		t.Fatal("Start() during Close returned nil and could publish a replacement loop")
	}
	if replacementCancel != nil || replacementDone != nil {
		t.Fatal("Start() during Close published replacement discovery ownership")
	}
}

func TestSupervisorBlockedRuntimeCloseKeepsPublishedTopologyUntilOwnershipResolves(t *testing.T) {
	closeEntered := make(chan struct{}, 1)
	closeRelease := make(chan struct{})
	runtimeService := &gatedMachineService{
		closeEntered: closeEntered,
		closeRelease: closeRelease,
	}
	runtime := &nodeRuntime{
		binding:      NodeBinding{NodeID: 1, NodeType: "vless", Name: "removed"},
		service:      runtimeService,
		missingCount: removedNodeMissingThreshold - 1,
	}
	supervisor := &Supervisor{
		discoverer: &concurrencyDiscoverer{responses: []*newV2board.MachineNodesResponse{
			machineNodesResponse(),
		}},
		factory: func(NodeBinding) (service.Service, error) {
			return nil, errors.New("unexpected factory call")
		},
		running: map[int]*nodeRuntime{1: runtime},
	}

	reconcileDone := make(chan error, 1)
	go func() {
		reconcileDone <- supervisor.ReconcileNow()
	}()
	<-closeEntered

	if supervisor.running[1] != runtime {
		t.Fatal("runtime was unpublished before its blocking Close resolved")
	}
	close(closeRelease)
	if err := <-reconcileDone; err != nil {
		t.Fatalf("ReconcileNow() error = %v", err)
	}
	if _, exists := supervisor.running[1]; exists {
		t.Fatal("runtime remained published after Close resolved")
	}
	if _, closes := runtimeService.counts(); closes != 1 {
		t.Fatalf("runtime Close calls = %d, want 1", closes)
	}
}

func TestSupervisorConcurrentReconcileNowCallsShareSerialization(t *testing.T) {
	discoverer := &concurrencyDiscoverer{responses: []*newV2board.MachineNodesResponse{
		machineNodesResponse(),
		machineNodesResponse(),
	}}
	supervisor, err := NewSupervisor(SupervisorConfig{}, discoverer, func(NodeBinding) (service.Service, error) {
		return nil, errors.New("unexpected factory call")
	})
	if err != nil {
		t.Fatalf("NewSupervisor() error = %v", err)
	}

	gate := newReconcileOperationGate()
	supervisor.observeOperation = gate.observe
	firstDone := make(chan error, 1)
	go func() {
		firstDone <- supervisor.ReconcileNow()
	}()
	<-gate.firstEntered

	secondDone := make(chan error, 1)
	go func() {
		secondDone <- supervisor.ReconcileNow()
	}()
	<-gate.secondAttempted
	close(gate.releaseFirst)

	if err := <-firstDone; err != nil {
		t.Fatalf("first ReconcileNow() error = %v", err)
	}
	if err := <-secondDone; err != nil {
		t.Fatalf("second ReconcileNow() error = %v", err)
	}
	<-gate.secondExited
	if got, want := gate.eventSnapshot(), expectedSerializedReconcileEvents(); !reflect.DeepEqual(got, want) {
		t.Fatalf("operation events = %#v, want %#v", got, want)
	}
}

func TestSupervisorPeriodicAndWebSocketReconcileShareSerialization(t *testing.T) {
	discoverer := &concurrencyDiscoverer{responses: []*newV2board.MachineNodesResponse{
		machineNodesResponse(),
		machineNodesResponse(),
	}}
	supervisor, err := NewSupervisor(SupervisorConfig{}, discoverer, func(NodeBinding) (service.Service, error) {
		return nil, errors.New("unexpected factory call")
	})
	if err != nil {
		t.Fatalf("NewSupervisor() error = %v", err)
	}

	gate := newReconcileOperationGate()
	supervisor.observeOperation = gate.observe

	periodicDone := make(chan error, 1)
	go func() {
		periodicDone <- supervisor.reconcilePeriodic()
	}()
	<-gate.firstEntered

	wsRuntime := NewSharedWSRuntime(SharedWSRuntimeConfig{})
	wsRuntime.SetRediscover(supervisor.ReconcileNow)
	wsRuntime.handleEvent(nil, &newV2board.WSEvent{
		Event:   newV2board.WSEventXboardSyncNodes,
		Payload: map[string]any{},
	})
	<-gate.secondAttempted
	close(gate.releaseFirst)

	if err := <-periodicDone; err != nil {
		t.Fatalf("reconcilePeriodic() error = %v", err)
	}
	<-gate.secondExited
	if got, want := gate.eventSnapshot(), expectedSerializedReconcileEvents(); !reflect.DeepEqual(got, want) {
		t.Fatalf("operation events = %#v, want %#v", got, want)
	}
}

func operationEvent(phase string, operation int) string {
	return phase + "." + strconv.Itoa(operation)
}
