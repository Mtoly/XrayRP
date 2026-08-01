package machine

import (
	"context"
	"errors"
	"reflect"
	"strconv"
	"strings"
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

type lateContextDiscoverer struct {
	entered  chan struct{}
	release  chan struct{}
	response *newV2board.MachineNodesResponse
}

func (d *lateContextDiscoverer) DiscoverMachineNodes() (*newV2board.MachineNodesResponse, error) {
	return nil, errors.New("context discovery required")
}

func (d *lateContextDiscoverer) DiscoverMachineNodesContext(context.Context) (*newV2board.MachineNodesResponse, error) {
	close(d.entered)
	<-d.release
	return d.response, nil
}

type cancelAwareContextDiscoverer struct {
	entered  chan struct{}
	canceled chan struct{}
	response *newV2board.MachineNodesResponse
}

func (d *cancelAwareContextDiscoverer) DiscoverMachineNodes() (*newV2board.MachineNodesResponse, error) {
	return nil, errors.New("context discovery required")
}

func (d *cancelAwareContextDiscoverer) DiscoverMachineNodesContext(ctx context.Context) (*newV2board.MachineNodesResponse, error) {
	close(d.entered)
	<-ctx.Done()
	close(d.canceled)
	return d.response, nil
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

func TestSupervisorCanceledDiscoveryDoesNotPublishLateTopology(t *testing.T) {
	discoverer := &lateContextDiscoverer{
		entered: make(chan struct{}),
		release: make(chan struct{}),
		response: machineNodesResponse(
			newV2board.MachineNode{ID: 1, Type: "vless", Name: "late"},
		),
	}
	factoryCalls := 0
	supervisor, err := NewSupervisor(SupervisorConfig{}, discoverer, func(NodeBinding) (service.Service, error) {
		factoryCalls++
		return &fakeService{}, nil
	})
	if err != nil {
		t.Fatalf("NewSupervisor() error = %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	result := make(chan error, 1)
	go func() { result <- supervisor.ReconcileNowContext(ctx) }()
	<-discoverer.entered
	cancel()
	close(discoverer.release)

	if err := <-result; !errors.Is(err, context.Canceled) {
		t.Fatalf("ReconcileNowContext() error = %v, want context cancellation", err)
	}
	state := supervisor.topologySnapshot()
	if state.generation != 0 || len(state.running) != 0 || factoryCalls != 0 {
		t.Fatalf("late discovery published topology: generation=%d running=%#v factoryCalls=%d", state.generation, state.running, factoryCalls)
	}
}

func TestSupervisorCloseCancelsBlockingDiscoveryBeforeWaitingForReconcile(t *testing.T) {
	discoverer := &cancelAwareContextDiscoverer{
		entered:  make(chan struct{}),
		canceled: make(chan struct{}),
		response: machineNodesResponse(
			newV2board.MachineNode{ID: 1, Type: "vless", Name: "late"},
		),
	}
	factoryCalls := 0
	supervisor, err := NewSupervisor(SupervisorConfig{}, discoverer, func(NodeBinding) (service.Service, error) {
		factoryCalls++
		return &fakeService{}, nil
	})
	if err != nil {
		t.Fatalf("NewSupervisor() error = %v", err)
	}

	reconcileDone := make(chan error, 1)
	go func() { reconcileDone <- supervisor.ReconcileNow() }()
	<-discoverer.entered
	closeDone := make(chan error, 1)
	go func() { closeDone <- supervisor.Close() }()
	<-discoverer.canceled

	if err := <-reconcileDone; !errors.Is(err, context.Canceled) {
		t.Fatalf("ReconcileNow() error = %v, want shutdown cancellation", err)
	}
	if err := <-closeDone; err != nil {
		t.Fatalf("Close() error = %v", err)
	}
	state := supervisor.topologySnapshot()
	if len(state.running) != 0 || factoryCalls != 0 {
		t.Fatalf("shutdown accepted late discovery: running=%#v factoryCalls=%d", state.running, factoryCalls)
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

func TestSupervisorRestartAndCloseSerializeOwnership(t *testing.T) {
	oldCloseEntered := make(chan struct{}, 1)
	oldCloseRelease := make(chan struct{})
	closeAttempted := make(chan struct{}, 1)
	oldService := &gatedMachineService{closeEntered: oldCloseEntered, closeRelease: oldCloseRelease}
	replacement := &gatedMachineService{}
	rollback := &gatedMachineService{}
	supervisor, err := NewSupervisor(
		SupervisorConfig{},
		&concurrencyDiscoverer{responses: []*newV2board.MachineNodesResponse{
			machineNodesResponse(newV2board.MachineNode{ID: 1, Type: "trojan", Name: "replacement"}),
		}},
		func(binding NodeBinding) (service.Service, error) {
			if binding.NodeType == "vless" {
				return rollback, nil
			}
			return replacement, nil
		},
	)
	if err != nil {
		t.Fatalf("NewSupervisor() error = %v", err)
	}
	supervisor.running[1] = &nodeRuntime{
		binding: NodeBinding{NodeID: 1, NodeType: "vless", Name: "old"},
		service: oldService,
		state:   nodeRuntimeRunning,
	}
	supervisor.observeOperation = func(operation supervisorOperation, phase supervisorOperationPhase) {
		if operation == supervisorOperationClose && phase == supervisorOperationAttempted {
			closeAttempted <- struct{}{}
		}
	}

	reconcileDone := make(chan error, 1)
	go func() { reconcileDone <- supervisor.ReconcileNow() }()
	<-oldCloseEntered
	closeDone := make(chan error, 1)
	go func() { closeDone <- supervisor.Close() }()
	<-closeAttempted
	close(oldCloseRelease)

	if err := <-reconcileDone; !errors.Is(err, context.Canceled) {
		t.Fatalf("ReconcileNow() error = %v, want shutdown cancellation", err)
	}
	if err := <-closeDone; err != nil {
		t.Fatalf("Close() error = %v", err)
	}
	if starts, closes := oldService.counts(); starts != 0 || closes != 1 {
		t.Fatalf("old lifecycle = start %d close %d, want 0/1", starts, closes)
	}
	if starts, closes := replacement.counts(); starts != 0 || closes != 1 {
		t.Fatalf("canceled replacement lifecycle = start %d close %d, want 0/1", starts, closes)
	}
	if starts, closes := rollback.counts(); starts != 1 || closes != 1 {
		t.Fatalf("rollback lifecycle = start %d close %d, want 1/1", starts, closes)
	}
	if !supervisor.closed || len(supervisor.running) != 0 {
		t.Fatalf("closed topology = closed:%t running:%#v", supervisor.closed, supervisor.running)
	}
}

func TestSupervisorReconcileCandidateStartPublishesAtomicallyWithoutStateLock(t *testing.T) {
	startEntered := make(chan struct{}, 1)
	startRelease := make(chan struct{})
	candidate := &gatedMachineService{
		startEntered: startEntered,
		startRelease: startRelease,
	}
	supervisor, err := NewSupervisor(
		SupervisorConfig{},
		&concurrencyDiscoverer{responses: []*newV2board.MachineNodesResponse{
			machineNodesResponse(newV2board.MachineNode{ID: 1, Type: "vless", Name: "candidate"}),
		}},
		func(NodeBinding) (service.Service, error) {
			return candidate, nil
		},
	)
	if err != nil {
		t.Fatalf("NewSupervisor() error = %v", err)
	}

	reconcileDone := make(chan error, 1)
	go func() {
		reconcileDone <- supervisor.ReconcileNow()
	}()
	<-startEntered

	stateLockAvailable := supervisor.mu.TryLock()
	candidatePublishedEarly := false
	if stateLockAvailable {
		_, candidatePublishedEarly = supervisor.running[1]
		supervisor.mu.Unlock()
	}
	close(startRelease)
	if err := <-reconcileDone; err != nil {
		t.Fatalf("ReconcileNow() error = %v", err)
	}

	if !stateLockAvailable {
		t.Fatal("candidate Start executed while holding Supervisor.mu")
	}
	if candidatePublishedEarly {
		t.Fatal("candidate runtime was published before Start completed")
	}
	if supervisor.running[1] == nil {
		t.Fatal("started candidate runtime was not published at commit")
	}
}

func TestSupervisorReconcileRejectsStaleGenerationAndCleansCandidate(t *testing.T) {
	startEntered := make(chan struct{}, 1)
	startRelease := make(chan struct{})
	candidate := &gatedMachineService{
		startEntered: startEntered,
		startRelease: startRelease,
	}
	supervisor, err := NewSupervisor(
		SupervisorConfig{},
		&concurrencyDiscoverer{responses: []*newV2board.MachineNodesResponse{
			machineNodesResponse(newV2board.MachineNode{ID: 1, Type: "vless", Name: "candidate"}),
		}},
		func(NodeBinding) (service.Service, error) {
			return candidate, nil
		},
	)
	if err != nil {
		t.Fatalf("NewSupervisor() error = %v", err)
	}

	reconcileDone := make(chan error, 1)
	go func() {
		reconcileDone <- supervisor.ReconcileNow()
	}()
	<-startEntered

	supervisor.mu.Lock()
	supervisor.topologyGeneration++
	supervisor.mu.Unlock()
	close(startRelease)

	reconcileErr := <-reconcileDone
	if reconcileErr == nil || !strings.Contains(reconcileErr.Error(), "topology generation changed") {
		t.Fatalf("ReconcileNow() error = %v, want stale generation error", reconcileErr)
	}
	if starts, closes := candidate.counts(); starts != 1 || closes != 1 {
		t.Fatalf("candidate lifecycle = start %d close %d, want 1/1", starts, closes)
	}
	state := supervisor.topologySnapshot()
	if state.generation != 1 || len(state.running) != 0 {
		t.Fatalf("stale transaction changed topology: generation=%d running=%#v", state.generation, state.running)
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

	stateLockAvailable := supervisor.mu.TryLock()
	runtimePublished := false
	if stateLockAvailable {
		runtimePublished = supervisor.running[1] == runtime
		supervisor.mu.Unlock()
	}
	if !stateLockAvailable {
		close(closeRelease)
		<-reconcileDone
		t.Fatal("runtime Close executed while holding Supervisor.mu")
	}
	if !runtimePublished {
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

func TestSupervisorReplacementCleanupFailureRetainsOldAndCandidateOwnership(t *testing.T) {
	replacementStartErr := errors.New("replacement start failed")
	replacementCleanupErr := errors.New("replacement cleanup failed")
	oldService := &fakeService{}
	replacementService := &fakeService{startErr: replacementStartErr, closeErr: replacementCleanupErr}
	supervisor, err := NewSupervisor(
		SupervisorConfig{},
		&concurrencyDiscoverer{responses: []*newV2board.MachineNodesResponse{
			machineNodesResponse(newV2board.MachineNode{ID: 1, Type: "trojan", Name: "replacement"}),
		}},
		func(NodeBinding) (service.Service, error) {
			return replacementService, nil
		},
	)
	if err != nil {
		t.Fatalf("NewSupervisor() error = %v", err)
	}
	supervisor.running[1] = &nodeRuntime{
		binding: NodeBinding{NodeID: 1, NodeType: "vless", Name: "old"},
		service: oldService,
		state:   nodeRuntimeRunning,
	}

	reconcileErr := supervisor.ReconcileNow()
	if !errors.Is(reconcileErr, replacementStartErr) || !errors.Is(reconcileErr, replacementCleanupErr) {
		t.Fatalf("ReconcileNow() error = %v, want replacement start and cleanup failures", reconcileErr)
	}
	state := supervisor.topologySnapshot()
	retained := state.running[1]
	if retained == nil || retained.state != nodeRuntimeFailedOwned || retained.binding.NodeType != "vless" {
		t.Fatalf("failed replacement ownership = %#v", retained)
	}
	if retained.service != nil || len(retained.cleanupServices) != 1 || retained.cleanupServices[0] != replacementService {
		t.Fatalf("retained owners = primary:%v cleanup:%#v", retained.service, retained.cleanupServices)
	}
	if oldService.closes != 1 || replacementService.starts != 1 || replacementService.closes != 1 {
		t.Fatalf("lifecycle old close=%d replacement start/close=%d/%d", oldService.closes, replacementService.starts, replacementService.closes)
	}
}

func TestSupervisorReconcileStartCleanupFailurePublishesFailedOwnedCandidate(t *testing.T) {
	startErr := errors.New("candidate start failed")
	cleanupErr := errors.New("candidate cleanup failed")
	candidate := &fakeService{startErr: startErr, closeErr: cleanupErr}
	supervisor, err := NewSupervisor(
		SupervisorConfig{},
		&concurrencyDiscoverer{responses: []*newV2board.MachineNodesResponse{
			machineNodesResponse(newV2board.MachineNode{ID: 1, Type: "vless", Name: "candidate"}),
		}},
		func(NodeBinding) (service.Service, error) {
			return candidate, nil
		},
	)
	if err != nil {
		t.Fatalf("NewSupervisor() error = %v", err)
	}

	reconcileErr := supervisor.ReconcileNow()
	if !errors.Is(reconcileErr, startErr) || !errors.Is(reconcileErr, cleanupErr) {
		t.Fatalf("ReconcileNow() error = %v, want start and cleanup errors", reconcileErr)
	}
	if candidate.starts != 1 || candidate.closes != 1 {
		t.Fatalf("candidate lifecycle = start %d close %d, want 1/1", candidate.starts, candidate.closes)
	}
	state := supervisor.topologySnapshot()
	retained := state.running[1]
	if retained == nil || retained.state != nodeRuntimeFailedOwned || retained.service != candidate {
		t.Fatalf("failed candidate ownership = %#v", retained)
	}
	if !errors.Is(state.failure, startErr) || !errors.Is(state.failure, cleanupErr) {
		t.Fatalf("published failure = %v, want start and cleanup errors", state.failure)
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
	startSharedWSRuntimeWithClient(t, wsRuntime, newRecordingSharedWSClient())
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
