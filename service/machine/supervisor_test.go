package machine

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/Mtoly/XrayRP/api"
	"github.com/Mtoly/XrayRP/api/newV2board"
	"github.com/Mtoly/XrayRP/service"
	"github.com/sirupsen/logrus"
)

type fakeService struct {
	starts   int
	closes   int
	startErr error
	closeErr error
}

func (s *fakeService) Start() error {
	s.starts++
	return s.startErr
}

func (s *fakeService) Close() error {
	s.closes++
	return s.closeErr
}

type fakeDiscoverer struct {
	responses []*newV2board.MachineNodesResponse
	err       error
	calls     int
}

func (d *fakeDiscoverer) DiscoverMachineNodes() (*newV2board.MachineNodesResponse, error) {
	d.calls++
	if d.err != nil {
		return nil, d.err
	}
	if len(d.responses) == 0 {
		return &newV2board.MachineNodesResponse{}, nil
	}
	response := d.responses[0]
	if len(d.responses) > 1 {
		d.responses = d.responses[1:]
	}
	return response, nil
}

type fakeFactory struct {
	services      map[int]*fakeService
	serviceQueues map[int][]*fakeService
	buildErr      map[int]error
	built         []NodeBinding
}

type fakeMachineStatusReporter struct {
	statuses []api.MachineStatus
	err      error
}

func (r *fakeMachineStatusReporter) ReportMachineStatus(status api.MachineStatus) error {
	r.statuses = append(r.statuses, status)
	return r.err
}

type channelMachineStatusReporter struct {
	statuses chan api.MachineStatus
	err      error
}

func (r *channelMachineStatusReporter) ReportMachineStatus(status api.MachineStatus) error {
	r.statuses <- status
	return r.err
}

func (f *fakeFactory) build(binding NodeBinding) (service.Service, error) {
	f.built = append(f.built, binding)
	if err := f.buildErr[binding.NodeID]; err != nil {
		return nil, err
	}
	if services := f.serviceQueues[binding.NodeID]; len(services) > 0 {
		service := services[0]
		f.serviceQueues[binding.NodeID] = services[1:]
		return service, nil
	}
	if service, ok := f.services[binding.NodeID]; ok {
		return service, nil
	}
	service := &fakeService{}
	f.services[binding.NodeID] = service
	return service, nil
}

func TestSupervisorLogWarningOmitsErrorDetailsByDefault(t *testing.T) {
	buffer := &bytes.Buffer{}
	logger := logrus.New()
	logger.SetOutput(buffer)
	logger.SetFormatter(&logrus.TextFormatter{DisableTimestamp: true})
	err := errors.New("token=secret")
	supervisor := &Supervisor{config: SupervisorConfig{Logger: logrus.NewEntry(logger)}}

	supervisor.logWarning(err)

	logOutput := buffer.String()
	if strings.Contains(logOutput, err.Error()) {
		t.Fatalf("expected sensitive error to be omitted, got %q", logOutput)
	}
	if !strings.Contains(logOutput, "details omitted") {
		t.Fatalf("expected redacted log message, got %q", logOutput)
	}
}

func TestSupervisorLogWarningCanShowErrorDetails(t *testing.T) {
	buffer := &bytes.Buffer{}
	logger := logrus.New()
	logger.SetOutput(buffer)
	logger.SetFormatter(&logrus.TextFormatter{DisableTimestamp: true})
	err := errors.New("token=secret")
	supervisor := &Supervisor{config: SupervisorConfig{
		Logger:           logrus.NewEntry(logger),
		ShowErrorDetails: true,
	}}

	supervisor.logWarning(err)

	logOutput := buffer.String()
	if !strings.Contains(logOutput, err.Error()) {
		t.Fatalf("expected detailed error to be logged, got %q", logOutput)
	}
}

func TestSupervisorStartFailsWhenDiscoveryFails(t *testing.T) {
	discoveryErr := errors.New("discovery failed")
	discoverer := &fakeDiscoverer{err: discoveryErr}
	factory := newFakeFactory()
	supervisor := newTestSupervisor(t, discoverer, factory)

	err := supervisor.Start()
	if !errors.Is(err, discoveryErr) {
		t.Fatalf("expected discovery error, got %v", err)
	}
	if discoverer.calls != 1 {
		t.Fatalf("expected one discovery call, got %d", discoverer.calls)
	}
	if len(factory.built) != 0 {
		t.Fatalf("expected no services to be built, got %#v", factory.built)
	}
	if len(supervisor.running) != 0 {
		t.Fatalf("expected no running services, got %d", len(supervisor.running))
	}
}

func TestSupervisorStartSkipsFailedNodeAndKeepsHealthyServices(t *testing.T) {
	startErr := errors.New("start failed")
	first := &fakeService{}
	second := &fakeService{startErr: startErr}
	third := &fakeService{}
	discoverer := &fakeDiscoverer{responses: []*newV2board.MachineNodesResponse{
		machineNodesResponse(
			newV2board.MachineNode{ID: 1, Type: "vless", Name: "first"},
			newV2board.MachineNode{ID: 2, Type: "vmess", Name: "second"},
			newV2board.MachineNode{ID: 3, Type: "trojan", Name: "third"},
		),
	}}
	factory := newFakeFactory()
	factory.services[1] = first
	factory.services[2] = second
	factory.services[3] = third
	supervisor := newTestSupervisor(t, discoverer, factory)

	if err := supervisor.Start(); err != nil {
		t.Fatalf("Start returned error: %v", err)
	}
	t.Cleanup(func() { _ = supervisor.Close() })
	if first.starts != 1 || first.closes != 0 {
		t.Fatalf("expected first service start=1 close=0, got start=%d close=%d", first.starts, first.closes)
	}
	if second.starts != 1 || second.closes != 0 {
		t.Fatalf("expected failed service start=1 close=0, got start=%d close=%d", second.starts, second.closes)
	}
	if third.starts != 1 || third.closes != 0 {
		t.Fatalf("expected third service start=1 close=0, got start=%d close=%d", third.starts, third.closes)
	}
	if _, exists := supervisor.running[2]; exists {
		t.Fatal("expected failed node to stay absent from running map")
	}
	if len(supervisor.running) != 2 {
		t.Fatalf("expected healthy services to keep running, got %d", len(supervisor.running))
	}
}

func TestSupervisorStartFailsWhenAllDiscoveredNodesFail(t *testing.T) {
	startErr := errors.New("start failed")
	service := &fakeService{startErr: startErr}
	discoverer := &fakeDiscoverer{responses: []*newV2board.MachineNodesResponse{
		machineNodesResponse(newV2board.MachineNode{ID: 1, Type: "vless", Name: "first"}),
	}}
	factory := newFakeFactory()
	factory.services[1] = service
	supervisor := newTestSupervisor(t, discoverer, factory)

	err := supervisor.Start()
	if !errors.Is(err, startErr) {
		t.Fatalf("expected start error, got %v", err)
	}
	if service.starts != 1 || service.closes != 0 {
		t.Fatalf("expected failed service start=1 close=0, got start=%d close=%d", service.starts, service.closes)
	}
	if len(supervisor.running) != 0 {
		t.Fatalf("expected no running services after all nodes fail, got %d", len(supervisor.running))
	}
}

func TestSupervisorStartStartsAllDiscoveredNodes(t *testing.T) {
	services := map[int]*fakeService{
		1: {},
		2: {},
		3: {},
	}
	discoverer := &fakeDiscoverer{responses: []*newV2board.MachineNodesResponse{
		machineNodesResponse(
			newV2board.MachineNode{ID: 3, Type: "Trojan", Name: "third"},
			newV2board.MachineNode{ID: 1, Type: " Vless ", Name: " first "},
			newV2board.MachineNode{ID: 2, Type: "Vmess", Name: "second"},
		),
	}}
	factory := newFakeFactory()
	factory.services = services
	supervisor := newTestSupervisor(t, discoverer, factory)

	if err := supervisor.Start(); err != nil {
		t.Fatalf("Start returned error: %v", err)
	}
	t.Cleanup(func() { _ = supervisor.Close() })
	if len(supervisor.running) != 3 {
		t.Fatalf("expected 3 running services, got %d", len(supervisor.running))
	}
	for nodeID, service := range services {
		if service.starts != 1 {
			t.Fatalf("expected node %d service to start once, got %d", nodeID, service.starts)
		}
		if runtime := supervisor.running[nodeID]; runtime == nil {
			t.Fatalf("expected node %d runtime", nodeID)
		} else if runtime.binding.NodeID != nodeID {
			t.Fatalf("unexpected runtime binding for node %d: %#v", nodeID, runtime.binding)
		}
	}
	if supervisor.running[1].binding.NodeType != "Vless" {
		t.Fatalf("expected normalized type to trim whitespace, got %q", supervisor.running[1].binding.NodeType)
	}
	if supervisor.running[1].binding.Name != " first " {
		t.Fatalf("expected name to be preserved, got %q", supervisor.running[1].binding.Name)
	}
}

func TestSupervisorCloseClosesAllRunningServices(t *testing.T) {
	services := map[int]*fakeService{
		1: {},
		2: {closeErr: errors.New("close failed")},
		3: {},
	}
	discoverer := &fakeDiscoverer{responses: []*newV2board.MachineNodesResponse{
		machineNodesResponse(
			newV2board.MachineNode{ID: 1, Type: "vless", Name: "first"},
			newV2board.MachineNode{ID: 2, Type: "vmess", Name: "second"},
			newV2board.MachineNode{ID: 3, Type: "trojan", Name: "third"},
		),
	}}
	factory := newFakeFactory()
	factory.services = services
	supervisor := newTestSupervisor(t, discoverer, factory)
	if err := supervisor.Start(); err != nil {
		t.Fatalf("Start returned error: %v", err)
	}

	err := supervisor.Close()
	if err == nil {
		t.Fatal("expected close error from one service")
	}
	for nodeID, service := range services {
		if service.closes != 1 {
			t.Fatalf("expected node %d service to close once, got %d", nodeID, service.closes)
		}
	}
	if len(supervisor.running) != 0 {
		t.Fatalf("expected running map to be cleared, got %d", len(supervisor.running))
	}
}

func newTestSupervisor(t *testing.T, discoverer *fakeDiscoverer, factory *fakeFactory) *Supervisor {
	t.Helper()
	supervisor, err := NewSupervisor(SupervisorConfig{}, discoverer, factory.build)
	if err != nil {
		t.Fatalf("NewSupervisor returned error: %v", err)
	}
	return supervisor
}

func newFakeFactory() *fakeFactory {
	return &fakeFactory{
		services:      make(map[int]*fakeService),
		serviceQueues: make(map[int][]*fakeService),
		buildErr:      make(map[int]error),
	}
}

func machineNodesResponse(nodes ...newV2board.MachineNode) *newV2board.MachineNodesResponse {
	return &newV2board.MachineNodesResponse{Nodes: nodes}
}

func machineNodesResponseWithBaseConfig(baseConfig api.BaseConfig, nodes ...newV2board.MachineNode) *newV2board.MachineNodesResponse {
	return &newV2board.MachineNodesResponse{Nodes: nodes, BaseConfig: baseConfig}
}

func TestSupervisorStartSkipsBuildFailedNodeAndKeepsHealthyServices(t *testing.T) {
	buildErr := fmt.Errorf("build failed")
	first := &fakeService{}
	third := &fakeService{}
	discoverer := &fakeDiscoverer{responses: []*newV2board.MachineNodesResponse{
		machineNodesResponse(
			newV2board.MachineNode{ID: 1, Type: "vless", Name: "first"},
			newV2board.MachineNode{ID: 2, Type: "vmess", Name: "second"},
			newV2board.MachineNode{ID: 3, Type: "trojan", Name: "third"},
		),
	}}
	factory := newFakeFactory()
	factory.services[1] = first
	factory.services[3] = third
	factory.buildErr[2] = buildErr
	supervisor := newTestSupervisor(t, discoverer, factory)

	if err := supervisor.Start(); err != nil {
		t.Fatalf("Start returned error: %v", err)
	}
	t.Cleanup(func() { _ = supervisor.Close() })
	if first.starts != 1 || first.closes != 0 {
		t.Fatalf("expected first service start=1 close=0, got start=%d close=%d", first.starts, first.closes)
	}
	if third.starts != 1 || third.closes != 0 {
		t.Fatalf("expected third service start=1 close=0, got start=%d close=%d", third.starts, third.closes)
	}
	if _, exists := supervisor.running[2]; exists {
		t.Fatal("expected build-failed node to stay absent from running map")
	}
	if len(supervisor.running) != 2 {
		t.Fatalf("expected healthy services to keep running, got %d", len(supervisor.running))
	}
}

func TestSupervisorPeriodicDiscoveryFailureKeepsRunningServices(t *testing.T) {
	discoveryErr := errors.New("discovery failed")
	service := &fakeService{}
	discoverer := &fakeDiscoverer{responses: []*newV2board.MachineNodesResponse{
		machineNodesResponse(newV2board.MachineNode{ID: 1, Type: "vless", Name: "first"}),
	}}
	factory := newFakeFactory()
	factory.services[1] = service
	supervisor := newTestSupervisor(t, discoverer, factory)
	if err := supervisor.startInitial(); err != nil {
		t.Fatalf("startInitial returned error: %v", err)
	}
	discoverer.err = discoveryErr

	err := supervisor.reconcilePeriodic()
	if !errors.Is(err, discoveryErr) {
		t.Fatalf("expected discovery error, got %v", err)
	}
	if service.closes != 0 {
		t.Fatalf("expected existing service to stay running, closes=%d", service.closes)
	}
	if got := supervisor.running[1]; got == nil || got.missingCount != 0 {
		t.Fatalf("expected running service with missing count 0, got %#v", got)
	}
}

func TestSupervisorPeriodicAddedNodeStartsService(t *testing.T) {
	first := &fakeService{}
	second := &fakeService{}
	discoverer := &fakeDiscoverer{responses: []*newV2board.MachineNodesResponse{
		machineNodesResponse(newV2board.MachineNode{ID: 1, Type: "vless", Name: "first"}),
		machineNodesResponse(
			newV2board.MachineNode{ID: 1, Type: "vless", Name: "first"},
			newV2board.MachineNode{ID: 2, Type: "trojan", Name: "second"},
		),
	}}
	factory := newFakeFactory()
	factory.services[1] = first
	factory.services[2] = second
	supervisor := newTestSupervisor(t, discoverer, factory)
	if err := supervisor.startInitial(); err != nil {
		t.Fatalf("startInitial returned error: %v", err)
	}

	if err := supervisor.reconcilePeriodic(); err != nil {
		t.Fatalf("reconcilePeriodic returned error: %v", err)
	}
	if first.starts != 1 || second.starts != 1 {
		t.Fatalf("expected first start=1 and second start=1, got %d/%d", first.starts, second.starts)
	}
	if len(supervisor.running) != 2 {
		t.Fatalf("expected two running services, got %d", len(supervisor.running))
	}
}

func TestSupervisorPeriodicAddedNodeStartFailureKeepsExistingServices(t *testing.T) {
	startErr := errors.New("start failed")
	first := &fakeService{}
	second := &fakeService{startErr: startErr}
	discoverer := &fakeDiscoverer{responses: []*newV2board.MachineNodesResponse{
		machineNodesResponse(newV2board.MachineNode{ID: 1, Type: "vless", Name: "first"}),
		machineNodesResponse(
			newV2board.MachineNode{ID: 1, Type: "vless", Name: "first"},
			newV2board.MachineNode{ID: 2, Type: "trojan", Name: "second"},
		),
	}}
	factory := newFakeFactory()
	factory.services[1] = first
	factory.services[2] = second
	supervisor := newTestSupervisor(t, discoverer, factory)
	if err := supervisor.startInitial(); err != nil {
		t.Fatalf("startInitial returned error: %v", err)
	}

	err := supervisor.reconcilePeriodic()
	if !errors.Is(err, startErr) {
		t.Fatalf("expected start error, got %v", err)
	}
	if first.starts != 1 || first.closes != 0 {
		t.Fatalf("expected existing service unchanged, start=%d close=%d", first.starts, first.closes)
	}
	if second.starts != 1 || second.closes != 0 {
		t.Fatalf("expected failing service start once and not close, start=%d close=%d", second.starts, second.closes)
	}
	if _, exists := supervisor.running[2]; exists {
		t.Fatal("expected failed added node to stay absent from running map")
	}
}

func TestSupervisorRemovedNodeMissingOnceStaysRunning(t *testing.T) {
	first := &fakeService{}
	second := &fakeService{}
	discoverer := &fakeDiscoverer{responses: []*newV2board.MachineNodesResponse{
		machineNodesResponse(
			newV2board.MachineNode{ID: 1, Type: "vless", Name: "first"},
			newV2board.MachineNode{ID: 2, Type: "trojan", Name: "second"},
		),
		machineNodesResponse(newV2board.MachineNode{ID: 1, Type: "vless", Name: "first"}),
	}}
	factory := newFakeFactory()
	factory.services[1] = first
	factory.services[2] = second
	supervisor := newTestSupervisor(t, discoverer, factory)
	if err := supervisor.startInitial(); err != nil {
		t.Fatalf("startInitial returned error: %v", err)
	}

	if err := supervisor.reconcilePeriodic(); err != nil {
		t.Fatalf("reconcilePeriodic returned error: %v", err)
	}
	if second.closes != 0 {
		t.Fatalf("expected missing-once service to stay running, closes=%d", second.closes)
	}
	if got := supervisor.running[2]; got == nil || got.missingCount != 1 {
		t.Fatalf("expected node 2 missing count 1, got %#v", got)
	}
}

func TestSupervisorRemovedNodeMissingTwiceClosesService(t *testing.T) {
	first := &fakeService{}
	second := &fakeService{}
	discoverer := &fakeDiscoverer{responses: []*newV2board.MachineNodesResponse{
		machineNodesResponse(
			newV2board.MachineNode{ID: 1, Type: "vless", Name: "first"},
			newV2board.MachineNode{ID: 2, Type: "trojan", Name: "second"},
		),
		machineNodesResponse(newV2board.MachineNode{ID: 1, Type: "vless", Name: "first"}),
		machineNodesResponse(newV2board.MachineNode{ID: 1, Type: "vless", Name: "first"}),
	}}
	factory := newFakeFactory()
	factory.services[1] = first
	factory.services[2] = second
	supervisor := newTestSupervisor(t, discoverer, factory)
	if err := supervisor.startInitial(); err != nil {
		t.Fatalf("startInitial returned error: %v", err)
	}
	if err := supervisor.reconcilePeriodic(); err != nil {
		t.Fatalf("first reconcilePeriodic returned error: %v", err)
	}

	if err := supervisor.reconcilePeriodic(); err != nil {
		t.Fatalf("second reconcilePeriodic returned error: %v", err)
	}
	if second.closes != 1 {
		t.Fatalf("expected second service to close once, got %d", second.closes)
	}
	if _, exists := supervisor.running[2]; exists {
		t.Fatal("expected node 2 to be removed from running map")
	}
}

func TestSupervisorRemovedNodeReappearsResetsMissingCount(t *testing.T) {
	first := &fakeService{}
	second := &fakeService{}
	discoverer := &fakeDiscoverer{responses: []*newV2board.MachineNodesResponse{
		machineNodesResponse(
			newV2board.MachineNode{ID: 1, Type: "vless", Name: "first"},
			newV2board.MachineNode{ID: 2, Type: "trojan", Name: "second"},
		),
		machineNodesResponse(newV2board.MachineNode{ID: 1, Type: "vless", Name: "first"}),
		machineNodesResponse(
			newV2board.MachineNode{ID: 1, Type: "vless", Name: "first"},
			newV2board.MachineNode{ID: 2, Type: "trojan", Name: "second"},
		),
	}}
	factory := newFakeFactory()
	factory.services[1] = first
	factory.services[2] = second
	supervisor := newTestSupervisor(t, discoverer, factory)
	if err := supervisor.startInitial(); err != nil {
		t.Fatalf("startInitial returned error: %v", err)
	}
	if err := supervisor.reconcilePeriodic(); err != nil {
		t.Fatalf("first reconcilePeriodic returned error: %v", err)
	}

	if err := supervisor.reconcilePeriodic(); err != nil {
		t.Fatalf("second reconcilePeriodic returned error: %v", err)
	}
	if second.closes != 0 || second.starts != 1 {
		t.Fatalf("expected reappeared service not restarted or closed, start=%d close=%d", second.starts, second.closes)
	}
	if got := supervisor.running[2]; got == nil || got.missingCount != 0 {
		t.Fatalf("expected node 2 missing count reset to 0, got %#v", got)
	}
}

func TestSupervisorNameUpdateDoesNotRestartService(t *testing.T) {
	service := &fakeService{}
	discoverer := &fakeDiscoverer{responses: []*newV2board.MachineNodesResponse{
		machineNodesResponse(newV2board.MachineNode{ID: 1, Type: "vless", Name: "old"}),
		machineNodesResponse(newV2board.MachineNode{ID: 1, Type: "vless", Name: "new"}),
	}}
	factory := newFakeFactory()
	factory.services[1] = service
	supervisor := newTestSupervisor(t, discoverer, factory)
	if err := supervisor.startInitial(); err != nil {
		t.Fatalf("startInitial returned error: %v", err)
	}

	if err := supervisor.reconcilePeriodic(); err != nil {
		t.Fatalf("reconcilePeriodic returned error: %v", err)
	}
	if service.starts != 1 || service.closes != 0 {
		t.Fatalf("expected service not restarted, start=%d close=%d", service.starts, service.closes)
	}
	if got := supervisor.running[1].binding.Name; got != "new" {
		t.Fatalf("expected binding name updated, got %q", got)
	}
}

func TestSupervisorNodeTypeUpdateRestartsService(t *testing.T) {
	oldService := &fakeService{}
	newService := &fakeService{}
	discoverer := &fakeDiscoverer{responses: []*newV2board.MachineNodesResponse{
		machineNodesResponse(newV2board.MachineNode{ID: 1, Type: "vless", Name: "node"}),
		machineNodesResponse(newV2board.MachineNode{ID: 1, Type: "trojan", Name: "node"}),
	}}
	factory := newFakeFactory()
	factory.serviceQueues[1] = []*fakeService{oldService, newService}
	supervisor := newTestSupervisor(t, discoverer, factory)
	if err := supervisor.startInitial(); err != nil {
		t.Fatalf("startInitial returned error: %v", err)
	}

	if err := supervisor.reconcilePeriodic(); err != nil {
		t.Fatalf("reconcilePeriodic returned error: %v", err)
	}
	if oldService.starts != 1 || oldService.closes != 1 {
		t.Fatalf("expected old service start=1 close=1, got start=%d close=%d", oldService.starts, oldService.closes)
	}
	if newService.starts != 1 || newService.closes != 0 {
		t.Fatalf("expected new service start=1 close=0, got start=%d close=%d", newService.starts, newService.closes)
	}
	if got := supervisor.running[1]; got == nil || got.binding.NodeType != "trojan" || got.service != newService {
		t.Fatalf("expected running runtime to use new service/type, got %#v", got)
	}
}

func TestSupervisorNodeTypeRestartFailureRollsBackOldService(t *testing.T) {
	startErr := errors.New("new start failed")
	oldService := &fakeService{}
	newService := &fakeService{startErr: startErr}
	rollbackService := &fakeService{}
	discoverer := &fakeDiscoverer{responses: []*newV2board.MachineNodesResponse{
		machineNodesResponse(newV2board.MachineNode{ID: 1, Type: "vless", Name: "node"}),
		machineNodesResponse(newV2board.MachineNode{ID: 1, Type: "trojan", Name: "node"}),
	}}
	factory := newFakeFactory()
	factory.serviceQueues[1] = []*fakeService{oldService, newService, rollbackService}
	supervisor := newTestSupervisor(t, discoverer, factory)
	if err := supervisor.startInitial(); err != nil {
		t.Fatalf("startInitial returned error: %v", err)
	}

	err := supervisor.reconcilePeriodic()
	if !errors.Is(err, startErr) {
		t.Fatalf("expected start error, got %v", err)
	}
	if oldService.starts != 1 || oldService.closes != 1 {
		t.Fatalf("expected old service start=1 close=1, got start=%d close=%d", oldService.starts, oldService.closes)
	}
	if newService.starts != 1 || newService.closes != 1 {
		t.Fatalf("expected failed new service start=1 close=1, got start=%d close=%d", newService.starts, newService.closes)
	}
	if rollbackService.starts != 1 || rollbackService.closes != 0 {
		t.Fatalf("expected rollback service start=1 close=0, got start=%d close=%d", rollbackService.starts, rollbackService.closes)
	}
	if got := supervisor.running[1]; got == nil || got.binding.NodeType != "vless" || got.service != rollbackService {
		t.Fatalf("expected running runtime rolled back to old type/service, got %#v", got)
	}
}

func TestSupervisorDiscoveryIntervalDefaultsAndClamps(t *testing.T) {
	tests := []struct {
		name     string
		interval time.Duration
		min      time.Duration
		want     time.Duration
	}{
		{name: "default", interval: 0, want: defaultMachineDiscoveryInterval},
		{name: "default negative", interval: -1 * time.Second, want: defaultMachineDiscoveryInterval},
		{name: "clamp default min", interval: 5 * time.Second, want: minMachineDiscoveryInterval},
		{name: "use interval", interval: 45 * time.Second, want: 45 * time.Second},
		{name: "custom min", interval: 10 * time.Second, min: 15 * time.Second, want: 15 * time.Second},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := normalizeDiscoveryInterval(tt.interval, tt.min); got != tt.want {
				t.Fatalf("normalizeDiscoveryInterval() = %s, want %s", got, tt.want)
			}
		})
	}
}

func TestMaterializeMachineRuntimeSchedule(t *testing.T) {
	tests := []struct {
		name                string
		baseConfig          api.BaseConfig
		options             machineRuntimeScheduleOptions
		wantDiscovery       time.Duration
		wantStatus          time.Duration
		wantUpdateDiscovery bool
		wantUpdateStatus    bool
	}{
		{
			name:       "missing base config intervals keep current schedule",
			baseConfig: api.BaseConfig{},
			options: machineRuntimeScheduleOptions{
				currentDiscoveryInterval: 60 * time.Second,
				currentStatusInterval:    60 * time.Second,
			},
			wantDiscovery: 60 * time.Second,
			wantStatus:    60 * time.Second,
		},
		{
			name:       "negative base config intervals keep current schedule",
			baseConfig: api.BaseConfig{PullInterval: -1, PushInterval: -1},
			options: machineRuntimeScheduleOptions{
				currentDiscoveryInterval: 60 * time.Second,
				currentStatusInterval:    60 * time.Second,
			},
			wantDiscovery: 60 * time.Second,
			wantStatus:    60 * time.Second,
		},
		{
			name:       "base config intervals update schedule",
			baseConfig: api.BaseConfig{PullInterval: 45, PushInterval: 15},
			options: machineRuntimeScheduleOptions{
				currentDiscoveryInterval: 60 * time.Second,
				currentStatusInterval:    60 * time.Second,
			},
			wantDiscovery:       45 * time.Second,
			wantStatus:          15 * time.Second,
			wantUpdateDiscovery: true,
			wantUpdateStatus:    true,
		},
		{
			name:       "base config intervals keep existing clamps",
			baseConfig: api.BaseConfig{PullInterval: 5, PushInterval: 5},
			options: machineRuntimeScheduleOptions{
				currentDiscoveryInterval: 60 * time.Second,
				currentStatusInterval:    60 * time.Second,
			},
			wantDiscovery:       minMachineDiscoveryInterval,
			wantStatus:          minMachineStatusInterval,
			wantUpdateDiscovery: true,
			wantUpdateStatus:    true,
		},
		{
			name:       "same effective intervals do not request replacement",
			baseConfig: api.BaseConfig{PullInterval: 45, PushInterval: 15},
			options: machineRuntimeScheduleOptions{
				currentDiscoveryInterval: 45 * time.Second,
				currentStatusInterval:    15 * time.Second,
			},
			wantDiscovery: 45 * time.Second,
			wantStatus:    15 * time.Second,
		},
		{
			name:       "custom minimum intervals are preserved",
			baseConfig: api.BaseConfig{PullInterval: 20, PushInterval: 8},
			options: machineRuntimeScheduleOptions{
				currentDiscoveryInterval: 60 * time.Second,
				minDiscoveryInterval:     25 * time.Second,
				currentStatusInterval:    60 * time.Second,
				minStatusInterval:        12 * time.Second,
			},
			wantDiscovery:       25 * time.Second,
			wantStatus:          12 * time.Second,
			wantUpdateDiscovery: true,
			wantUpdateStatus:    true,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			schedule := materializeMachineRuntimeSchedule(test.baseConfig, test.options)
			if schedule.discoveryInterval != test.wantDiscovery || schedule.statusInterval != test.wantStatus {
				t.Fatalf("expected discovery=%s status=%s, got discovery=%s status=%s", test.wantDiscovery, test.wantStatus, schedule.discoveryInterval, schedule.statusInterval)
			}
			if schedule.updateDiscovery != test.wantUpdateDiscovery || schedule.updateStatus != test.wantUpdateStatus {
				t.Fatalf("expected update discovery=%v status=%v, got discovery=%v status=%v", test.wantUpdateDiscovery, test.wantUpdateStatus, schedule.updateDiscovery, schedule.updateStatus)
			}
		})
	}
}

func TestSupervisorStartAppliesBaseConfigPullInterval(t *testing.T) {
	discoverer := &fakeDiscoverer{responses: []*newV2board.MachineNodesResponse{
		machineNodesResponseWithBaseConfig(api.BaseConfig{PullInterval: 45}),
	}}
	supervisor, err := NewSupervisor(SupervisorConfig{DiscoveryInterval: 60 * time.Second}, discoverer, newFakeFactory().build)
	if err != nil {
		t.Fatalf("NewSupervisor returned error: %v", err)
	}

	if err := supervisor.startInitial(); err != nil {
		t.Fatalf("startInitial returned error: %v", err)
	}
	if supervisor.discoveryInterval != 45*time.Second {
		t.Fatalf("expected discovery interval from base config, got %s", supervisor.discoveryInterval)
	}
}

func TestSupervisorStartAppliesBaseConfigPushInterval(t *testing.T) {
	discoverer := &fakeDiscoverer{responses: []*newV2board.MachineNodesResponse{
		machineNodesResponseWithBaseConfig(api.BaseConfig{PushInterval: 15}),
	}}
	supervisor, err := NewSupervisor(SupervisorConfig{}, discoverer, newFakeFactory().build)
	if err != nil {
		t.Fatalf("NewSupervisor returned error: %v", err)
	}

	if err := supervisor.startInitial(); err != nil {
		t.Fatalf("startInitial returned error: %v", err)
	}
	if supervisor.statusInterval != 15*time.Second {
		t.Fatalf("expected machine status interval from base config, got %s", supervisor.statusInterval)
	}
}

func TestMaterializeMachineStatusSnapshot(t *testing.T) {
	collectorErr := errors.New("collect failed")
	status := api.MachineStatus{CPU: 12.3, MemTotal: 1000, MemUsed: 500, NetInSpeed: -1, NetOutSpeed: -1}
	snapshot := materializeMachineStatusSnapshot(func() (api.MachineStatus, error) {
		return status, collectorErr
	})
	if !errors.Is(snapshot.err, collectorErr) {
		t.Fatalf("expected collector error, got %v", snapshot.err)
	}
	if snapshot.status != status {
		t.Fatalf("expected collected status to be preserved, got %#v", snapshot.status)
	}
}

func TestMaterializeMachineStatusSnapshotWithNilCollector(t *testing.T) {
	snapshot := materializeMachineStatusSnapshot(nil)
	if snapshot.err != nil {
		t.Fatalf("expected no error for nil collector, got %v", snapshot.err)
	}
	if snapshot.status != (api.MachineStatus{}) {
		t.Fatalf("expected zero status for nil collector, got %#v", snapshot.status)
	}
}

func TestSupervisorReportsMachineStatus(t *testing.T) {
	reporter := &fakeMachineStatusReporter{}
	collectorCalls := make(chan struct{}, 1)
	status := api.MachineStatus{CPU: 12.3, MemTotal: 1000, MemUsed: 500, DiskTotal: 2000, DiskUsed: 1000, NetInSpeed: -1, NetOutSpeed: -1}
	discoverer := &fakeDiscoverer{responses: []*newV2board.MachineNodesResponse{
		machineNodesResponse(),
	}}
	supervisor, err := NewSupervisor(SupervisorConfig{
		MachineStatus: MachineStatusReporterConfig{
			Reporter:       reporter,
			Collector:      func() (api.MachineStatus, error) { collectorCalls <- struct{}{}; return status, nil },
			StatusInterval: 50 * time.Millisecond,
		},
	}, discoverer, newFakeFactory().build)
	if err != nil {
		t.Fatalf("NewSupervisor returned error: %v", err)
	}
	if err := supervisor.Start(); err != nil {
		t.Fatalf("Start returned error: %v", err)
	}
	defer supervisor.Close()

	select {
	case <-collectorCalls:
	case <-time.After(time.Second):
		t.Fatal("expected machine status collector to be called")
	}
	if len(reporter.statuses) != 1 {
		t.Fatalf("expected one machine status report, got %d", len(reporter.statuses))
	}
	if reporter.statuses[0] != status {
		t.Fatalf("unexpected machine status: %#v", reporter.statuses[0])
	}
}

func TestSupervisorReportsPartialMachineStatusAfterCollectorError(t *testing.T) {
	collectorErr := errors.New("collect failed")
	status := api.MachineStatus{CPU: 12.3, MemTotal: 1000, MemUsed: 500, DiskTotal: 2000, DiskUsed: 1000, NetInSpeed: -1, NetOutSpeed: -1}
	reporter := &fakeMachineStatusReporter{}
	supervisor := &Supervisor{config: SupervisorConfig{
		MachineStatus: MachineStatusReporterConfig{
			Reporter: reporter,
			Collector: func() (api.MachineStatus, error) {
				return status, collectorErr
			},
		},
	}}

	supervisor.reportMachineStatus()

	if len(reporter.statuses) != 1 {
		t.Fatalf("expected one machine status report, got %d", len(reporter.statuses))
	}
	if reporter.statuses[0] != status {
		t.Fatalf("expected partial status to be reported, got %#v", reporter.statuses[0])
	}
}

func TestSupervisorContinuesStatusLoopAfterReporterError(t *testing.T) {
	buffer := &bytes.Buffer{}
	logger := logrus.New()
	logger.SetOutput(buffer)
	logger.SetFormatter(&logrus.TextFormatter{DisableTimestamp: true})
	reporter := &channelMachineStatusReporter{
		statuses: make(chan api.MachineStatus, 4),
		err:      errors.New("report failed"),
	}
	collectorCalls := make(chan struct{}, 4)
	nextStatus := api.MachineStatus{CPU: 1, NetInSpeed: -1, NetOutSpeed: -1}
	discoverer := &fakeDiscoverer{responses: []*newV2board.MachineNodesResponse{
		machineNodesResponse(),
	}}
	supervisor, err := NewSupervisor(SupervisorConfig{
		MachineStatus: MachineStatusReporterConfig{
			Reporter: reporter,
			Collector: func() (api.MachineStatus, error) {
				collectorCalls <- struct{}{}
				status := nextStatus
				nextStatus.CPU++
				return status, nil
			},
			StatusInterval:    10 * time.Millisecond,
			MinStatusInterval: 10 * time.Millisecond,
		},
		Logger: logrus.NewEntry(logger),
	}, discoverer, newFakeFactory().build)
	if err != nil {
		t.Fatalf("NewSupervisor returned error: %v", err)
	}
	if err := supervisor.Start(); err != nil {
		t.Fatalf("Start returned error: %v", err)
	}
	defer supervisor.Close()

	first := receiveMachineStatus(t, reporter.statuses)
	second := receiveMachineStatus(t, reporter.statuses)
	if first.CPU != 1 || second.CPU != 2 {
		t.Fatalf("expected status loop to continue after reporter errors, got first=%#v second=%#v", first, second)
	}
	if len(collectorCalls) < 2 {
		t.Fatalf("expected at least two collector calls, got %d", len(collectorCalls))
	}
	if !strings.Contains(buffer.String(), "machine supervisor operation failed") {
		t.Fatalf("expected reporter error to be logged, got %q", buffer.String())
	}
}

func TestSupervisorStatusLoopDoesNotRunDiscovery(t *testing.T) {
	reporter := &channelMachineStatusReporter{statuses: make(chan api.MachineStatus, 4)}
	discoverer := &fakeDiscoverer{responses: []*newV2board.MachineNodesResponse{
		machineNodesResponse(newV2board.MachineNode{ID: 1, Type: "vless", Name: "first"}),
	}}
	factory := newFakeFactory()
	service := &fakeService{}
	factory.services[1] = service
	supervisor, err := NewSupervisor(SupervisorConfig{
		DiscoveryInterval:    time.Hour,
		MinDiscoveryInterval: time.Hour,
		MachineStatus: MachineStatusReporterConfig{
			Reporter: reporter,
			Collector: func() (api.MachineStatus, error) {
				return api.MachineStatus{CPU: 1, NetInSpeed: -1, NetOutSpeed: -1}, nil
			},
			StatusInterval:    10 * time.Millisecond,
			MinStatusInterval: 10 * time.Millisecond,
		},
	}, discoverer, factory.build)
	if err != nil {
		t.Fatalf("NewSupervisor returned error: %v", err)
	}
	if err := supervisor.startInitial(); err != nil {
		t.Fatalf("startInitial returned error: %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go supervisor.runStatus(ctx, done, 10*time.Millisecond)
	defer func() {
		cancel()
		<-done
	}()

	_ = receiveMachineStatus(t, reporter.statuses)
	_ = receiveMachineStatus(t, reporter.statuses)
	if discoverer.calls != 1 {
		t.Fatalf("expected status loop not to run discovery, got %d discovery calls", discoverer.calls)
	}
	if service.starts != 1 || service.closes != 0 {
		t.Fatalf("expected node service lifecycle unchanged, start=%d close=%d", service.starts, service.closes)
	}
}

func receiveMachineStatus(t *testing.T, statuses <-chan api.MachineStatus) api.MachineStatus {
	t.Helper()
	select {
	case status := <-statuses:
		return status
	case <-time.After(time.Second):
		t.Fatal("timeout waiting for machine status report")
	}
	return api.MachineStatus{}
}

func TestSupervisorPeriodicAppliesBaseConfigPullInterval(t *testing.T) {
	discoverer := &fakeDiscoverer{responses: []*newV2board.MachineNodesResponse{
		machineNodesResponseWithBaseConfig(api.BaseConfig{PullInterval: 45}),
		machineNodesResponseWithBaseConfig(api.BaseConfig{PullInterval: 5}),
	}}
	supervisor, err := NewSupervisor(SupervisorConfig{DiscoveryInterval: 60 * time.Second}, discoverer, newFakeFactory().build)
	if err != nil {
		t.Fatalf("NewSupervisor returned error: %v", err)
	}
	if err := supervisor.startInitial(); err != nil {
		t.Fatalf("startInitial returned error: %v", err)
	}

	if err := supervisor.reconcilePeriodic(); err != nil {
		t.Fatalf("reconcilePeriodic returned error: %v", err)
	}
	if supervisor.discoveryInterval != minMachineDiscoveryInterval {
		t.Fatalf("expected clamped discovery interval, got %s", supervisor.discoveryInterval)
	}
}
