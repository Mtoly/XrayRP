package hysteria2

import (
	"errors"
	"go/ast"
	"go/parser"
	"go/token"
	"reflect"
	"regexp"
	"testing"
	"time"

	"github.com/apernet/hysteria/core/v2/server"
	log "github.com/sirupsen/logrus"

	"github.com/Mtoly/XrayRP/api"
	"github.com/Mtoly/XrayRP/common/mylego"
	"github.com/Mtoly/XrayRP/service/controller"
	"golang.org/x/time/rate"
)

func newReloadTestService() (*Hysteria2Service, *fakeRuntimeServer, *api.NodeInfo) {
	oldNode := &api.NodeInfo{
		NodeType: "Hysteria2", NodeID: 9, Port: 9443, EnableTLS: true,
		SNI: "old.example.com", Hysteria2Config: &api.Hysteria2Config{Obfs: "none"},
	}
	oldRuntime := &fakeRuntimeServer{events: &lifecycleEvents{}}
	oldServeDone := make(chan struct{})
	close(oldServeDone)
	oldWatcherDone := make(chan struct{})
	close(oldWatcherDone)
	service := New(&configurablePanelClient{}, &controller.Config{
		ListenIP: "127.0.0.1",
		CertConfig: &mylego.CertConfig{
			CertMode: "file", CertDomain: "old.example.com", CertFile: "old.cert", KeyFile: "old.key",
		},
	})
	service.state = stateRunning
	service.nodeInfo = oldNode
	service.server = oldRuntime
	service.serveDone = oldServeDone
	service.watcherDone = oldWatcherDone
	service.tag = "Hysteria2_127.0.0.1_9443_9"
	return service, oldRuntime, oldNode
}

func TestReloadRequiresExplicitCandidateConfigFactory(t *testing.T) {
	service, _, _ := newReloadTestService()
	legacyCalled := false
	service.reloadServerConfigFactory = nil
	service.serverConfigFactory = func(*Hysteria2Service) (*server.Config, error) {
		legacyCalled = true
		return &server.Config{}, nil
	}
	service.runtimeServerFactory = func(*server.Config) (runtimeServer, error) {
		return &fakeRuntimeServer{events: &lifecycleEvents{}}, nil
	}

	_, err := service.buildReloadRuntimeServer(serverBuildSpec{
		nodeInfo:   newReloadNode(10443, "new.example.com"),
		certConfig: cloneCertConfig(service.config.CertConfig),
	})
	if err == nil {
		t.Fatal("buildReloadRuntimeServer() error = nil, want missing explicit candidate factory error")
	}
	if legacyCalled {
		t.Fatal("buildReloadRuntimeServer() called legacy factory that reads mutable service fields")
	}
}

func newReloadNode(port uint32, sni string) *api.NodeInfo {
	return &api.NodeInfo{
		NodeType: "Hysteria2", NodeID: 9, Port: port, EnableTLS: true, SNI: sni,
		Hysteria2Config: &api.Hysteria2Config{Obfs: "none"},
	}
}

func TestRuntimeCallbacksReadTagThroughAppliedSnapshot(t *testing.T) {
	file, err := parser.ParseFile(token.NewFileSet(), "eventlogger.go", nil, 0)
	if err != nil {
		t.Fatalf("parse eventlogger.go: %v", err)
	}
	ast.Inspect(file, func(node ast.Node) bool {
		selector, ok := node.(*ast.SelectorExpr)
		if ok && selector.Sel.Name == "tag" {
			t.Errorf("eventlogger.go reads tag directly; runtime callbacks must use appliedTag")
		}
		return true
	})
}

func TestReloadNilNodeInfoIsNoOp(t *testing.T) {
	service, oldRuntime, oldNode := newReloadTestService()
	called := false
	service.serverConfigFactory = func(*Hysteria2Service) (*server.Config, error) {
		called = true
		return nil, nil
	}

	if err := service.reloadNode(nil); err != nil {
		t.Fatalf("reloadNode(nil) error = %v", err)
	}
	if called || service.server != oldRuntime || service.nodeInfo != oldNode {
		t.Fatalf("nil reload mutated state: called=%v server=%v nodeInfo=%v", called, service.server, service.nodeInfo)
	}
}

func TestReloadRejectsInvalidCandidateWithoutMutation(t *testing.T) {
	tests := []struct {
		name string
		node *api.NodeInfo
	}{
		{name: "wrong type", node: &api.NodeInfo{NodeType: "Tuic", Port: 9443}},
		{name: "zero port", node: newReloadNode(0, "new.example.com")},
		{name: "nil config", node: &api.NodeInfo{NodeType: "Hysteria2", Port: 9443}},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			service, oldRuntime, oldNode := newReloadTestService()
			oldCert := *service.config.CertConfig
			called := false
			service.serverConfigFactory = func(*Hysteria2Service) (*server.Config, error) {
				called = true
				return nil, nil
			}

			if err := service.reloadNode(tc.node); err == nil {
				t.Fatal("reloadNode() error = nil, want validation error")
			}
			if called || service.server != oldRuntime || service.nodeInfo != oldNode || !reflect.DeepEqual(*service.config.CertConfig, oldCert) {
				t.Fatalf("invalid reload mutated state: called=%v server=%v nodeInfo=%v cert=%+v", called, service.server, service.nodeInfo, service.config.CertConfig)
			}
		})
	}
}

func TestReloadBuildFailureRetainsOldRuntimeRulesAndAppliedState(t *testing.T) {
	buildErr := errors.New("candidate build failed")
	service, oldRuntime, oldNode := newReloadTestService()
	oldTag := service.tag
	oldCert := *service.config.CertConfig
	oldRules := []portHopRule{{FromPortStart: 30001, FromPortEnd: 30002, ToPort: 9443}}
	service.portHopRules = append([]portHopRule(nil), oldRules...)
	events := &lifecycleEvents{}
	service.reloadServerConfigFactory = func(*Hysteria2Service, serverBuildSpec) (*server.Config, error) {
		events.add("build:candidate")
		return nil, buildErr
	}
	originalApply, originalDelete := applyPortHopRules, deletePortHopRules
	defer func() {
		applyPortHopRules = originalApply
		deletePortHopRules = originalDelete
	}()
	applyPortHopRules = func([]portHopRule, *log.Entry) error { events.add("rules:apply"); return nil }
	deletePortHopRules = func([]portHopRule, *log.Entry) error { events.add("rules:delete"); return nil }

	newNode := newReloadNode(10443, "new.example.com")
	err := service.reloadNode(newNode)
	if !errors.Is(err, buildErr) {
		t.Fatalf("reloadNode() error = %v, want %v", err, buildErr)
	}
	if service.server != oldRuntime || service.nodeInfo != oldNode || service.tag != oldTag {
		t.Fatalf("build failure lost old state: server=%v nodeInfo=%v tag=%q", service.server, service.nodeInfo, service.tag)
	}
	if !reflect.DeepEqual(*service.config.CertConfig, oldCert) || !reflect.DeepEqual(service.portHopRules, oldRules) {
		t.Fatalf("build failure published cert/rules: cert=%+v rules=%v", service.config.CertConfig, service.portHopRules)
	}
	if got := events.snapshot(); !reflect.DeepEqual(got, []string{"build:candidate"}) {
		t.Fatalf("events = %v, want candidate validation without rule or runtime mutation", got)
	}
}

func TestReloadServeFailureCleansCandidateAndRestoresOldRuntime(t *testing.T) {
	serveErr := errors.New("candidate serve failed")
	service, _, oldNode := newReloadTestService()
	candidate := &fakeRuntimeServer{events: &lifecycleEvents{}}
	restored := &fakeRuntimeServer{events: &lifecycleEvents{}}
	events := &lifecycleEvents{}
	builds := 0
	service.reloadServerConfigFactory = func(*Hysteria2Service, serverBuildSpec) (*server.Config, error) {
		builds++
		if builds == 1 {
			events.add("build:candidate")
		} else {
			events.add("build:restore")
		}
		return &server.Config{}, nil
	}
	service.runtimeServerFactory = func(*server.Config) (runtimeServer, error) {
		if builds == 1 {
			return candidate, nil
		}
		return restored, nil
	}
	service.closeRuntime = func(runtime runtimeServer) error {
		switch runtime {
		case service.server:
			events.add("close:old")
		case candidate:
			events.add("close:candidate")
		default:
			events.add("close:restored")
		}
		return nil
	}
	service.serveRuntime = func(runtime runtimeServer) error {
		if runtime == candidate {
			events.add("serve:candidate")
			return serveErr
		}
		events.add("serve:restored")
		return nil
	}
	service.serveHandshake = func(start func(), _ <-chan struct{}, result <-chan error) error {
		start()
		return <-result
	}

	err := service.reloadNode(newReloadNode(9443, "new.example.com"))
	if !errors.Is(err, serveErr) {
		t.Fatalf("reloadNode() error = %v, want %v", err, serveErr)
	}
	if service.server != restored || service.nodeInfo != oldNode {
		t.Fatalf("serve failure did not restore old runtime: server=%v nodeInfo=%v", service.server, service.nodeInfo)
	}
	want := []string{"close:old", "build:candidate", "serve:candidate", "close:candidate", "build:restore", "serve:restored"}
	if got := events.snapshot(); !reflect.DeepEqual(got, want) {
		t.Fatalf("events = %v, want %v", got, want)
	}
}

func TestReloadSameEndpointWaitsForOldServeAndWatcherBeforeCandidateBuild(t *testing.T) {
	service, oldRuntime, _ := newReloadTestService()
	oldServeDone := make(chan struct{})
	oldWatcherDone := make(chan struct{})
	service.serveDone = oldServeDone
	service.watcherDone = oldWatcherDone
	oldClosed := make(chan struct{})
	releaseOldWatcher := make(chan struct{})
	candidateBuildEntered := make(chan struct{})
	candidateServeRelease := make(chan struct{})
	candidate := &fakeRuntimeServer{events: &lifecycleEvents{}}

	go func() {
		<-releaseOldWatcher
		close(oldWatcherDone)
	}()
	service.closeRuntime = func(runtime runtimeServer) error {
		switch runtime {
		case oldRuntime:
			close(oldServeDone)
			close(oldClosed)
		case candidate:
			close(candidateServeRelease)
		}
		return nil
	}
	service.reloadServerConfigFactory = func(*Hysteria2Service, serverBuildSpec) (*server.Config, error) {
		close(candidateBuildEntered)
		return &server.Config{}, nil
	}
	service.runtimeServerFactory = func(*server.Config) (runtimeServer, error) { return candidate, nil }
	service.serveRuntime = func(runtimeServer) error {
		<-candidateServeRelease
		return nil
	}
	service.serveHandshake = func(start func(), started <-chan struct{}, _ <-chan error) error {
		start()
		<-started
		return nil
	}

	reloadDone := make(chan error, 1)
	go func() { reloadDone <- service.reloadNode(newReloadNode(9443, "new.example.com")) }()
	<-oldClosed
	select {
	case <-candidateBuildEntered:
		t.Fatal("candidate build started before the old watcher completed")
	default:
	}
	close(releaseOldWatcher)
	<-candidateBuildEntered
	if err := <-reloadDone; err != nil {
		t.Fatalf("reloadNode() error = %v", err)
	}
	if err := service.Close(); err != nil {
		t.Fatalf("Close() error = %v", err)
	}
}

func TestReloadServeResultIsObservableWithoutWatcherLeak(t *testing.T) {
	serveErr := errors.New("candidate serve failed after claimed readiness")
	service, _, _ := newReloadTestService()
	candidate := &fakeRuntimeServer{events: &lifecycleEvents{}}
	service.reloadServerConfigFactory = func(*Hysteria2Service, serverBuildSpec) (*server.Config, error) {
		return &server.Config{}, nil
	}
	service.runtimeServerFactory = func(*server.Config) (runtimeServer, error) { return candidate, nil }
	service.closeRuntime = func(runtimeServer) error { return nil }
	service.serveRuntime = func(runtimeServer) error { return serveErr }
	service.serveHandshake = func(start func(), _ <-chan struct{}, result <-chan error) error {
		start()
		if err := <-result; !errors.Is(err, serveErr) {
			t.Fatalf("handshake observed Serve error %v, want %v", err, serveErr)
		}
		return nil
	}

	if err := service.reloadNode(newReloadNode(10443, "new.example.com")); err != nil {
		t.Fatalf("reloadNode() error = %v", err)
	}
	watcherDone := service.watcherDone
	select {
	case <-watcherDone:
	case <-time.After(time.Second):
		t.Fatal("watcher leaked after the handshake observed the Serve result")
	}
	service.lifecycleMu.Lock()
	state, runtimeErr := service.state, service.runtimeErr
	service.lifecycleMu.Unlock()
	if state != stateFailed || !errors.Is(runtimeErr, serveErr) {
		t.Fatalf("Serve result was lost: state=%v runtimeErr=%v", state, runtimeErr)
	}
	closeDone := make(chan error, 1)
	go func() { closeDone <- service.Close() }()
	select {
	case err := <-closeDone:
		if err != nil {
			t.Fatalf("Close() error = %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("Close() hung after the handshake observed the Serve result")
	}
}

func TestReloadRestorationFailureJoinsErrorsAndRecordsFailure(t *testing.T) {
	serveErr := errors.New("candidate serve failed")
	restoreErr := errors.New("old runtime restore failed")
	service, _, _ := newReloadTestService()
	candidate := &fakeRuntimeServer{events: &lifecycleEvents{}}
	builds := 0
	service.reloadServerConfigFactory = func(*Hysteria2Service, serverBuildSpec) (*server.Config, error) {
		builds++
		if builds == 1 {
			return &server.Config{}, nil
		}
		return nil, restoreErr
	}
	service.runtimeServerFactory = func(*server.Config) (runtimeServer, error) { return candidate, nil }
	service.serveRuntime = func(runtimeServer) error { return serveErr }
	service.serveHandshake = func(start func(), _ <-chan struct{}, result <-chan error) error {
		start()
		return <-result
	}
	service.closeRuntime = func(runtimeServer) error { return nil }

	err := service.reloadNode(newReloadNode(9443, "new.example.com"))
	if !errors.Is(err, serveErr) || !errors.Is(err, restoreErr) {
		t.Fatalf("reloadNode() error = %v, want joined serve and restore errors", err)
	}
	if service.state != stateFailed || !errors.Is(service.runtimeErr, serveErr) || !errors.Is(service.runtimeErr, restoreErr) {
		t.Fatalf("state/error = %v/%v, want failed with joined reload errors", service.state, service.runtimeErr)
	}
}

func TestReloadSurfacesOldCloseFailureAfterSuccessfulReplacement(t *testing.T) {
	closeErr := errors.New("old close failed")
	service, oldRuntime, _ := newReloadTestService()
	candidate := &fakeRuntimeServer{events: &lifecycleEvents{}}
	service.reloadServerConfigFactory = func(*Hysteria2Service, serverBuildSpec) (*server.Config, error) { return &server.Config{}, nil }
	service.runtimeServerFactory = func(*server.Config) (runtimeServer, error) { return candidate, nil }
	service.closeRuntime = func(runtime runtimeServer) error {
		if runtime == oldRuntime {
			return closeErr
		}
		return nil
	}
	service.serveRuntime = func(runtimeServer) error { return nil }
	service.serveHandshake = func(start func(), _ <-chan struct{}, result <-chan error) error {
		start()
		return <-result
	}

	err := service.reloadNode(newReloadNode(10443, "new.example.com"))
	if !errors.Is(err, closeErr) {
		t.Fatalf("reloadNode() error = %v, want surfaced old close error %v", err, closeErr)
	}
	if service.server != candidate || service.nodeInfo.Port != 10443 {
		t.Fatalf("successful replacement not published after old close error: server=%v node=%v", service.server, service.nodeInfo)
	}
}

func TestReloadPublishesRuntimeRulesAndOwnershipOnlyAfterServeReady(t *testing.T) {
	service, oldRuntime, oldNode := newReloadTestService()
	oldServeDone := service.serveDone
	oldWatcherDone := service.watcherDone
	oldRules := []portHopRule{{FromPortStart: 30001, FromPortEnd: 30002, ToPort: 9443}}
	service.portHopRules = append([]portHopRule(nil), oldRules...)
	candidate := &fakeRuntimeServer{events: &lifecycleEvents{}}
	serveEntered := make(chan struct{})
	releaseServe := make(chan struct{})
	releaseHandshake := make(chan struct{})
	service.reloadServerConfigFactory = func(*Hysteria2Service, serverBuildSpec) (*server.Config, error) { return &server.Config{}, nil }
	service.runtimeServerFactory = func(*server.Config) (runtimeServer, error) { return candidate, nil }
	service.closeRuntime = func(runtimeServer) error { return nil }
	service.serveRuntime = func(runtimeServer) error {
		close(serveEntered)
		<-releaseServe
		return nil
	}
	service.serveHandshake = func(start func(), _ <-chan struct{}, _ <-chan error) error {
		start()
		<-serveEntered
		<-releaseHandshake
		return nil
	}
	originalApply, originalDelete := applyPortHopRules, deletePortHopRules
	defer func() {
		applyPortHopRules = originalApply
		deletePortHopRules = originalDelete
	}()
	ruleEvents := &lifecycleEvents{}
	applyPortHopRules = func([]portHopRule, *log.Entry) error { ruleEvents.add("rules:apply"); return nil }
	deletePortHopRules = func([]portHopRule, *log.Entry) error { ruleEvents.add("rules:delete"); return nil }

	done := make(chan error, 1)
	go func() { done <- service.reloadNode(newReloadNode(10443, "new.example.com")) }()
	<-serveEntered

	service.lifecycleMu.Lock()
	premature := service.server != oldRuntime || service.nodeInfo != oldNode || service.tag != "Hysteria2_127.0.0.1_9443_9" || service.config.CertConfig.CertDomain != "old.example.com" || service.state != stateReloading || !reflect.DeepEqual(service.portHopRules, oldRules) || service.serveDone != oldServeDone || service.watcherDone != oldWatcherDone
	service.lifecycleMu.Unlock()
	rulesPremature := len(ruleEvents.snapshot()) != 0
	close(releaseHandshake)
	if err := <-done; err != nil {
		t.Fatalf("reloadNode() error = %v", err)
	}
	if premature || rulesPremature {
		t.Fatal("reload published candidate runtime, node, tag, certificate state, rules, or goroutine ownership before Serve readiness")
	}
	if service.server != candidate || service.nodeInfo.Port != 10443 || service.tag != "Hysteria2_127.0.0.1_9443_9" || service.config.CertConfig.CertDomain != "new.example.com" || service.state != stateRunning || service.serveDone == nil || service.watcherDone == nil {
		t.Fatalf("successful reload state = server:%v node:%v tag:%q cert:%q state:%v serveDone:%v watcherDone:%v", service.server, service.nodeInfo, service.tag, service.config.CertConfig.CertDomain, service.state, service.serveDone, service.watcherDone)
	}
	watcherDone := service.watcherDone
	close(releaseServe)
	<-watcherDone
}

func TestReloadHoldsSerializationUntilServeReadiness(t *testing.T) {
	service, _, _ := newReloadTestService()
	candidate := &fakeRuntimeServer{events: &lifecycleEvents{}}
	serveEntered := make(chan struct{})
	releaseServe := make(chan struct{})
	service.reloadServerConfigFactory = func(*Hysteria2Service, serverBuildSpec) (*server.Config, error) { return &server.Config{}, nil }
	service.runtimeServerFactory = func(*server.Config) (runtimeServer, error) { return candidate, nil }
	service.closeRuntime = func(runtimeServer) error { return nil }
	service.serveRuntime = func(runtimeServer) error {
		close(serveEntered)
		<-releaseServe
		return nil
	}
	service.serveHandshake = func(start func(), _ <-chan struct{}, result <-chan error) error {
		start()
		return <-result
	}

	done := make(chan error, 1)
	go func() { done <- service.reloadNode(newReloadNode(10443, "new.example.com")) }()
	<-serveEntered
	locked := !service.reloadMu.TryLock()
	if !locked {
		service.reloadMu.Unlock()
	}
	close(releaseServe)
	if err := <-done; err != nil {
		t.Fatalf("reloadNode() error = %v", err)
	}
	if !locked {
		t.Fatal("reload serialization lock was released while Serve readiness was in flight")
	}
}

func TestConcurrentReloadsExecuteSequentially(t *testing.T) {
	service, _, _ := newReloadTestService()
	firstBuildEntered := make(chan struct{})
	releaseFirstBuild := make(chan struct{})
	secondBuildEntered := make(chan struct{})
	builds := 0
	service.reloadServerConfigFactory = func(_ *Hysteria2Service, spec serverBuildSpec) (*server.Config, error) {
		builds++
		switch spec.nodeInfo.Port {
		case 10443:
			close(firstBuildEntered)
			<-releaseFirstBuild
		case 11443:
			close(secondBuildEntered)
		}
		return &server.Config{}, nil
	}
	service.runtimeServerFactory = func(*server.Config) (runtimeServer, error) {
		block := make(chan struct{})
		return &fakeRuntimeServer{events: &lifecycleEvents{}, serveBlock: block}, nil
	}
	service.serveRuntime = defaultServeRuntime
	service.serveHandshake = func(start func(), started <-chan struct{}, _ <-chan error) error {
		start()
		<-started
		return nil
	}
	service.closeRuntime = defaultCloseRuntime

	firstDone := make(chan error, 1)
	go func() { firstDone <- service.reloadNode(newReloadNode(10443, "first.example.com")) }()
	<-firstBuildEntered
	secondAttempted := make(chan struct{})
	secondDone := make(chan error, 1)
	go func() {
		close(secondAttempted)
		secondDone <- service.reloadNode(newReloadNode(11443, "second.example.com"))
	}()
	<-secondAttempted
	select {
	case <-secondBuildEntered:
		t.Fatal("second reload entered candidate build before first reload completed")
	default:
	}
	close(releaseFirstBuild)
	if err := <-firstDone; err != nil {
		t.Fatalf("first reloadNode() error = %v", err)
	}
	<-secondBuildEntered
	if err := <-secondDone; err != nil {
		t.Fatalf("second reloadNode() error = %v", err)
	}
	if service.nodeInfo.Port != 11443 || builds != 2 {
		t.Fatalf("final applied port/builds = %d/%d, want 11443/2", service.nodeInfo.Port, builds)
	}
	if err := service.Close(); err != nil {
		t.Fatalf("Close() error = %v", err)
	}
}

func TestCertificateReloadUsesSameSerializedTransaction(t *testing.T) {
	service, _, _ := newReloadTestService()
	service.config.CertConfig.CertMode = "dns"
	candidate := &fakeRuntimeServer{events: &lifecycleEvents{}}
	renewEntered := make(chan struct{})
	releaseRenew := make(chan struct{})
	service.renewCertificate = func(*mylego.CertConfig) (string, string, bool, error) {
		close(renewEntered)
		<-releaseRenew
		return "renewed.cert", "renewed.key", true, nil
	}
	service.reloadServerConfigFactory = func(*Hysteria2Service, serverBuildSpec) (*server.Config, error) {
		return &server.Config{}, nil
	}
	service.runtimeServerFactory = func(*server.Config) (runtimeServer, error) { return candidate, nil }
	service.closeRuntime = func(runtimeServer) error { return nil }
	service.serveRuntime = func(runtimeServer) error { return nil }
	service.serveHandshake = func(start func(), _ <-chan struct{}, result <-chan error) error {
		start()
		return <-result
	}

	done := make(chan error, 1)
	go func() { done <- service.certMonitor() }()
	<-renewEntered
	locked := !service.reloadMu.TryLock()
	if !locked {
		service.reloadMu.Unlock()
	}
	close(releaseRenew)
	if err := <-done; err != nil {
		t.Fatalf("certMonitor() error = %v", err)
	}
	if !locked || service.server != candidate {
		t.Fatalf("certificate reload transaction = locked:%v server:%v", locked, service.server)
	}
}

func TestCertificateRenewalFailureIsReturnedWithoutReplacingRuntime(t *testing.T) {
	renewErr := errors.New("certificate renewal failed")
	service, oldRuntime, oldNode := newReloadTestService()
	service.config.CertConfig.CertMode = "dns"
	service.renewCertificate = func(*mylego.CertConfig) (string, string, bool, error) {
		return "", "", false, renewErr
	}
	service.reloadServerConfigFactory = func(*Hysteria2Service, serverBuildSpec) (*server.Config, error) {
		t.Fatal("certificate renewal failure attempted a runtime build")
		return nil, nil
	}

	err := service.certMonitor()
	if !errors.Is(err, renewErr) {
		t.Fatalf("certMonitor() error = %v, want %v", err, renewErr)
	}
	if service.server != oldRuntime || service.nodeInfo != oldNode || service.state != stateRunning {
		t.Fatalf("certificate renewal failure replaced applied state: server=%v node=%v state=%v", service.server, service.nodeInfo, service.state)
	}
}

func TestCertificateReloadBuildFailurePreservesLastKnownGoodRuntime(t *testing.T) {
	buildErr := errors.New("certificate candidate build failed")
	service, _, oldNode := newReloadTestService()
	service.config.CertConfig.CertMode = "dns"
	restored := &fakeRuntimeServer{events: &lifecycleEvents{}, serveBlock: make(chan struct{})}
	service.renewCertificate = func(*mylego.CertConfig) (string, string, bool, error) {
		return "renewed.cert", "renewed.key", true, nil
	}
	builds := 0
	service.reloadServerConfigFactory = func(*Hysteria2Service, serverBuildSpec) (*server.Config, error) {
		builds++
		if builds == 1 {
			return nil, buildErr
		}
		return &server.Config{}, nil
	}
	service.runtimeServerFactory = func(*server.Config) (runtimeServer, error) { return restored, nil }
	service.serveRuntime = defaultServeRuntime
	service.closeRuntime = defaultCloseRuntime
	service.serveHandshake = func(start func(), started <-chan struct{}, _ <-chan error) error {
		start()
		<-started
		return nil
	}
	t.Cleanup(func() { _ = service.Close() })

	err := service.certMonitor()
	if !errors.Is(err, buildErr) {
		t.Fatalf("certMonitor() error = %v, want %v", err, buildErr)
	}
	if service.server != restored || service.nodeInfo != oldNode || service.state != stateRunning {
		t.Fatalf("certificate reload failure replaced applied state: server=%v node=%v state=%v", service.server, service.nodeInfo, service.state)
	}
}

func TestSuccessfulReloadKeepsStableRuntimeTagAndDetectRules(t *testing.T) {
	service, _, _ := newReloadTestService()
	t.Cleanup(func() { _ = service.Close() })
	oldTag := service.tag
	pattern := regexp.MustCompile(`blocked\.example`)
	if err := service.rules.UpdateRule(oldTag, []api.DetectRule{{ID: 17, Pattern: pattern}}); err != nil {
		t.Fatalf("UpdateRule() error = %v", err)
	}
	candidate := &fakeRuntimeServer{events: &lifecycleEvents{}, serveBlock: make(chan struct{}), serving: make(chan struct{})}
	service.reloadServerConfigFactory = func(*Hysteria2Service, serverBuildSpec) (*server.Config, error) {
		return &server.Config{}, nil
	}
	service.runtimeServerFactory = func(*server.Config) (runtimeServer, error) { return candidate, nil }
	service.serveRuntime = defaultServeRuntime
	service.closeRuntime = defaultCloseRuntime
	service.serveHandshake = func(start func(), _ <-chan struct{}, _ <-chan error) error {
		start()
		<-candidate.serving
		return nil
	}

	if err := service.reloadNode(newReloadNode(10443, "new.example.com")); err != nil {
		t.Fatalf("reloadNode() error = %v", err)
	}
	if service.tag != oldTag {
		t.Fatalf("reload changed stable runtime tag: tag=%q want=%q", service.tag, oldTag)
	}
	if !service.rules.Detect(service.tag, "blocked.example:443", "17", "127.0.0.1") {
		t.Fatal("detect rules no longer apply after successful reload")
	}
}

func TestSuccessfulReloadPublishesNodeRateLimitWithRuntime(t *testing.T) {
	service, _, _ := newReloadTestService()
	t.Cleanup(func() { _ = service.Close() })
	service.nodeInfo.SpeedLimit = 10
	service.users["user"] = userRecord{UID: 1}
	oldLimiter := rate.NewLimiter(10, 10)
	service.rateLimiters = map[string]*rate.Limiter{"user": oldLimiter}
	candidate := &fakeRuntimeServer{events: &lifecycleEvents{}, serveBlock: make(chan struct{}), serving: make(chan struct{})}
	service.reloadServerConfigFactory = func(*Hysteria2Service, serverBuildSpec) (*server.Config, error) {
		return &server.Config{}, nil
	}
	service.runtimeServerFactory = func(*server.Config) (runtimeServer, error) { return candidate, nil }
	service.serveRuntime = defaultServeRuntime
	service.closeRuntime = defaultCloseRuntime
	service.serveHandshake = func(start func(), _ <-chan struct{}, _ <-chan error) error {
		start()
		<-candidate.serving
		return nil
	}
	candidateNode := newReloadNode(10443, "new.example.com")
	candidateNode.SpeedLimit = 20

	if err := service.reloadNode(candidateNode); err != nil {
		t.Fatalf("reloadNode() error = %v", err)
	}
	if limiter := service.rateLimiters["user"]; limiter != oldLimiter || limiter.Limit() != 20 {
		t.Fatalf("published limiter = %v/%v, want reused limiter with limit 20", limiter, limiter.Limit())
	}
}

func TestSuccessfulReloadSharesNewNodeLimiterAcrossUserAliases(t *testing.T) {
	service, _, _ := newReloadTestService()
	t.Cleanup(func() { _ = service.Close() })
	service.nodeInfo.SpeedLimit = 0
	users := []api.UserInfo{{UID: 0, UUID: "user-uuid", Passwd: "user-password"}}
	service.syncUsers(&users)
	candidate := &fakeRuntimeServer{events: &lifecycleEvents{}, serveBlock: make(chan struct{}), serving: make(chan struct{})}
	service.reloadServerConfigFactory = func(*Hysteria2Service, serverBuildSpec) (*server.Config, error) {
		return &server.Config{}, nil
	}
	service.runtimeServerFactory = func(*server.Config) (runtimeServer, error) { return candidate, nil }
	service.serveRuntime = defaultServeRuntime
	service.closeRuntime = defaultCloseRuntime
	service.serveHandshake = func(start func(), _ <-chan struct{}, _ <-chan error) error {
		start()
		<-candidate.serving
		return nil
	}
	candidateNode := newReloadNode(10443, "new.example.com")
	candidateNode.SpeedLimit = 20

	if err := service.reloadNode(candidateNode); err != nil {
		t.Fatalf("reloadNode() error = %v", err)
	}
	uuidLimiter := service.rateLimiters["user-uuid"]
	passwordLimiter := service.rateLimiters["user-password"]
	if uuidLimiter == nil || uuidLimiter != passwordLimiter {
		t.Fatalf("alias limiters = %v/%v, want one shared limiter", uuidLimiter, passwordLimiter)
	}
}

func TestReplacePortHopRulesRestoresOldRulesWhenNewApplyFails(t *testing.T) {
	applyErr := errors.New("apply new rules failed")
	service, _, _ := newReloadTestService()
	oldRules := []portHopRule{{FromPortStart: 30001, FromPortEnd: 30002, ToPort: 9443}}
	newRules := []portHopRule{{FromPortStart: 31001, FromPortEnd: 31002, ToPort: 10443}}
	service.portHopRules = append([]portHopRule(nil), oldRules...)
	events := &lifecycleEvents{}
	originalApply, originalDelete := applyPortHopRules, deletePortHopRules
	t.Cleanup(func() {
		applyPortHopRules = originalApply
		deletePortHopRules = originalDelete
	})
	deletePortHopRules = func(rules []portHopRule, _ *log.Entry) error {
		events.add("delete:old")
		return nil
	}
	applyCalls := 0
	applyPortHopRules = func(rules []portHopRule, _ *log.Entry) error {
		applyCalls++
		if applyCalls == 1 {
			events.add("apply:new")
			return applyErr
		}
		events.add("apply:old")
		return nil
	}

	_, err := service.replacePortHopRulesLocked(newRules)
	if !errors.Is(err, applyErr) {
		t.Fatalf("replacePortHopRulesLocked() error = %v, want %v", err, applyErr)
	}
	if got, want := events.snapshot(), []string{"delete:old", "apply:new", "apply:old"}; !reflect.DeepEqual(got, want) {
		t.Fatalf("port-hop events = %v, want %v", got, want)
	}
	if !reflect.DeepEqual(service.portHopRules, oldRules) {
		t.Fatalf("failed replacement published rules = %v, want %v", service.portHopRules, oldRules)
	}
}

func TestReloadPortHopRollbackFailureDoesNotPublishFalseOwnership(t *testing.T) {
	applyErr := errors.New("apply new rules failed")
	rulesRestoreErr := errors.New("restore old rules failed")
	candidateCloseErr := errors.New("candidate close failed")
	restoredServeErr := errors.New("restored runtime serve failed")
	service, oldRuntime, oldNode := newReloadTestService()
	oldRules := []portHopRule{{FromPortStart: 30001, FromPortEnd: 30002, ToPort: 9443}}
	service.portHopRules = append([]portHopRule(nil), oldRules...)
	candidate := &fakeRuntimeServer{events: &lifecycleEvents{}, serveBlock: make(chan struct{})}
	restored := &fakeRuntimeServer{events: &lifecycleEvents{}, serveBlock: make(chan struct{}), serveErr: restoredServeErr}
	builds := 0
	service.reloadServerConfigFactory = func(*Hysteria2Service, serverBuildSpec) (*server.Config, error) {
		builds++
		return &server.Config{}, nil
	}
	service.runtimeServerFactory = func(*server.Config) (runtimeServer, error) {
		if builds == 1 {
			return candidate, nil
		}
		return restored, nil
	}
	service.serveRuntime = defaultServeRuntime
	service.serveHandshake = func(start func(), started <-chan struct{}, _ <-chan error) error {
		start()
		<-started
		return nil
	}
	service.closeRuntime = func(runtime runtimeServer) error {
		if runtime == oldRuntime {
			return nil
		}
		err := runtime.Close()
		if runtime == candidate {
			return errors.Join(err, candidateCloseErr)
		}
		return err
	}
	originalApply, originalDelete := applyPortHopRules, deletePortHopRules
	t.Cleanup(func() {
		applyPortHopRules = originalApply
		deletePortHopRules = originalDelete
		_ = service.Close()
	})
	deletePortHopRules = func([]portHopRule, *log.Entry) error { return nil }
	applyCalls := 0
	applyPortHopRules = func([]portHopRule, *log.Entry) error {
		applyCalls++
		if applyCalls == 1 {
			return applyErr
		}
		return rulesRestoreErr
	}
	newNode := newReloadNode(10443, "new.example.com")
	newNode.Hysteria2Config.PortHopEnabled = true
	newNode.Hysteria2Config.PortHopPorts = "31001-31002"

	err := service.reloadNode(newNode)
	for _, wantErr := range []error{applyErr, rulesRestoreErr, candidateCloseErr} {
		if !errors.Is(err, wantErr) {
			t.Fatalf("reloadNode() error = %v, want joined %v", err, wantErr)
		}
	}
	if service.server != restored || service.nodeInfo != oldNode {
		t.Fatalf("runtime restoration = server:%v node:%v, want restored runtime and old node", service.server, service.nodeInfo)
	}
	if service.state != stateFailed || !errors.Is(service.runtimeErr, rulesRestoreErr) {
		t.Fatalf("rollback failure state/error = %v/%v, want failed with restore error", service.state, service.runtimeErr)
	}
	if len(service.portHopRules) != 0 {
		t.Fatalf("rollback failure published false port-hop ownership: %v", service.portHopRules)
	}
	watcherDone := service.watcherDone
	close(restored.serveBlock)
	<-watcherDone
	service.lifecycleMu.Lock()
	runtimeErr := service.runtimeErr
	service.lifecycleMu.Unlock()
	if !errors.Is(runtimeErr, rulesRestoreErr) || !errors.Is(runtimeErr, restoredServeErr) {
		t.Fatalf("restored runtime error = %v, want existing rollback and later Serve errors", runtimeErr)
	}
}

func TestCloseRacingWithReloadIsRejectedWithoutMutation(t *testing.T) {
	service, _, _ := newReloadTestService()
	candidate := &fakeRuntimeServer{events: &lifecycleEvents{}}
	serveEntered := make(chan struct{})
	releaseServe := make(chan struct{})
	service.reloadServerConfigFactory = func(*Hysteria2Service, serverBuildSpec) (*server.Config, error) { return &server.Config{}, nil }
	service.runtimeServerFactory = func(*server.Config) (runtimeServer, error) { return candidate, nil }
	service.closeRuntime = func(runtimeServer) error { return nil }
	service.serveRuntime = func(runtimeServer) error {
		close(serveEntered)
		<-releaseServe
		return nil
	}
	service.serveHandshake = func(start func(), _ <-chan struct{}, result <-chan error) error {
		start()
		return <-result
	}

	done := make(chan error, 1)
	go func() { done <- service.reloadNode(newReloadNode(10443, "new.example.com")) }()
	<-serveEntered
	closeErr := service.Close()
	closed, state := service.closed, service.state
	close(releaseServe)
	if err := <-done; err != nil {
		t.Fatalf("reloadNode() error = %v", err)
	}
	if closeErr == nil || closed || state != stateReloading {
		t.Fatalf("Close during reload = error:%v closed:%v state:%v, want rejection without mutation", closeErr, closed, state)
	}
}
