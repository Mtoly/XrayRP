package tuic

import (
	"bytes"
	"errors"
	"go/ast"
	"go/parser"
	"go/token"
	"reflect"
	"regexp"
	"strings"
	"testing"

	"github.com/Mtoly/XrayRP/api"
	"github.com/Mtoly/XrayRP/common/mylego"
	"github.com/Mtoly/XrayRP/service/controller"
	log "github.com/sirupsen/logrus"
	"golang.org/x/time/rate"
)

type reloadRuntime struct{ name string }

func (*reloadRuntime) Start() error { return nil }
func (*reloadRuntime) Close() error { return nil }

type fakePreparedRenewal struct {
	renewed       bool
	certificate   []byte
	privateKey    []byte
	commitErr     error
	rollbackErr   error
	commitCalls   int
	rollbackCalls int
	closed        bool
	onCommit      func()
	onRollback    func()
}

func (r *fakePreparedRenewal) Renewed() bool          { return r.renewed }
func (r *fakePreparedRenewal) CertificatePEM() []byte { return append([]byte(nil), r.certificate...) }
func (r *fakePreparedRenewal) PrivateKeyPEM() []byte  { return append([]byte(nil), r.privateKey...) }
func (r *fakePreparedRenewal) Commit() error {
	if r.closed {
		return errors.New("prepared renewal already closed")
	}
	r.commitCalls++
	r.closed = true
	if r.onCommit != nil {
		r.onCommit()
	}
	return r.commitErr
}
func (r *fakePreparedRenewal) Rollback() error {
	if r.closed {
		return nil
	}
	r.rollbackCalls++
	r.closed = true
	if r.onRollback != nil {
		r.onRollback()
	}
	return r.rollbackErr
}

func newReloadTestService() (*TuicService, *reloadRuntime, *api.NodeInfo) {
	oldNode := &api.NodeInfo{
		NodeType: "Tuic", NodeID: 8, Port: 8443, EnableTLS: true,
		SNI: "old.example.com", TuicConfig: &api.TuicConfig{ALPN: []string{"h3"}},
	}
	oldRuntime := &reloadRuntime{name: "old"}
	service := New(&configurablePanelClient{}, &controller.Config{
		ListenIP: "127.0.0.1",
		CertConfig: &mylego.CertConfig{
			CertMode: "file", CertDomain: "old.example.com", CertFile: "old.cert", KeyFile: "old.key",
		},
	})
	service.state = stateRunning
	service.nodeInfo = oldNode
	service.box = oldRuntime
	service.tag = "Tuic_127.0.0.1_8443_8"
	service.inboundTag = service.tag
	return service, oldRuntime, oldNode
}

func newReloadNode(port uint32, sni string) *api.NodeInfo {
	return &api.NodeInfo{
		NodeType: "Tuic", NodeID: 8, Port: port, EnableTLS: true, SNI: sni,
		TuicConfig: &api.TuicConfig{ALPN: []string{"h3"}},
	}
}

func TestRuntimeCallbacksReadTagThroughAppliedSnapshot(t *testing.T) {
	file, err := parser.ParseFile(token.NewFileSet(), "hook.go", nil, 0)
	if err != nil {
		t.Fatalf("parse hook.go: %v", err)
	}
	ast.Inspect(file, func(node ast.Node) bool {
		selector, ok := node.(*ast.SelectorExpr)
		if ok && selector.Sel.Name == "tag" {
			t.Errorf("hook.go reads tag directly; runtime callbacks must use appliedTag")
		}
		return true
	})
}

func TestReloadNilNodeInfoIsNoOp(t *testing.T) {
	service, oldRuntime, oldNode := newReloadTestService()
	called := false
	service.runtimeFactory = func(*TuicService) (runtimeInstance, string, error) {
		called = true
		return nil, "", nil
	}

	if err := service.reloadNode(nil); err != nil {
		t.Fatalf("reloadNode(nil) error = %v", err)
	}
	if called || service.box != oldRuntime || service.nodeInfo != oldNode {
		t.Fatalf("nil reload mutated state: called=%v box=%v nodeInfo=%v", called, service.box, service.nodeInfo)
	}
}

func TestReloadRejectsInvalidCandidateWithoutMutation(t *testing.T) {
	tests := []struct {
		name string
		node *api.NodeInfo
	}{
		{name: "wrong type", node: &api.NodeInfo{NodeType: "AnyTLS", Port: 8443}},
		{name: "zero port", node: newReloadNode(0, "new.example.com")},
		{name: "port above uint16", node: newReloadNode(65536, "new.example.com")},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			service, oldRuntime, oldNode := newReloadTestService()
			oldCert := *service.config.CertConfig
			called := false
			service.reloadRuntimeFactory = func(*TuicService, runtimeBuildSpec) (runtimeInstance, string, error) {
				called = true
				return nil, "", errors.New("unexpected candidate build")
			}

			if err := service.reloadNode(tc.node); err == nil {
				t.Fatal("reloadNode() error = nil, want validation error")
			}
			if called || service.box != oldRuntime || service.nodeInfo != oldNode || !reflect.DeepEqual(*service.config.CertConfig, oldCert) {
				t.Fatalf("invalid reload mutated state: called=%v box=%v nodeInfo=%v cert=%+v", called, service.box, service.nodeInfo, service.config.CertConfig)
			}
		})
	}
}

func TestReloadRequiresExplicitCandidateFactory(t *testing.T) {
	service, _, _ := newReloadTestService()
	legacyCalled := false
	service.reloadRuntimeFactory = nil
	service.runtimeFactory = func(*TuicService) (runtimeInstance, string, error) {
		legacyCalled = true
		return &reloadRuntime{name: "legacy"}, "legacy-inbound", nil
	}

	_, _, err := service.buildReloadRuntime(runtimeBuildSpec{
		nodeInfo:   newReloadNode(9443, "new.example.com"),
		inboundTag: service.inboundTag,
		certConfig: cloneCertConfig(service.config.CertConfig),
	})
	if err == nil {
		t.Fatal("buildReloadRuntime() error = nil, want missing explicit candidate factory error")
	}
	if legacyCalled {
		t.Fatal("buildReloadRuntime() called legacy factory that reads mutable service fields")
	}
}

func TestReloadBuildFailureRetainsOldRuntimeAndAppliedState(t *testing.T) {
	buildErr := errors.New("candidate build failed")
	service, oldRuntime, oldNode := newReloadTestService()
	oldTag, oldInboundTag := service.tag, service.inboundTag
	oldCert := *service.config.CertConfig
	events := &lifecycleEvents{}
	service.closeRuntime = func(runtime runtimeInstance) error {
		events.add("close:" + runtime.(*reloadRuntime).name)
		return nil
	}
	service.reloadRuntimeFactory = func(*TuicService, runtimeBuildSpec) (runtimeInstance, string, error) {
		events.add("build:candidate")
		return nil, "", buildErr
	}

	err := service.reloadNode(newReloadNode(9443, "new.example.com"))
	if !errors.Is(err, buildErr) {
		t.Fatalf("reloadNode() error = %v, want %v", err, buildErr)
	}
	if service.box != oldRuntime || service.nodeInfo != oldNode || service.tag != oldTag || service.inboundTag != oldInboundTag {
		t.Fatalf("build failure lost old state: box=%v nodeInfo=%v tag=%q inboundTag=%q", service.box, service.nodeInfo, service.tag, service.inboundTag)
	}
	if !reflect.DeepEqual(*service.config.CertConfig, oldCert) {
		t.Fatalf("build failure published certificate state: got=%+v want=%+v", service.config.CertConfig, oldCert)
	}
	if got := events.snapshot(); !reflect.DeepEqual(got, []string{"build:candidate"}) {
		t.Fatalf("events = %v, want candidate validation without closing old runtime", got)
	}
}

func TestReloadStartFailureCleansCandidateAndRestoresOldRuntime(t *testing.T) {
	startErr := errors.New("candidate start failed")
	service, _, oldNode := newReloadTestService()
	candidate := &reloadRuntime{name: "candidate"}
	restored := &reloadRuntime{name: "restored"}
	events := &lifecycleEvents{}
	builds := 0
	service.reloadRuntimeFactory = func(_ *TuicService, spec runtimeBuildSpec) (runtimeInstance, string, error) {
		builds++
		if builds == 1 {
			events.add("build:candidate")
			return candidate, spec.inboundTag, nil
		}
		events.add("build:restore")
		return restored, spec.inboundTag, nil
	}
	service.closeRuntime = func(runtime runtimeInstance) error {
		events.add("close:" + runtime.(*reloadRuntime).name)
		return nil
	}
	service.startRuntime = func(runtime runtimeInstance) error {
		name := runtime.(*reloadRuntime).name
		events.add("start:" + name)
		if name == "candidate" {
			return startErr
		}
		return nil
	}

	err := service.reloadNode(newReloadNode(9443, "new.example.com"))
	if !errors.Is(err, startErr) {
		t.Fatalf("reloadNode() error = %v, want %v", err, startErr)
	}
	if service.box != restored || service.nodeInfo != oldNode {
		t.Fatalf("start failure did not restore old runtime: box=%v nodeInfo=%v", service.box, service.nodeInfo)
	}
	want := []string{"build:candidate", "close:old", "start:candidate", "close:candidate", "build:restore", "start:restored"}
	if got := events.snapshot(); !reflect.DeepEqual(got, want) {
		t.Fatalf("events = %v, want %v", got, want)
	}
}

func TestReloadRestorationFailureJoinsErrorsAndRecordsFailure(t *testing.T) {
	startErr := errors.New("candidate start failed")
	restoreErr := errors.New("old runtime restore failed")
	service, _, _ := newReloadTestService()
	candidate := &reloadRuntime{name: "candidate"}
	builds := 0
	service.reloadRuntimeFactory = func(_ *TuicService, spec runtimeBuildSpec) (runtimeInstance, string, error) {
		builds++
		if builds == 1 {
			return candidate, spec.inboundTag, nil
		}
		return nil, "", restoreErr
	}
	service.startRuntime = func(runtime runtimeInstance) error {
		if runtime == candidate {
			return startErr
		}
		return nil
	}
	service.closeRuntime = func(runtimeInstance) error { return nil }

	err := service.reloadNode(newReloadNode(9443, "new.example.com"))
	if !errors.Is(err, startErr) || !errors.Is(err, restoreErr) {
		t.Fatalf("reloadNode() error = %v, want joined start and restore errors", err)
	}
	if service.state != stateFailed || !errors.Is(service.runtimeErr, startErr) || !errors.Is(service.runtimeErr, restoreErr) {
		t.Fatalf("state/error = %v/%v, want failed with joined reload errors", service.state, service.runtimeErr)
	}
}

func TestReloadSurfacesOldCloseFailureAfterSuccessfulReplacement(t *testing.T) {
	closeErr := errors.New("old close failed")
	service, oldRuntime, _ := newReloadTestService()
	candidate := &reloadRuntime{name: "candidate"}
	service.reloadRuntimeFactory = func(_ *TuicService, spec runtimeBuildSpec) (runtimeInstance, string, error) {
		return candidate, spec.inboundTag, nil
	}
	service.closeRuntime = func(runtime runtimeInstance) error {
		if runtime == oldRuntime {
			return closeErr
		}
		return nil
	}
	service.startRuntime = func(runtimeInstance) error { return nil }

	err := service.reloadNode(newReloadNode(9443, "new.example.com"))
	if !errors.Is(err, closeErr) {
		t.Fatalf("reloadNode() error = %v, want surfaced old close error %v", err, closeErr)
	}
	if service.box != candidate || service.nodeInfo.Port != 9443 {
		t.Fatalf("successful replacement not published after old close error: box=%v node=%v", service.box, service.nodeInfo)
	}
}

func TestReloadPublishesCandidateOnlyAfterSynchronousStart(t *testing.T) {
	service, oldRuntime, oldNode := newReloadTestService()
	candidate := &reloadRuntime{name: "candidate"}
	startEntered := make(chan struct{})
	releaseStart := make(chan struct{})
	service.reloadRuntimeFactory = func(_ *TuicService, spec runtimeBuildSpec) (runtimeInstance, string, error) {
		return candidate, spec.inboundTag, nil
	}
	service.closeRuntime = func(runtimeInstance) error { return nil }
	service.startRuntime = func(runtimeInstance) error {
		close(startEntered)
		<-releaseStart
		return nil
	}

	done := make(chan error, 1)
	go func() { done <- service.reloadNode(newReloadNode(9443, "new.example.com")) }()
	<-startEntered

	service.lifecycleMu.Lock()
	premature := service.box != oldRuntime || service.nodeInfo != oldNode || service.tag != "Tuic_127.0.0.1_8443_8" || service.inboundTag != "Tuic_127.0.0.1_8443_8" || service.config.CertConfig.CertDomain != "old.example.com" || service.state != stateReloading
	service.lifecycleMu.Unlock()
	close(releaseStart)
	if err := <-done; err != nil {
		t.Fatalf("reloadNode() error = %v", err)
	}
	if premature {
		t.Fatal("reload published candidate state before candidate start completed")
	}
	if service.box != candidate || service.nodeInfo.Port != 9443 || service.tag != "Tuic_127.0.0.1_8443_8" || service.inboundTag != "Tuic_127.0.0.1_8443_8" || service.config.CertConfig.CertDomain != "new.example.com" || service.state != stateRunning {
		t.Fatalf("successful reload state = box:%v node:%v tag:%q inbound:%q cert:%q state:%v", service.box, service.nodeInfo, service.tag, service.inboundTag, service.config.CertConfig.CertDomain, service.state)
	}
}

func TestReloadHoldsSerializationUntilCandidateStartCompletes(t *testing.T) {
	service, _, _ := newReloadTestService()
	candidate := &reloadRuntime{name: "candidate"}
	startEntered := make(chan struct{})
	releaseStart := make(chan struct{})
	service.reloadRuntimeFactory = func(_ *TuicService, spec runtimeBuildSpec) (runtimeInstance, string, error) {
		return candidate, spec.inboundTag, nil
	}
	service.closeRuntime = func(runtimeInstance) error { return nil }
	service.startRuntime = func(runtimeInstance) error {
		close(startEntered)
		<-releaseStart
		return nil
	}

	done := make(chan error, 1)
	go func() { done <- service.reloadNode(newReloadNode(9443, "new.example.com")) }()
	<-startEntered
	locked := !service.reloadMu.TryLock()
	if !locked {
		service.reloadMu.Unlock()
	}
	close(releaseStart)
	if err := <-done; err != nil {
		t.Fatalf("reloadNode() error = %v", err)
	}
	if !locked {
		t.Fatal("reload serialization lock was released while candidate start was still in flight")
	}
}

func TestConcurrentReloadsExecuteSequentially(t *testing.T) {
	service, _, _ := newReloadTestService()
	firstBuildEntered := make(chan struct{})
	releaseFirstBuild := make(chan struct{})
	secondBuildEntered := make(chan struct{})
	service.reloadRuntimeFactory = func(_ *TuicService, spec runtimeBuildSpec) (runtimeInstance, string, error) {
		switch spec.nodeInfo.Port {
		case 9443:
			close(firstBuildEntered)
			<-releaseFirstBuild
		case 10443:
			close(secondBuildEntered)
		}
		return &reloadRuntime{name: "candidate"}, spec.inboundTag, nil
	}
	service.closeRuntime = func(runtimeInstance) error { return nil }
	service.startRuntime = func(runtimeInstance) error { return nil }

	firstDone := make(chan error, 1)
	go func() { firstDone <- service.reloadNode(newReloadNode(9443, "first.example.com")) }()
	<-firstBuildEntered
	secondAttempted := make(chan struct{})
	secondDone := make(chan error, 1)
	go func() {
		close(secondAttempted)
		secondDone <- service.reloadNode(newReloadNode(10443, "second.example.com"))
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
	if service.nodeInfo.Port != 10443 {
		t.Fatalf("final applied port = %d, want second reload port 10443", service.nodeInfo.Port)
	}
}

func TestCertificateReloadUsesSameSerializedTransaction(t *testing.T) {
	service, oldRuntime, _ := newReloadTestService()
	service.config.CertConfig.CertMode = "dns"
	candidate := &reloadRuntime{name: "candidate"}
	renewEntered := make(chan struct{})
	releaseRenew := make(chan struct{})
	service.prepareRenewal = func(*mylego.CertConfig) (preparedCertificateRenewal, error) {
		close(renewEntered)
		<-releaseRenew
		return &fakePreparedRenewal{
			renewed:     true,
			certificate: []byte("candidate-cert"),
			privateKey:  []byte("candidate-key"),
		}, nil
	}
	service.reloadRuntimeFactory = func(*TuicService, runtimeBuildSpec) (runtimeInstance, string, error) {
		return candidate, "candidate-inbound", nil
	}
	service.closeRuntime = func(runtimeInstance) error { return nil }
	service.startRuntime = func(runtimeInstance) error { return nil }

	done := make(chan error, 1)
	go func() { done <- service.certMonitor() }()
	<-renewEntered
	locked := !service.reloadMu.TryLock()
	if !locked {
		service.reloadMu.Unlock()
	}
	if closeErr := service.Close(); closeErr == nil {
		close(releaseRenew)
		<-done
		t.Fatal("Close() succeeded while certificate reload transaction was active")
	}
	runtimeAfterRejectedClose := service.box
	stateAfterRejectedClose := service.state
	if runtimeAfterRejectedClose != oldRuntime || stateAfterRejectedClose != stateReloading {
		close(releaseRenew)
		<-done
		t.Fatalf("rejected Close() mutated active transaction: box=%v state=%d", runtimeAfterRejectedClose, stateAfterRejectedClose)
	}
	close(releaseRenew)
	if err := <-done; err != nil {
		t.Fatalf("certMonitor() error = %v", err)
	}
	if !locked || service.box != candidate {
		t.Fatalf("certificate reload transaction = locked:%v box:%v", locked, service.box)
	}
}

func TestCertificateRenewalFailureIsReturnedWithoutReplacingRuntime(t *testing.T) {
	renewErr := errors.New("certificate renewal failed")
	service, oldRuntime, oldNode := newReloadTestService()
	service.config.CertConfig.CertMode = "dns"
	service.prepareRenewal = func(*mylego.CertConfig) (preparedCertificateRenewal, error) {
		return nil, renewErr
	}
	service.reloadRuntimeFactory = func(*TuicService, runtimeBuildSpec) (runtimeInstance, string, error) {
		t.Fatal("certificate renewal failure attempted a runtime build")
		return nil, "", nil
	}

	err := service.certMonitor()
	if !errors.Is(err, renewErr) {
		t.Fatalf("certMonitor() error = %v, want %v", err, renewErr)
	}
	if service.box != oldRuntime || service.nodeInfo != oldNode || service.state != stateRunning {
		t.Fatalf("certificate renewal failure replaced applied state: box=%v node=%v state=%v", service.box, service.nodeInfo, service.state)
	}
}

func TestCertificateRenewalWithoutCandidatePEMDoesNotReloadOrCommit(t *testing.T) {
	service, oldRuntime, oldNode := newReloadTestService()
	service.config.CertConfig.CertMode = "dns"
	prepared := &fakePreparedRenewal{renewed: true}
	service.prepareRenewal = func(*mylego.CertConfig) (preparedCertificateRenewal, error) {
		return prepared, nil
	}
	service.reloadRuntimeFactory = func(*TuicService, runtimeBuildSpec) (runtimeInstance, string, error) {
		t.Fatal("incomplete certificate renewal attempted a runtime build")
		return nil, "", nil
	}

	err := service.certMonitor()
	if err == nil {
		t.Fatal("certMonitor() succeeded with incomplete candidate certificate")
	}
	if prepared.commitCalls != 0 || prepared.rollbackCalls != 1 {
		t.Fatalf("prepared renewal completion = commit:%d rollback:%d, want 0/1", prepared.commitCalls, prepared.rollbackCalls)
	}
	if service.box != oldRuntime || service.nodeInfo != oldNode || service.state != stateRunning {
		t.Fatalf("incomplete candidate certificate replaced applied state: box=%v node=%v state=%v", service.box, service.nodeInfo, service.state)
	}
}

func TestCertificateMonitorPeriodicRedactsFailureAndRetries(t *testing.T) {
	const secret = "acme-token-secret"
	service, _, _ := newReloadTestService()
	service.config.CertConfig.CertMode = "dns"
	var logs bytes.Buffer
	logger := log.New()
	logger.SetOutput(&logs)
	logger.SetFormatter(&log.TextFormatter{DisableTimestamp: true})
	service.logger = log.NewEntry(logger)

	renewCalls := 0
	service.prepareRenewal = func(*mylego.CertConfig) (preparedCertificateRenewal, error) {
		renewCalls++
		if renewCalls == 1 {
			return nil, errors.New(secret)
		}
		return &fakePreparedRenewal{}, nil
	}

	if err := service.certMonitorPeriodic(); err != nil {
		t.Fatalf("first certMonitorPeriodic() error = %v", err)
	}
	if renewCalls != 1 {
		t.Fatalf("renew calls after first attempt = %d, want 1", renewCalls)
	}
	if strings.Contains(logs.String(), secret) {
		t.Fatalf("periodic certificate log exposed sensitive error: %q", logs.String())
	}
	if !strings.Contains(logs.String(), "certificate monitor failed; will retry") {
		t.Fatalf("periodic certificate log = %q, want redacted retry message", logs.String())
	}

	if err := service.certMonitorPeriodic(); err != nil {
		t.Fatalf("second certMonitorPeriodic() error = %v", err)
	}
	if renewCalls != 2 {
		t.Fatalf("renew calls after retry = %d, want 2", renewCalls)
	}
}

func TestCertificateReloadBuildFailurePreservesLastKnownGoodRuntime(t *testing.T) {
	buildErr := errors.New("certificate candidate build failed")
	rollbackErr := errors.New("candidate rollback failed")
	service, oldRuntime, oldNode := newReloadTestService()
	service.config.CertConfig.CertMode = "dns"
	prepared := &fakePreparedRenewal{
		renewed:     true,
		certificate: []byte("candidate-cert"),
		privateKey:  []byte("candidate-key"),
		rollbackErr: rollbackErr,
	}
	service.prepareRenewal = func(*mylego.CertConfig) (preparedCertificateRenewal, error) {
		return prepared, nil
	}
	service.reloadRuntimeFactory = func(_ *TuicService, spec runtimeBuildSpec) (runtimeInstance, string, error) {
		if string(spec.certificatePEM) != "candidate-cert" || string(spec.privateKeyPEM) != "candidate-key" {
			t.Fatalf("candidate certificate material = %q/%q", spec.certificatePEM, spec.privateKeyPEM)
		}
		return nil, "", buildErr
	}

	err := service.certMonitor()
	if !errors.Is(err, buildErr) || !errors.Is(err, rollbackErr) {
		t.Fatalf("certMonitor() error = %v, want build %v and rollback %v", err, buildErr, rollbackErr)
	}
	if service.box != oldRuntime || service.nodeInfo != oldNode || service.state != stateRunning {
		t.Fatalf("certificate reload failure replaced applied state: box=%v node=%v state=%v", service.box, service.nodeInfo, service.state)
	}
	if prepared.commitCalls != 0 || prepared.rollbackCalls != 1 {
		t.Fatalf("candidate completion calls = commit:%d rollback:%d, want 0/1", prepared.commitCalls, prepared.rollbackCalls)
	}
}

func TestCertificateReloadCommitsAfterStartBeforePublication(t *testing.T) {
	service, oldRuntime, _ := newReloadTestService()
	service.config.CertConfig.CertMode = "dns"
	candidate := &reloadRuntime{name: "candidate"}
	started := false
	prepared := &fakePreparedRenewal{
		renewed:     true,
		certificate: []byte("candidate-cert"),
		privateKey:  []byte("candidate-key"),
	}
	prepared.onCommit = func() {
		if !started {
			t.Fatal("candidate certificate committed before runtime start")
		}
		if service.box != oldRuntime {
			t.Fatal("candidate runtime published before certificate commit")
		}
	}
	service.prepareRenewal = func(*mylego.CertConfig) (preparedCertificateRenewal, error) {
		return prepared, nil
	}
	service.reloadRuntimeFactory = func(_ *TuicService, spec runtimeBuildSpec) (runtimeInstance, string, error) {
		if string(spec.certificatePEM) != "candidate-cert" || string(spec.privateKeyPEM) != "candidate-key" {
			t.Fatalf("candidate certificate material = %q/%q", spec.certificatePEM, spec.privateKeyPEM)
		}
		return candidate, spec.inboundTag, nil
	}
	service.closeRuntime = func(runtimeInstance) error { return nil }
	service.startRuntime = func(runtime runtimeInstance) error {
		if runtime != candidate {
			t.Fatalf("started runtime = %v, want candidate", runtime)
		}
		if service.box != oldRuntime || prepared.commitCalls != 0 {
			t.Fatal("candidate state published or committed before start")
		}
		started = true
		return nil
	}

	if err := service.certMonitor(); err != nil {
		t.Fatalf("certMonitor() error = %v", err)
	}
	if service.box != candidate || prepared.commitCalls != 1 || prepared.rollbackCalls != 0 {
		t.Fatalf("certificate publication = box:%v commit:%d rollback:%d", service.box, prepared.commitCalls, prepared.rollbackCalls)
	}
}

func TestCertificateReloadStartFailureRollsBackBeforeRestore(t *testing.T) {
	startErr := errors.New("candidate start failed")
	service, _, oldNode := newReloadTestService()
	service.config.CertConfig.CertMode = "dns"
	candidate := &reloadRuntime{name: "candidate"}
	restored := &reloadRuntime{name: "restored"}
	prepared := &fakePreparedRenewal{
		renewed:     true,
		certificate: []byte("candidate-cert"),
		privateKey:  []byte("candidate-key"),
	}
	service.prepareRenewal = func(*mylego.CertConfig) (preparedCertificateRenewal, error) {
		return prepared, nil
	}
	builds := 0
	service.reloadRuntimeFactory = func(_ *TuicService, spec runtimeBuildSpec) (runtimeInstance, string, error) {
		builds++
		if builds == 1 {
			return candidate, spec.inboundTag, nil
		}
		if prepared.rollbackCalls != 1 {
			t.Fatal("old runtime restore began before candidate certificate rollback")
		}
		if len(spec.certificatePEM) != 0 || len(spec.privateKeyPEM) != 0 {
			t.Fatal("old runtime restore received candidate certificate material")
		}
		return restored, spec.inboundTag, nil
	}
	service.closeRuntime = func(runtimeInstance) error { return nil }
	service.startRuntime = func(runtime runtimeInstance) error {
		if runtime == candidate {
			return startErr
		}
		return nil
	}

	err := service.certMonitor()
	if !errors.Is(err, startErr) {
		t.Fatalf("certMonitor() error = %v, want %v", err, startErr)
	}
	if service.box != restored || service.nodeInfo != oldNode || service.state != stateRunning {
		t.Fatalf("restored state = box:%v node:%v state:%v", service.box, service.nodeInfo, service.state)
	}
	if prepared.commitCalls != 0 || prepared.rollbackCalls != 1 {
		t.Fatalf("candidate completion calls = commit:%d rollback:%d, want 0/1", prepared.commitCalls, prepared.rollbackCalls)
	}
}

func TestCertificateReloadFailureRetriesWhenRenewalIsAlreadyCurrent(t *testing.T) {
	buildErr := errors.New("certificate candidate build failed")
	service, oldRuntime, _ := newReloadTestService()
	service.config.CertConfig.CertMode = "dns"
	candidate := &reloadRuntime{name: "candidate"}
	renewCalls := 0
	service.prepareRenewal = func(*mylego.CertConfig) (preparedCertificateRenewal, error) {
		renewCalls++
		return &fakePreparedRenewal{
			renewed:     renewCalls <= 2,
			certificate: []byte("candidate-cert"),
			privateKey:  []byte("candidate-key"),
		}, nil
	}
	builds := 0
	service.reloadRuntimeFactory = func(*TuicService, runtimeBuildSpec) (runtimeInstance, string, error) {
		builds++
		if builds == 1 {
			return nil, "", buildErr
		}
		return candidate, "candidate-inbound", nil
	}
	service.closeRuntime = func(runtimeInstance) error { return nil }
	service.startRuntime = func(runtimeInstance) error { return nil }

	if err := service.certMonitor(); !errors.Is(err, buildErr) {
		t.Fatalf("first certMonitor() error = %v, want %v", err, buildErr)
	}
	if service.box != oldRuntime {
		t.Fatalf("failed certificate reload replaced runtime: box=%v want=%v", service.box, oldRuntime)
	}
	if err := service.certMonitor(); err != nil {
		t.Fatalf("second certMonitor() error = %v", err)
	}
	if service.box != candidate {
		t.Fatalf("pending certificate reload was not retried: box=%v want=%v", service.box, candidate)
	}
	if err := service.certMonitor(); err != nil {
		t.Fatalf("third certMonitor() error = %v", err)
	}
	if builds != 2 {
		t.Fatalf("runtime builds = %d, want one failure and one retry", builds)
	}
}

func TestCertificateReloadAppliedWithCloseErrorDoesNotRetry(t *testing.T) {
	closeErr := errors.New("old runtime close failed")
	service, oldRuntime, _ := newReloadTestService()
	service.config.CertConfig.CertMode = "dns"
	candidate := &reloadRuntime{name: "candidate"}
	renewCalls := 0
	service.prepareRenewal = func(*mylego.CertConfig) (preparedCertificateRenewal, error) {
		renewCalls++
		return &fakePreparedRenewal{
			renewed:     renewCalls == 1,
			certificate: []byte("candidate-cert"),
			privateKey:  []byte("candidate-key"),
		}, nil
	}
	builds := 0
	service.reloadRuntimeFactory = func(*TuicService, runtimeBuildSpec) (runtimeInstance, string, error) {
		builds++
		return candidate, "candidate-inbound", nil
	}
	service.closeRuntime = func(runtime runtimeInstance) error {
		if runtime == oldRuntime {
			return closeErr
		}
		return nil
	}
	service.startRuntime = func(runtimeInstance) error { return nil }

	if err := service.certMonitor(); !errors.Is(err, closeErr) {
		t.Fatalf("first certMonitor() error = %v, want %v", err, closeErr)
	}
	if service.box != candidate {
		t.Fatalf("certificate runtime was not published: box=%v want=%v", service.box, candidate)
	}
	if err := service.certMonitor(); err != nil {
		t.Fatalf("second certMonitor() error = %v", err)
	}
	if builds != 1 {
		t.Fatalf("runtime builds = %d, want no retry after certificate was applied", builds)
	}
}

func TestSuccessfulReloadKeepsStableRuntimeTagAndDetectRules(t *testing.T) {
	service, _, _ := newReloadTestService()
	oldTag := service.tag
	pattern := regexp.MustCompile(`blocked\.example`)
	if err := service.rules.UpdateRule(oldTag, []api.DetectRule{{ID: 17, Pattern: pattern}}); err != nil {
		t.Fatalf("UpdateRule() error = %v", err)
	}
	candidate := &reloadRuntime{name: "candidate"}
	service.reloadRuntimeFactory = func(_ *TuicService, spec runtimeBuildSpec) (runtimeInstance, string, error) {
		return candidate, spec.inboundTag, nil
	}
	service.closeRuntime = func(runtimeInstance) error { return nil }
	service.startRuntime = func(runtimeInstance) error { return nil }

	if err := service.reloadNode(newReloadNode(9443, "new.example.com")); err != nil {
		t.Fatalf("reloadNode() error = %v", err)
	}
	if service.tag != oldTag || service.inboundTag != oldTag {
		t.Fatalf("reload changed stable runtime tags: tag=%q inbound=%q want=%q", service.tag, service.inboundTag, oldTag)
	}
	if !service.rules.DetectUID(service.tag, "blocked.example:443", 17, "127.0.0.1") {
		t.Fatal("detect rules no longer apply after successful reload")
	}
}

func TestSuccessfulReloadPublishesNodeRateLimitWithRuntime(t *testing.T) {
	service, _, _ := newReloadTestService()
	service.nodeInfo.SpeedLimit = 10
	service.users["user"] = userRecord{UID: 1}
	oldLimiter := rate.NewLimiter(10, 10)
	service.rateLimiters = map[string]*rate.Limiter{"user": oldLimiter}
	candidate := &reloadRuntime{name: "candidate"}
	service.reloadRuntimeFactory = func(_ *TuicService, spec runtimeBuildSpec) (runtimeInstance, string, error) {
		return candidate, spec.inboundTag, nil
	}
	service.closeRuntime = func(runtimeInstance) error { return nil }
	service.startRuntime = func(runtimeInstance) error { return nil }
	candidateNode := newReloadNode(9443, "new.example.com")
	candidateNode.SpeedLimit = 20

	if err := service.reloadNode(candidateNode); err != nil {
		t.Fatalf("reloadNode() error = %v", err)
	}
	if limiter := service.rateLimiters["user"]; limiter != oldLimiter || limiter.Limit() != 20 {
		t.Fatalf("published limiter = %v/%v, want reused limiter with limit 20", limiter, limiter.Limit())
	}
}

func TestCloseRacingWithReloadIsRejectedWithoutMutation(t *testing.T) {
	service, _, _ := newReloadTestService()
	candidate := &reloadRuntime{name: "candidate"}
	startEntered := make(chan struct{})
	releaseStart := make(chan struct{})
	service.reloadRuntimeFactory = func(_ *TuicService, spec runtimeBuildSpec) (runtimeInstance, string, error) {
		return candidate, spec.inboundTag, nil
	}
	service.closeRuntime = func(runtimeInstance) error { return nil }
	service.startRuntime = func(runtimeInstance) error {
		close(startEntered)
		<-releaseStart
		return nil
	}

	done := make(chan error, 1)
	go func() { done <- service.reloadNode(newReloadNode(9443, "new.example.com")) }()
	<-startEntered
	closeErr := service.Close()
	closed, state := service.closed, service.state
	close(releaseStart)
	if err := <-done; err != nil {
		t.Fatalf("reloadNode() error = %v", err)
	}
	if closeErr == nil || closed || state != stateReloading {
		t.Fatalf("Close during reload = error:%v closed:%v state:%v, want rejection without mutation", closeErr, closed, state)
	}
}
