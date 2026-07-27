package controller

import (
	"bytes"
	"errors"
	"strings"
	"testing"

	"github.com/Mtoly/XrayRP/api"
	"github.com/Mtoly/XrayRP/common/mylego"
	"github.com/sirupsen/logrus"
)

type fakeControllerPreparedRenewal struct {
	renewed        bool
	certificate    []byte
	privateKey     []byte
	commitErr      error
	rollbackErr    error
	commitCalls    int
	rollbackCalls  int
	closed         bool
	panicOnRenewed bool
	onCommit       func()
	onRollback     func()
}

func (r *fakeControllerPreparedRenewal) Renewed() bool {
	if r.panicOnRenewed {
		panic("prepared renewal state panic")
	}
	return r.renewed
}
func (r *fakeControllerPreparedRenewal) CertificatePEM() []byte {
	return append([]byte(nil), r.certificate...)
}
func (r *fakeControllerPreparedRenewal) PrivateKeyPEM() []byte {
	return append([]byte(nil), r.privateKey...)
}
func (r *fakeControllerPreparedRenewal) Commit() error {
	if r.closed {
		return errors.New("prepared renewal already closed")
	}
	r.closed = true
	r.commitCalls++
	if r.onCommit != nil {
		r.onCommit()
	}
	return r.commitErr
}
func (r *fakeControllerPreparedRenewal) Rollback() error {
	if r.closed {
		return nil
	}
	r.closed = true
	r.rollbackCalls++
	if r.onRollback != nil {
		r.onRollback()
	}
	return r.rollbackErr
}

func TestControllerCertMonitorReturnsRenewalFailure(t *testing.T) {
	controller := &Controller{
		config: &Config{
			CertConfig: &mylego.CertConfig{
				CertMode:   "dns",
				CertDomain: "node.example.com",
			},
		},
	}
	controller.setNodeState(&api.NodeInfo{EnableTLS: true}, "node-tag")

	renewErr := errors.New("renew failed")
	controller.prepareRenewal = func(*mylego.CertConfig) (preparedCertificateRenewal, error) {
		return nil, renewErr
	}

	if err := controller.certMonitor(); !errors.Is(err, renewErr) {
		t.Fatalf("certMonitor() error = %v, want %v", err, renewErr)
	}
}

func TestControllerCertMonitorPeriodicLogsFailureAndRetries(t *testing.T) {
	buffer := &bytes.Buffer{}
	logger := logrus.New()
	logger.SetOutput(buffer)
	logger.SetFormatter(&logrus.TextFormatter{DisableTimestamp: true})

	controller := &Controller{
		config: &Config{
			CertConfig: &mylego.CertConfig{
				CertMode:   "dns",
				CertDomain: "node.example.com",
			},
		},
		logger: logrus.NewEntry(logger),
	}
	controller.setNodeState(&api.NodeInfo{EnableTLS: true}, "node-tag")

	renewErr := errors.New("token=renew-secret")
	attempts := 0
	controller.prepareRenewal = func(*mylego.CertConfig) (preparedCertificateRenewal, error) {
		attempts++
		if attempts == 1 {
			return nil, renewErr
		}
		return &fakeControllerPreparedRenewal{}, nil
	}

	if err := controller.certMonitorPeriodic(); err != nil {
		t.Fatalf("first certMonitorPeriodic() error = %v, want nil so periodic retries continue", err)
	}
	if err := controller.certMonitorPeriodic(); err != nil {
		t.Fatalf("second certMonitorPeriodic() error = %v, want nil", err)
	}
	if attempts != 2 {
		t.Fatalf("renew attempts = %d, want 2", attempts)
	}

	logOutput := buffer.String()
	if strings.Contains(logOutput, renewErr.Error()) {
		t.Fatalf("certificate monitor leaked sensitive error: %q", logOutput)
	}
	if !strings.Contains(logOutput, "certificate renewal failed") {
		t.Fatalf("certificate monitor did not expose failure: %q", logOutput)
	}
}

func TestControllerCertMonitorPeriodicCanLogDetailedFailure(t *testing.T) {
	buffer := &bytes.Buffer{}
	logger := logrus.New()
	logger.SetOutput(buffer)
	logger.SetFormatter(&logrus.TextFormatter{DisableTimestamp: true})

	controller := &Controller{
		config: &Config{
			ShowErrorDetails: true,
			CertConfig: &mylego.CertConfig{
				CertMode:   "http",
				CertDomain: "node.example.com",
			},
		},
		logger: logrus.NewEntry(logger),
	}
	controller.setNodeState(&api.NodeInfo{EnableTLS: true}, "node-tag")

	renewErr := errors.New("renew failed")
	controller.prepareRenewal = func(*mylego.CertConfig) (preparedCertificateRenewal, error) {
		return nil, renewErr
	}

	if err := controller.certMonitorPeriodic(); err != nil {
		t.Fatalf("certMonitorPeriodic() error = %v, want nil so periodic retries continue", err)
	}
	if logOutput := buffer.String(); !strings.Contains(logOutput, renewErr.Error()) {
		t.Fatalf("certificate monitor omitted opted-in error details: %q", logOutput)
	}
}

func TestControllerCertMonitorUsesRuntimeApplySerialization(t *testing.T) {
	controller := &Controller{
		config: &Config{
			CertConfig: &mylego.CertConfig{
				CertMode:   "dns",
				CertDomain: "node.example.com",
			},
		},
	}
	controller.setNodeState(&api.NodeInfo{EnableTLS: true}, "node-tag")

	renewEntered := make(chan struct{})
	releaseRenew := make(chan struct{})
	controller.prepareRenewal = func(*mylego.CertConfig) (preparedCertificateRenewal, error) {
		close(renewEntered)
		<-releaseRenew
		return &fakeControllerPreparedRenewal{}, nil
	}

	done := make(chan error, 1)
	go func() {
		done <- controller.certMonitor()
	}()
	<-renewEntered

	locked := !controller.reloadMu.TryLock()
	if !locked {
		controller.reloadMu.Unlock()
	}
	close(releaseRenew)
	if err := <-done; err != nil {
		t.Fatalf("certMonitor() error = %v", err)
	}
	if !locked {
		t.Fatal("certificate monitor did not hold runtime apply serialization")
	}
}

func TestControllerCertMonitorBlocksRuntimeApplyUntilRenewalCompletes(t *testing.T) {
	controller := &Controller{
		config: &Config{
			CertConfig: &mylego.CertConfig{
				CertMode:   "dns",
				CertDomain: "node.example.com",
			},
		},
	}
	controller.setNodeState(&api.NodeInfo{EnableTLS: true}, "")

	renewEntered := make(chan struct{})
	releaseRenew := make(chan struct{})
	controller.prepareRenewal = func(*mylego.CertConfig) (preparedCertificateRenewal, error) {
		close(renewEntered)
		<-releaseRenew
		return &fakeControllerPreparedRenewal{}, nil
	}

	monitorDone := make(chan error, 1)
	go func() {
		monitorDone <- controller.certMonitor()
	}()
	<-renewEntered

	reloadLockHeld := make(chan bool, 1)
	applyEntered := make(chan struct{})
	applyDone := make(chan error, 1)
	module := nodeRuntimeStateApplyModule{
		controller: controller,
		hooks: syncApplyHooks{
			beforeReloadLock: func() {
				acquired := controller.reloadMu.TryLock()
				if acquired {
					controller.reloadMu.Unlock()
				}
				reloadLockHeld <- !acquired
			},
			onSnapshotApplied: func(syncApplySnapshot) {
				close(applyEntered)
			},
		},
	}
	go func() {
		applyDone <- module.applySyncSnapshot(syncApplySnapshot{
			Action: syncAction{Type: syncActionTypeSyncDevices},
		})
	}()
	if !<-reloadLockHeld {
		close(releaseRenew)
		<-monitorDone
		<-applyDone
		t.Fatal("runtime apply reached its lock seam without certificate renewal holding reloadMu")
	}

	close(releaseRenew)
	if err := <-monitorDone; err != nil {
		t.Fatalf("certMonitor() error = %v", err)
	}
	if err := <-applyDone; err != nil {
		t.Fatalf("applySyncSnapshot() error = %v", err)
	}
	<-applyEntered
}

func TestControllerCertificateRenewalPanicRollsBackPreparedOwnership(t *testing.T) {
	controller := &Controller{
		config: &Config{
			CertConfig: &mylego.CertConfig{
				CertMode:   "dns",
				CertDomain: "node.example.com",
			},
		},
	}
	controller.setNodeState(&api.NodeInfo{EnableTLS: true}, "node-tag")
	prepared := &fakeControllerPreparedRenewal{panicOnRenewed: true}
	controller.prepareRenewal = func(*mylego.CertConfig) (preparedCertificateRenewal, error) {
		return prepared, nil
	}

	var (
		err        error
		panicValue any
	)
	func() {
		defer func() {
			panicValue = recover()
		}()
		err = controller.renewCertificateIfNeeded()
	}()

	if panicValue != nil {
		t.Fatalf("renewCertificateIfNeeded() propagated panic: %v", panicValue)
	}
	if err == nil || !strings.Contains(err.Error(), "prepared renewal state panic") {
		t.Fatalf("renewCertificateIfNeeded() error = %v, want converted panic", err)
	}
	if prepared.rollbackCalls != 1 || prepared.commitCalls != 0 {
		t.Fatalf("prepared renewal completion = commit:%d rollback:%d, want 0/1", prepared.commitCalls, prepared.rollbackCalls)
	}
}

func TestControllerCertificateRenewalCommitsAfterRuntimeReadiness(t *testing.T) {
	controller, recorder := newTestSyncApplyController(&fakeSyncApplyAPI{})
	currentNode := &api.NodeInfo{NodeType: "V2ray", NodeID: 1, Port: 443, EnableTLS: true}
	currentUsers := []api.UserInfo{{UID: 1, Email: "user@example.com"}}
	controller.setNodeState(currentNode, controller.buildNodeTagFrom(currentNode))
	controller.setUserList(&currentUsers)
	oldCert := &mylego.CertConfig{
		CertMode:   "dns",
		CertDomain: "node.example.com",
		Provider:   "cloudflare",
		Email:      "ops@example.com",
	}
	controller.config.CertConfig = oldCert
	prepared := &fakeControllerPreparedRenewal{
		renewed:     true,
		certificate: []byte("candidate-certificate"),
		privateKey:  []byte("candidate-private-key"),
	}
	prepared.onCommit = func() {
		if recorder.addTagCalls != 1 || recorder.addUserCalls != 1 {
			t.Fatal("certificate committed before candidate runtime and users were ready")
		}
		if controller.config.CertConfig != oldCert {
			t.Fatal("candidate certificate config was published through controller state")
		}
	}
	controller.prepareRenewal = func(*mylego.CertConfig) (preparedCertificateRenewal, error) {
		return prepared, nil
	}

	if err := controller.renewCertificateIfNeeded(); err != nil {
		t.Fatalf("renewCertificateIfNeeded() error = %v", err)
	}
	if prepared.commitCalls != 1 || prepared.rollbackCalls != 0 {
		t.Fatalf("prepared renewal completion = commit:%d rollback:%d", prepared.commitCalls, prepared.rollbackCalls)
	}
	if len(recorder.addedCertConfigs) != 1 {
		t.Fatalf("candidate runtime builds = %d, want 1", len(recorder.addedCertConfigs))
	}
	candidate := recorder.addedCertConfigs[0]
	if candidate.CertMode != "content" ||
		candidate.CertContent != "candidate-certificate" ||
		candidate.KeyContent != "candidate-private-key" {
		t.Fatalf("candidate runtime certificate config = %#v", candidate)
	}
	if len(recorder.removedTags) != 1 || recorder.deleteLimiterCalls != 0 {
		t.Fatalf("runtime replacement ownership = removed:%d limiter-deletes:%d", len(recorder.removedTags), recorder.deleteLimiterCalls)
	}
}

func TestControllerCertificateRenewalBuildFailureRollsBackBeforeRestore(t *testing.T) {
	buildErr := errors.New("candidate TLS runtime build failed")
	controller, recorder := newTestSyncApplyController(&fakeSyncApplyAPI{})
	currentNode := &api.NodeInfo{NodeType: "V2ray", NodeID: 1, Port: 443, EnableTLS: true}
	currentUsers := []api.UserInfo{{UID: 1, Email: "user@example.com"}}
	controller.setNodeState(currentNode, controller.buildNodeTagFrom(currentNode))
	controller.setUserList(&currentUsers)
	oldCert := &mylego.CertConfig{CertMode: "dns", CertDomain: "node.example.com"}
	controller.config.CertConfig = oldCert
	prepared := &fakeControllerPreparedRenewal{
		renewed:     true,
		certificate: []byte("candidate-certificate"),
		privateKey:  []byte("candidate-private-key"),
	}
	rolledBack := false
	prepared.onRollback = func() { rolledBack = true }
	controller.prepareRenewal = func(*mylego.CertConfig) (preparedCertificateRenewal, error) {
		return prepared, nil
	}
	recorder.addTagErr = buildErr
	recorder.addTagErrAtCall = 1
	recorder.onAddTag = func(*Config) {
		if recorder.addTagCalls == 2 && !rolledBack {
			t.Fatal("old runtime restore began before candidate certificate rollback")
		}
	}

	err := controller.renewCertificateIfNeeded()
	if !errors.Is(err, buildErr) {
		t.Fatalf("renewCertificateIfNeeded() error = %v, want %v", err, buildErr)
	}
	if prepared.commitCalls != 0 || prepared.rollbackCalls != 1 {
		t.Fatalf("prepared renewal completion = commit:%d rollback:%d", prepared.commitCalls, prepared.rollbackCalls)
	}
	if recorder.addTagCalls != 2 || len(recorder.removedTags) != 2 {
		t.Fatalf("failed candidate restoration = adds:%d removes:%d", recorder.addTagCalls, len(recorder.removedTags))
	}
	if controller.config.CertConfig != oldCert {
		t.Fatalf("failed renewal published candidate config: %#v", controller.config.CertConfig)
	}
}

func TestControllerCertificateCommitFailureJoinsCleanupAndRestoreErrors(t *testing.T) {
	commitErr := errors.New("certificate commit failed")
	cleanupErr := errors.New("candidate runtime cleanup failed")
	restoreErr := errors.New("last-known-good runtime restore failed")
	controller, recorder := newTestSyncApplyController(&fakeSyncApplyAPI{})
	currentNode := &api.NodeInfo{NodeType: "V2ray", NodeID: 1, Port: 443, EnableTLS: true}
	currentUsers := []api.UserInfo{{UID: 1, Email: "user@example.com"}}
	controller.setNodeState(currentNode, controller.buildNodeTagFrom(currentNode))
	controller.setUserList(&currentUsers)
	oldCert := &mylego.CertConfig{CertMode: "dns", CertDomain: "node.example.com"}
	controller.config.CertConfig = oldCert
	prepared := &fakeControllerPreparedRenewal{
		renewed:     true,
		certificate: []byte("candidate-certificate"),
		privateKey:  []byte("candidate-private-key"),
		commitErr:   commitErr,
	}
	controller.prepareRenewal = func(*mylego.CertConfig) (preparedCertificateRenewal, error) {
		return prepared, nil
	}
	recorder.cleanupTagErr = cleanupErr
	recorder.cleanupTagErrAtCall = 2
	recorder.addTagErr = restoreErr
	recorder.addTagErrAtCall = 2

	err := controller.renewCertificateIfNeeded()
	if !errors.Is(err, commitErr) || !errors.Is(err, cleanupErr) || !errors.Is(err, restoreErr) {
		t.Fatalf("renewCertificateIfNeeded() error = %v, want commit, cleanup, and restore failures", err)
	}
	if prepared.commitCalls != 1 || prepared.rollbackCalls != 0 {
		t.Fatalf("prepared renewal completion = commit:%d rollback:%d", prepared.commitCalls, prepared.rollbackCalls)
	}
	if controller.config.CertConfig != oldCert {
		t.Fatalf("failed commit published candidate config: %#v", controller.config.CertConfig)
	}
}

func TestControllerCertificateCleanupFailureAttemptsLastKnownGoodRestore(t *testing.T) {
	cleanupErr := errors.New("old certificate runtime cleanup failed")
	rollbackErr := errors.New("candidate certificate rollback failed")
	restoreErr := errors.New("last-known-good runtime restore failed")
	controller, recorder := newTestSyncApplyController(&fakeSyncApplyAPI{})
	currentNode := &api.NodeInfo{NodeType: "V2ray", NodeID: 1, Port: 443, EnableTLS: true}
	currentUsers := []api.UserInfo{{UID: 1, Email: "user@example.com"}}
	controller.setNodeState(currentNode, controller.buildNodeTagFrom(currentNode))
	controller.setUserList(&currentUsers)
	oldCert := &mylego.CertConfig{CertMode: "dns", CertDomain: "node.example.com"}
	controller.config.CertConfig = oldCert
	prepared := &fakeControllerPreparedRenewal{
		renewed:     true,
		certificate: []byte("candidate-certificate"),
		privateKey:  []byte("candidate-private-key"),
		rollbackErr: rollbackErr,
	}
	controller.prepareRenewal = func(*mylego.CertConfig) (preparedCertificateRenewal, error) {
		return prepared, nil
	}
	recorder.cleanupTagErr = cleanupErr
	recorder.cleanupTagErrAtCall = 1
	recorder.addTagErr = restoreErr
	recorder.addTagErrAtCall = 1

	err := controller.renewCertificateIfNeeded()
	if !errors.Is(err, cleanupErr) || !errors.Is(err, rollbackErr) || !errors.Is(err, restoreErr) {
		t.Fatalf("renewCertificateIfNeeded() error = %v, want cleanup, rollback, and restore failures", err)
	}
	if prepared.commitCalls != 0 || prepared.rollbackCalls != 1 {
		t.Fatalf("prepared renewal completion = commit:%d rollback:%d", prepared.commitCalls, prepared.rollbackCalls)
	}
	if recorder.addTagCalls != 1 {
		t.Fatalf("last-known-good runtime restore attempts = %d, want 1", recorder.addTagCalls)
	}
	if controller.config.CertConfig != oldCert {
		t.Fatalf("cleanup failure published candidate config: %#v", controller.config.CertConfig)
	}
}
