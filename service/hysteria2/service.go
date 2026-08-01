package hysteria2

import (
	"context"
	"errors"
	"fmt"
	"runtime/debug"
	"time"

	"github.com/apernet/hysteria/core/v2/server"
	log "github.com/sirupsen/logrus"

	"github.com/Mtoly/XrayRP/api"
	"github.com/Mtoly/XrayRP/common/mylego"
	"github.com/Mtoly/XrayRP/common/rule"
	"github.com/Mtoly/XrayRP/service"
	"github.com/Mtoly/XrayRP/service/controller"
	"github.com/Mtoly/XrayRP/service/internal/specialruntime"
)

type PanelClient interface {
	Describe() api.ClientInfo
	GetNodeInfo() (*api.NodeInfo, error)
	GetUserList() (*[]api.UserInfo, error)
	GetNodeRule() (*[]api.DetectRule, error)
	ReportNodeStatus(*api.NodeStatus) error
	ReportNodeOnlineUsers(*[]api.OnlineUser) error
	ReportUserTraffic(*[]api.UserTraffic) error
	ReportIllegal(*[]api.DetectResult) error
}

var _ service.Service = (*Hysteria2Service)(nil)

func defaultServerConfigFactory(h *Hysteria2Service, spec serverBuildSpec) (*server.Config, error) {
	return h.buildServerConfigFor(spec)
}

func defaultRuntimeServerFactory(cfg *server.Config) (runtimeServer, error) {
	return server.NewServer(cfg)
}

func defaultServeRuntime(runtime runtimeServer) error {
	return runtime.Serve()
}

func defaultCloseRuntime(runtime runtimeServer) error {
	return runtime.Close()
}

func defaultPrepareCertificateRenewal(certConfig *mylego.CertConfig) (preparedCertificateRenewal, error) {
	return mylego.PrepareRenewal(certConfig)
}

// New creates a new Hysteria2 service bound to a SSPanel node.
func New(apiClient PanelClient, cfg *controller.Config) *Hysteria2Service {
	clientInfo := apiClient.Describe()
	logger := log.NewEntry(log.StandardLogger()).WithFields(log.Fields{
		"Host": clientInfo.APIHost,
		"ID":   clientInfo.NodeID,
	})
	serviceRuntime := &Hysteria2Service{
		apiClient:            apiClient,
		config:               cfg,
		serverConfigFactory:  defaultServerConfigFactory,
		runtimeServerFactory: defaultRuntimeServerFactory,
		serveRuntime:         defaultServeRuntime,
		closeRuntime:         defaultCloseRuntime,
		prepareRenewal:       defaultPrepareCertificateRenewal,
		serveHandshake:       defaultServeHandshake,
		logger:               logger,
		rules:                rule.New(),
		users:                make(map[string]userRecord),
		traffic:              make(map[string]*userTraffic),
		overLimit:            make(map[string]bool),
		onlineIPs:            make(map[string]map[string]struct{}),
		ipLastActive:         make(map[string]map[string]time.Time),
		blockedIDs:           make(map[string]bool),
	}
	serviceRuntime.initializeSnapshotSyncCoordinator()
	return serviceRuntime
}

func (h *Hysteria2Service) buildRuntimeServer(spec serverBuildSpec) (runtimeServer, error) {
	configFactory := h.serverConfigFactory
	if configFactory == nil {
		configFactory = defaultServerConfigFactory
	}
	cfg, err := configFactory(h, spec)
	if err != nil {
		return nil, err
	}
	runtimeFactory := h.runtimeServerFactory
	if runtimeFactory == nil {
		runtimeFactory = defaultRuntimeServerFactory
	}
	return runtimeFactory(cfg)
}

func (h *Hysteria2Service) appliedStateSnapshot() (*api.NodeInfo, string, time.Time) {
	h.lifecycleMu.Lock()
	defer h.lifecycleMu.Unlock()
	return h.nodeInfo, h.tag, h.startAt
}

func (h *Hysteria2Service) appliedTag() string {
	_, tag, _ := h.appliedStateSnapshot()
	return tag
}

func (h *Hysteria2Service) failWithRuntimeOwnership(primary error, clientInfo api.ClientInfo, nodeInfo *api.NodeInfo, candidate reloadRuntime, tag string, startAt time.Time, tasks *specialruntime.Tasks) error {
	h.lifecycleMu.Lock()
	h.clientInfo = clientInfo
	h.nodeInfo = nodeInfo
	h.server = candidate.runtime
	h.tag = tag
	h.startAt = startAt
	h.tasks = tasks
	if candidate.serve != nil {
		h.serveDone = candidate.serve.done
	} else {
		h.serveDone = nil
	}
	h.watcherDone = nil
	h.trafficCancel = candidate.cancel
	h.state = stateFailed
	h.runtimeErr = primary
	h.closed = false
	h.lifecycleMu.Unlock()
	h.health.RecordFailure(service.FailureStageCleanup, time.Now())
	return primary
}

func (h *Hysteria2Service) startReloadCandidate(spec serverBuildSpec) (reloadRuntime, error) {
	ctx, cancel := service.WithDefaultTimeout(context.Background(), service.DefaultStartTimeout)
	defer cancel()
	return h.startReloadCandidateContext(ctx, spec)
}

func (h *Hysteria2Service) startReloadCandidateContext(ctx context.Context, spec serverBuildSpec) (reloadRuntime, error) {
	if err := ctx.Err(); err != nil {
		return reloadRuntime{}, err
	}
	authGate := newRuntimeAuthGate()
	spec.authGate = authGate
	trafficContext, cancelTraffic := context.WithCancel(context.WithoutCancel(ctx))
	spec.trafficContext = trafficContext
	runtime, err := h.buildRuntimeServer(spec)
	if err != nil {
		authGate.resolve(false)
		cancelTraffic()
		return reloadRuntime{}, err
	}
	serveRuntime := h.serveRuntime
	if serveRuntime == nil {
		serveRuntime = defaultServeRuntime
	}
	serve, err := h.startReloadRuntimeContext(ctx, runtime, serveRuntime)
	candidate := reloadRuntime{runtime: runtime, serve: serve, authGate: authGate, cancel: cancelTraffic}
	if err != nil {
		authGate.resolve(false)
		cancelTraffic()
		closeRuntime := h.closeRuntime
		if closeRuntime == nil {
			closeRuntime = defaultCloseRuntime
		}
		cleanupErr := closeRuntime(runtime)
		cleanupCtx, cleanupCancel := service.CleanupContext(ctx)
		joinErr := h.waitRuntimeContext(cleanupCtx, serve.done, nil)
		cleanupCancel()
		if cleanupErr != nil || joinErr != nil {
			return candidate, errors.Join(err, cleanupErr, joinErr)
		}
		return reloadRuntime{}, err
	}
	return candidate, nil
}

func (h *Hysteria2Service) Start() error {
	ctx, cancel := service.WithDefaultTimeout(context.Background(), service.DefaultStartTimeout)
	defer cancel()
	return h.StartContext(ctx)
}

func (h *Hysteria2Service) StartContext(parent context.Context) (err error) {
	ctx, cancel := service.WithDefaultTimeout(parent, service.DefaultStartTimeout)
	defer cancel()
	if err := ctx.Err(); err != nil {
		return err
	}
	h.lifecycleMu.Lock()
	if h.closed {
		h.lifecycleMu.Unlock()
		return errors.New("Hysteria2 service cannot start after close")
	}
	if h.state != stateStopped {
		state := h.state
		h.lifecycleMu.Unlock()
		return fmt.Errorf("Hysteria2 service cannot start from state %d", state)
	}
	h.state = stateStarting
	h.runtimeErr = nil
	h.lifecycleMu.Unlock()

	fail := func(primary error) error {
		h.lifecycleMu.Lock()
		h.state = stateFailed
		h.runtimeErr = primary
		h.lifecycleMu.Unlock()
		h.health.RecordFailure(service.FailureStageStart, time.Now())
		return primary
	}

	clientInfo := h.apiClient.Describe()
	nodeInfo, err := api.GetNodeInfoContext(ctx, h.apiClient)
	if err != nil {
		return fail(err)
	}
	if nodeInfo == nil || nodeInfo.NodeType != "Hysteria2" {
		return fail(fmt.Errorf("Hysteria2Service can only be used with Hysteria2 node, got %v", nodeInfo))
	}
	if nodeInfo.Port == 0 {
		return fail(errors.New("server port must > 0"))
	}
	if nodeInfo.Hysteria2Config == nil {
		return fail(errors.New("Hysteria2Config is nil in node info"))
	}
	if h.config == nil || h.config.CertConfig == nil {
		return fail(errors.New("CertConfig is required for Hysteria2"))
	}
	nodeInfo = cloneNodeInfo(nodeInfo)

	tag := fmt.Sprintf("%s_%s_%d_%d", nodeInfo.NodeType, h.config.ListenIP, nodeInfo.Port, nodeInfo.NodeID)
	startAt := time.Now()

	userInfo, err := api.GetUserListContext(ctx, h.apiClient)
	if err != nil {
		return fail(err)
	}

	startupUsers := h.buildCandidateUserState(userInfo, nodeInfo)

	rulesApplied := false
	if !h.config.DisableGetRule && h.rules != nil {
		ruleList, ruleErr := api.GetNodeRuleContext(ctx, h.apiClient)
		if ruleErr != nil {
			return fail(fmt.Errorf("get rule list: %w", ruleErr))
		}
		var startupRules []api.DetectRule
		if ruleList != nil {
			startupRules = *ruleList
		}
		if ruleErr := h.rules.UpdateRule(tag, startupRules); ruleErr != nil {
			return fail(ruleErr)
		}
		rulesApplied = true
	}
	clearStartupRules := func() error {
		if !rulesApplied {
			return nil
		}
		return h.rules.UpdateRule(tag, nil)
	}

	candidate, err := h.startReloadCandidateContext(ctx, serverBuildSpec{
		nodeInfo:   nodeInfo,
		certConfig: cloneCertConfig(h.config.CertConfig),
	})
	if err != nil {
		if candidate.runtime != nil {
			return h.failWithRuntimeOwnership(err, clientInfo, nodeInfo, candidate, tag, startAt, nil)
		}
		ruleCleanupErr := clearStartupRules()
		joined := errors.Join(err, ruleCleanupErr)
		if ruleCleanupErr != nil {
			return h.failWithRuntimeOwnership(joined, clientInfo, nodeInfo, candidate, tag, startAt, nil)
		}
		return fail(joined)
	}
	srv := candidate.runtime
	serve := candidate.serve

	closeRuntime := h.closeRuntime
	if closeRuntime == nil {
		closeRuntime = defaultCloseRuntime
	}

	interval := time.Duration(h.config.UpdatePeriodic) * time.Second
	h.initializeSnapshotSyncCoordinator()
	tasks := specialruntime.NewTasks()
	tasks.Add(h.syncCoordinator)
	tasks.Add(h.newTask(tag, interval, h.userMonitorContext))
	tasks.Add(h.newTask("node monitor", interval, h.nodeMonitorContext))
	if nodeInfo.EnableTLS {
		tasks.Add(h.newTask("cert monitor", interval*60, h.certMonitorPeriodicContext))
	}
	stopStartup := func() error {
		candidate.authGate.resolve(false)
		candidate.cancel()
		if runtimeErr := closeRuntime(srv); runtimeErr != nil {
			return runtimeErr
		}
		return clearStartupRules()
	}
	startupShutdown := specialruntime.RuntimeShutdown{
		Stop:        stopStartup,
		StopContext: func(context.Context) error { return stopStartup() },
		Join: func() error {
			h.waitRuntime(serve.done, nil)
			return nil
		},
		JoinContext: func(ctx context.Context) error {
			return h.waitRuntimeContext(ctx, serve.done, nil)
		},
	}
	if err := tasks.StartContext(ctx, startupShutdown); err != nil {
		if specialruntime.StartCleanupFailed(err) {
			return h.failWithRuntimeOwnership(err, clientInfo, nodeInfo, candidate, tag, startAt, tasks)
		}
		return fail(err)
	}

	if err := h.reloadMu.Lock(ctx); err != nil {
		rollbackErr := tasks.RollbackContext(ctx, startupShutdown)
		joined := errors.Join(err, rollbackErr)
		if rollbackErr != nil {
			return h.failWithRuntimeOwnership(joined, clientInfo, nodeInfo, candidate, tag, startAt, tasks)
		}
		return fail(joined)
	}
	rulesRestored, ruleErr := h.replacePortHopRulesLocked(ctx, buildPortHopRulesFromNode(nodeInfo))
	h.reloadMu.Unlock()
	if ruleErr != nil {
		rollbackErr := tasks.RollbackContext(ctx, startupShutdown)
		joined := errors.Join(ruleErr, rollbackErr)
		if rollbackErr != nil || !rulesRestored {
			return h.failWithRuntimeOwnership(joined, clientInfo, nodeInfo, candidate, tag, startAt, tasks)
		}
		return fail(joined)
	}

	watcherDone := make(chan struct{})
	h.lifecycleMu.Lock()
	h.clientInfo = clientInfo
	h.nodeInfo = nodeInfo
	h.server = srv
	h.tag = tag
	h.startAt = startAt
	h.tasks = tasks
	h.mu.Lock()
	h.users = startupUsers.users
	h.traffic = startupUsers.traffic
	h.overLimit = startupUsers.overLimit
	h.onlineIPs = startupUsers.onlineIPs
	h.ipLastActive = startupUsers.ipLastActive
	h.rateLimiters = startupUsers.rateLimiters
	h.mu.Unlock()
	h.state = stateRunning
	h.runtimeErr = nil
	h.serveDone = serve.done
	h.watcherDone = watcherDone
	h.trafficCancel = candidate.cancel
	h.lifecycleMu.Unlock()
	h.health.RecordSuccessfulSync(time.Now())
	h.refreshCertificateExpiry()
	candidate.authGate.resolve(true)
	go h.watchRuntime(srv, serve, candidate.cancel, watcherDone)

	h.logger.Infof("Hysteria2 node started on %s:%d (hysteria core %s)", h.config.ListenIP, nodeInfo.Port, getHysteriaCoreVersion())
	return nil
}

// Close implements service.Service.Close.
func (h *Hysteria2Service) Close() error {
	ctx, cancel := service.WithDefaultTimeout(context.Background(), service.DefaultCloseTimeout)
	defer cancel()
	return h.CloseContext(ctx)
}

func (h *Hysteria2Service) CloseContext(parent context.Context) error {
	ctx, cancel := service.WithDefaultTimeout(parent, service.DefaultCloseTimeout)
	defer cancel()

	h.lifecycleMu.Lock()
	if h.closed && h.state == stateStopped {
		h.lifecycleMu.Unlock()
		return h.cleanupPortHopRulesContext(ctx)
	}
	if h.state == stateStarting || h.state == stateStopping {
		h.lifecycleMu.Unlock()
		return errors.New("Hysteria2 service cannot close while starting or stopping")
	}
	tasks := h.tasks
	h.lifecycleMu.Unlock()

	// Stop periodic producers before waiting for an in-flight node or
	// certificate replacement to release the operation gate.
	var producerStopErr error
	if tasks != nil {
		producerStopErr = tasks.StopContext(ctx)
	}
	var syncWaitErr error
	if h.syncCoordinator != nil {
		syncWaitErr = h.syncCoordinator.WaitContext(ctx)
	}
	if err := h.reloadMu.Lock(ctx); err != nil {
		return errors.Join(producerStopErr, syncWaitErr, err)
	}
	if err := ctx.Err(); err != nil {
		h.reloadMu.Unlock()
		return errors.Join(producerStopErr, syncWaitErr, err)
	}

	h.lifecycleMu.Lock()
	if h.closed && h.state == stateStopped {
		h.lifecycleMu.Unlock()
		h.reloadMu.Unlock()
		return errors.Join(producerStopErr, syncWaitErr, h.cleanupPortHopRulesContext(ctx))
	}
	if h.state == stateStarting || h.state == stateReloading || h.state == stateStopping {
		state := h.state
		h.lifecycleMu.Unlock()
		h.reloadMu.Unlock()
		return errors.Join(producerStopErr, syncWaitErr, fmt.Errorf("Hysteria2 service cannot close from state %d", state))
	}
	h.state = stateStopping
	tasks = h.tasks
	srv := h.server
	serveDone := h.serveDone
	watcherDone := h.watcherDone
	cancelTraffic := h.trafficCancel
	cleanupRuntimes := append([]reloadRuntime(nil), h.cleanupRuntimes...)
	h.lifecycleMu.Unlock()
	h.reloadMu.Unlock()

	closeRuntime := h.closeRuntime
	if closeRuntime == nil {
		closeRuntime = defaultCloseRuntime
	}
	var runtimeCloseErr error
	stopRuntime := func() error {
		if cancelTraffic != nil {
			cancelTraffic()
		}
		runtimeCloseErr = closeRuntime(srv)
		return runtimeCloseErr
	}
	shutdown := specialruntime.RuntimeShutdown{
		Stop:        stopRuntime,
		StopContext: func(context.Context) error { return stopRuntime() },
		Join: func() error {
			h.waitRuntime(serveDone, watcherDone)
			return nil
		},
		JoinContext: func(ctx context.Context) error {
			return h.waitRuntimeContext(ctx, serveDone, watcherDone)
		},
	}
	var shutdownErr error
	if srv != nil {
		if tasks != nil {
			shutdownErr = errors.Join(producerStopErr, syncWaitErr, tasks.CloseStoppedContext(ctx, shutdown))
		} else {
			shutdownErr = errors.Join(producerStopErr, syncWaitErr, shutdown.StopContext(ctx), shutdown.JoinContext(ctx))
		}
	} else if tasks != nil {
		shutdownErr = errors.Join(producerStopErr, syncWaitErr, tasks.CloseStoppedContext(ctx, specialruntime.RuntimeShutdown{}))
	} else {
		shutdownErr = errors.Join(producerStopErr, syncWaitErr)
	}

	remainingRuntimes := make([]reloadRuntime, 0, len(cleanupRuntimes))
	var cleanupErr error
	for _, owned := range cleanupRuntimes {
		owned.authGate.resolve(false)
		if owned.cancel != nil {
			owned.cancel()
		}
		if owned.runtime == nil {
			continue
		}
		if err := ctx.Err(); err != nil {
			remainingRuntimes = append(remainingRuntimes, owned)
			cleanupErr = errors.Join(cleanupErr, err)
			continue
		}
		closeOwnedErr := closeRuntime(owned.runtime)
		var joinOwnedErr error
		if owned.serve != nil {
			joinOwnedErr = h.waitRuntimeContext(ctx, owned.serve.done, nil)
		}
		if closeOwnedErr != nil || joinOwnedErr != nil {
			remainingRuntimes = append(remainingRuntimes, owned)
			cleanupErr = errors.Join(cleanupErr, closeOwnedErr, joinOwnedErr)
		}
	}

	closeErr := errors.Join(shutdownErr, cleanupErr)
	if closeErr == nil {
		closeErr = h.cleanupPortHopRulesContext(ctx)
	}
	if closeErr == nil && h.rules != nil && h.tag != "" {
		closeErr = h.rules.UpdateRule(h.tag, nil)
	}

	h.lifecycleMu.Lock()
	if runtimeCloseErr == nil && runtimeLifecycleJoined(serveDone, watcherDone) {
		h.server = nil
		h.serveDone = nil
		h.watcherDone = nil
		h.trafficCancel = nil
	}
	h.cleanupRuntimes = remainingRuntimes
	if shutdownErr == nil {
		h.tasks = nil
	}
	if closeErr != nil {
		h.state = stateFailed
		h.runtimeErr = closeErr
		h.closed = false
		h.lifecycleMu.Unlock()
		stage := service.FailureStageClose
		if runtimeCloseErr != nil || len(remainingRuntimes) != 0 {
			stage = service.FailureStageCleanup
		}
		h.health.RecordFailure(stage, time.Now())
		return closeErr
	}
	h.nodeInfo = nil
	h.tag = ""
	h.startAt = time.Time{}
	h.runtimeErr = nil
	h.state = stateStopped
	h.closed = true
	h.mu.Lock()
	h.users = make(map[string]userRecord)
	h.traffic = make(map[string]*userTraffic)
	h.overLimit = make(map[string]bool)
	h.onlineIPs = make(map[string]map[string]struct{})
	h.ipLastActive = make(map[string]map[string]time.Time)
	h.blockedIDs = make(map[string]bool)
	h.rateLimiters = nil
	h.mu.Unlock()
	h.lifecycleMu.Unlock()
	return nil
}

// reloadNode replaces the active Hysteria2 server while preserving the last
// successfully applied node runtime state when replacement fails.
func (h *Hysteria2Service) reloadNode(nodeInfo *api.NodeInfo) error {
	ctx, cancel := service.WithDefaultTimeout(context.Background(), service.DefaultSyncTimeout)
	defer cancel()
	return h.reloadNodeContext(ctx, nodeInfo)
}

func (h *Hysteria2Service) reloadNodeContext(parent context.Context, nodeInfo *api.NodeInfo) error {
	if nodeInfo == nil {
		return nil
	}
	ctx, cancel := service.WithDefaultTimeout(parent, service.DefaultSyncTimeout)
	defer cancel()
	if err := h.reloadMu.Lock(ctx); err != nil {
		return err
	}
	defer h.reloadMu.Unlock()
	return h.reloadNodeLockedContext(ctx, nodeInfo)
}

func (h *Hysteria2Service) reloadNodeLocked(nodeInfo *api.NodeInfo) error {
	ctx, cancel := service.WithDefaultTimeout(context.Background(), service.DefaultSyncTimeout)
	defer cancel()
	return h.reloadNodeLockedContext(ctx, nodeInfo)
}

func (h *Hysteria2Service) reloadNodeLockedContext(ctx context.Context, nodeInfo *api.NodeInfo) error {
	return h.reloadNodeWithCertificateLockedContext(ctx, nodeInfo, nil)
}

func (h *Hysteria2Service) reloadNodeWithCertificateLocked(nodeInfo *api.NodeInfo, renewal preparedCertificateRenewal) (err error) {
	ctx, cancel := service.WithDefaultTimeout(context.Background(), service.DefaultSyncTimeout)
	defer cancel()
	return h.reloadNodeWithCertificateLockedContext(ctx, nodeInfo, renewal)
}

func (h *Hysteria2Service) reloadNodeWithCertificateLockedContext(ctx context.Context, nodeInfo *api.NodeInfo, renewal preparedCertificateRenewal) (err error) {
	if renewal != nil {
		defer func() {
			err = errors.Join(err, renewal.Rollback())
		}()
	}
	if nodeInfo == nil {
		return nil
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if nodeInfo.NodeType != "Hysteria2" {
		return fmt.Errorf("Hysteria2Service reloadNode: unexpected node type %s", nodeInfo.NodeType)
	}
	if nodeInfo.Port == 0 || nodeInfo.Port > 65535 {
		return fmt.Errorf("server port must be between 1 and 65535")
	}
	if nodeInfo.Hysteria2Config == nil {
		return errors.New("Hysteria2Config is nil in node info")
	}
	if h.config == nil || h.config.CertConfig == nil {
		return errors.New("CertConfig is required for Hysteria2")
	}
	if renewal != nil && (len(renewal.CertificatePEM()) == 0 || len(renewal.PrivateKeyPEM()) == 0) {
		return errors.New("prepared certificate renewal is missing certificate or private key PEM")
	}

	candidateNode := cloneNodeInfo(nodeInfo)
	candidateRules := buildPortHopRulesFromNode(candidateNode)

	h.lifecycleMu.Lock()
	expectedState := stateRunning
	if renewal != nil {
		expectedState = stateReloading
	}
	if h.closed || h.state != expectedState || h.server == nil || h.nodeInfo == nil {
		state := h.state
		h.lifecycleMu.Unlock()
		return fmt.Errorf("Hysteria2 service cannot reload from state %d", state)
	}
	h.state = stateReloading
	oldRuntime := h.server
	oldNodeInfo := h.nodeInfo
	oldTag := h.tag
	oldCertConfig := cloneCertConfig(h.config.CertConfig)
	oldRules := append([]portHopRule(nil), h.portHopRules...)
	oldServeDone := h.serveDone
	oldWatcherDone := h.watcherDone
	oldTrafficCancel := h.trafficCancel
	h.lifecycleMu.Unlock()

	candidateCertConfig := deriveReloadCertConfig(oldCertConfig, oldNodeInfo, candidateNode)
	candidateSpec := serverBuildSpec{
		nodeInfo:       candidateNode,
		certConfig:     candidateCertConfig,
		certificatePEM: certificatePEM(renewal),
		privateKeyPEM:  privateKeyPEM(renewal),
	}

	closeRuntime := h.closeRuntime
	if closeRuntime == nil {
		closeRuntime = defaultCloseRuntime
	}
	cleanupCandidate := func(candidate reloadRuntime) ([]reloadRuntime, error) {
		candidate.authGate.resolve(false)
		if candidate.cancel != nil {
			candidate.cancel()
		}
		if candidate.runtime == nil {
			return nil, nil
		}
		cleanupErr := closeRuntime(candidate.runtime)
		var joinErr error
		if candidate.serve != nil {
			cleanupCtx, cleanupCancel := service.CleanupContext(ctx)
			joinErr = h.waitRuntimeContext(cleanupCtx, candidate.serve.done, nil)
			cleanupCancel()
		}
		if cleanupErr != nil || joinErr != nil {
			return []reloadRuntime{candidate}, errors.Join(cleanupErr, joinErr)
		}
		return nil, nil
	}
	restoreOldRuntime := func() (reloadRuntime, []reloadRuntime, error) {
		restoreCtx, restoreCancel := service.WithDefaultTimeout(context.WithoutCancel(ctx), service.DefaultStartTimeout)
		defer restoreCancel()
		restored, restoreErr := h.startReloadCandidateContext(restoreCtx, serverBuildSpec{
			nodeInfo:   oldNodeInfo,
			certConfig: oldCertConfig,
		})
		if restoreErr != nil {
			if restored.runtime != nil {
				return reloadRuntime{}, []reloadRuntime{restored}, restoreErr
			}
			return reloadRuntime{}, nil, restoreErr
		}
		return restored, nil, nil
	}
	abortBeforeRetire := func(primary error, candidate reloadRuntime) error {
		owned, cleanupErr := cleanupCandidate(candidate)
		rollbackErr := rollbackCertificateRenewal(renewal)
		joined := errors.Join(primary, cleanupErr, rollbackErr)
		if cleanupErr != nil {
			h.finishExistingReloadWithOwnership(owned, stateFailed, joined)
		} else {
			h.finishExistingReload(stateRunning, nil)
		}
		return joined
	}
	retainOldFailure := func(primary error, candidate reloadRuntime) error {
		owned, cleanupErr := cleanupCandidate(candidate)
		rollbackErr := rollbackCertificateRenewal(renewal)
		joined := errors.Join(primary, cleanupErr, rollbackErr)
		h.finishExistingReloadWithOwnership(owned, stateFailed, joined)
		return joined
	}
	rollbackCandidate := func(primary error, candidate reloadRuntime, restoreRules bool) error {
		owned, cleanupErr := cleanupCandidate(candidate)
		rollbackErr := rollbackCertificateRenewal(renewal)
		actualRules := append([]portHopRule(nil), h.portHopRules...)
		if cleanupErr != nil {
			joined := errors.Join(primary, cleanupErr, rollbackErr)
			h.finishReloadWithOwnership(nil, owned, oldNodeInfo, oldTag, oldCertConfig, actualRules, nil, nil, nil, stateFailed, joined)
			return joined
		}
		var rulesErr error
		if restoreRules {
			rulesCtx, rulesCancel := service.CleanupContext(ctx)
			_, rulesErr = h.replacePortHopRulesLocked(rulesCtx, oldRules)
			rulesCancel()
			actualRules = append([]portHopRule(nil), h.portHopRules...)
		}
		restored, restoreOwned, restoreErr := restoreOldRuntime()
		joined := errors.Join(primary, rollbackErr, rulesErr, restoreErr)
		if restoreErr != nil {
			h.finishReloadWithOwnership(nil, restoreOwned, oldNodeInfo, oldTag, oldCertConfig, actualRules, nil, nil, nil, stateFailed, joined)
			return joined
		}
		if rulesErr != nil {
			h.finishReload(restored.runtime, oldNodeInfo, oldTag, oldCertConfig, actualRules, restored.serve, restored.authGate, restored.cancel, stateFailed, joined)
			return joined
		}
		h.finishReload(restored.runtime, oldNodeInfo, oldTag, oldCertConfig, oldRules, restored.serve, restored.authGate, restored.cancel, stateRunning, nil)
		return joined
	}

	sameEndpoint := candidateNode.Port == oldNodeInfo.Port
	var candidate reloadRuntime
	if sameEndpoint {
		if err := ctx.Err(); err != nil {
			return abortBeforeRetire(err, candidate)
		}
		if oldTrafficCancel != nil {
			oldTrafficCancel()
		}
		oldCloseErr := closeRuntime(oldRuntime)
		joinErr := h.waitRuntimeContext(ctx, oldServeDone, oldWatcherDone)
		if oldCloseErr != nil || joinErr != nil {
			return retainOldFailure(errors.Join(oldCloseErr, joinErr), candidate)
		}
		candidate, err = h.startReloadCandidateContext(ctx, candidateSpec)
	} else {
		candidate, err = h.startReloadCandidateContext(ctx, candidateSpec)
		if err == nil {
			if ctxErr := ctx.Err(); ctxErr != nil {
				return abortBeforeRetire(ctxErr, candidate)
			}
			if oldTrafficCancel != nil {
				oldTrafficCancel()
			}
			oldCloseErr := closeRuntime(oldRuntime)
			joinErr := h.waitRuntimeContext(ctx, oldServeDone, oldWatcherDone)
			if oldCloseErr != nil || joinErr != nil {
				return retainOldFailure(errors.Join(oldCloseErr, joinErr), candidate)
			}
		}
	}
	if err != nil {
		if !sameEndpoint {
			rollbackErr := rollbackCertificateRenewal(renewal)
			reloadErr := errors.Join(err, rollbackErr)
			if candidate.runtime != nil {
				h.finishExistingReloadWithOwnership([]reloadRuntime{candidate}, stateFailed, reloadErr)
				return reloadErr
			}
			h.finishExistingReload(stateRunning, nil)
			return reloadErr
		}
		return rollbackCandidate(err, candidate, false)
	}
	if err := ctx.Err(); err != nil {
		return rollbackCandidate(err, candidate, false)
	}

	rulesRestored, ruleErr := h.replacePortHopRulesLocked(ctx, candidateRules)
	if ruleErr != nil {
		rollbackErr := rollbackCertificateRenewal(renewal)
		owned, cleanupErr := cleanupCandidate(candidate)
		actualRules := append([]portHopRule(nil), h.portHopRules...)
		if cleanupErr != nil {
			joined := errors.Join(ruleErr, cleanupErr, rollbackErr)
			h.finishReloadWithOwnership(nil, owned, oldNodeInfo, oldTag, oldCertConfig, actualRules, nil, nil, nil, stateFailed, joined)
			return joined
		}
		restored, restoreOwned, restoreErr := restoreOldRuntime()
		joined := errors.Join(ruleErr, rollbackErr, restoreErr)
		if restoreErr != nil {
			h.finishReloadWithOwnership(nil, restoreOwned, oldNodeInfo, oldTag, oldCertConfig, actualRules, nil, nil, nil, stateFailed, joined)
			return joined
		}
		if !rulesRestored {
			h.finishReload(restored.runtime, oldNodeInfo, oldTag, oldCertConfig, actualRules, restored.serve, restored.authGate, restored.cancel, stateFailed, joined)
			return joined
		}
		h.finishReload(restored.runtime, oldNodeInfo, oldTag, oldCertConfig, oldRules, restored.serve, restored.authGate, restored.cancel, stateRunning, nil)
		return joined
	}
	if err := ctx.Err(); err != nil {
		return rollbackCandidate(err, candidate, true)
	}

	if renewal != nil {
		if commitErr := renewal.Commit(); commitErr != nil {
			return rollbackCandidate(commitErr, candidate, true)
		}
	}

	h.finishReload(candidate.runtime, candidateNode, oldTag, candidateCertConfig, candidateRules, candidate.serve, candidate.authGate, candidate.cancel, stateRunning, nil)
	h.logger.Infof("Hysteria2 node reloaded on %s:%d", h.config.ListenIP, candidateNode.Port)
	return nil
}
func certificatePEM(renewal preparedCertificateRenewal) []byte {
	if renewal == nil {
		return nil
	}
	return renewal.CertificatePEM()
}

func privateKeyPEM(renewal preparedCertificateRenewal) []byte {
	if renewal == nil {
		return nil
	}
	return renewal.PrivateKeyPEM()
}

func rollbackCertificateRenewal(renewal preparedCertificateRenewal) error {
	if renewal == nil {
		return nil
	}
	return renewal.Rollback()
}

func (h *Hysteria2Service) startReloadRuntime(runtime runtimeServer, serveRuntime serveRuntimeFunc) (*runtimeServeOutcome, error) {
	ctx, cancel := service.WithDefaultTimeout(context.Background(), service.DefaultStartTimeout)
	defer cancel()
	return h.startReloadRuntimeContext(ctx, runtime, serveRuntime)
}

func (h *Hysteria2Service) startReloadRuntimeContext(ctx context.Context, runtime runtimeServer, serveRuntime serveRuntimeFunc) (*runtimeServeOutcome, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	serveResult := make(chan error, 1)
	serve := &runtimeServeOutcome{done: make(chan struct{})}
	serveStarted := make(chan struct{})
	startServe := func() {
		go func() {
			close(serveStarted)
			serve.err = serveRuntime(runtime)
			serveResult <- serve.err
			close(serve.done)
		}()
	}
	handshake := h.serveHandshake
	if handshake == nil {
		handshake = defaultServeHandshake
	}
	handshakeDone := make(chan error, 1)
	go func() {
		handshakeDone <- handshake(startServe, serveStarted, serveResult)
	}()
	select {
	case <-ctx.Done():
		return serve, ctx.Err()
	case err := <-handshakeDone:
		if err != nil {
			return serve, err
		}
		return serve, ctx.Err()
	}
}
func (h *Hysteria2Service) watchRuntime(runtime runtimeServer, serve *runtimeServeOutcome, cancelTraffic context.CancelFunc, watcherDone chan struct{}) {
	defer close(watcherDone)
	<-serve.done
	if cancelTraffic != nil {
		cancelTraffic()
	}
	h.lifecycleMu.Lock()
	recordFailure := (h.state == stateRunning || h.state == stateFailed) && h.server == runtime
	if recordFailure {
		h.state = stateFailed
		if serve.err != nil {
			h.runtimeErr = errors.Join(h.runtimeErr, serve.err)
		}
	}
	h.lifecycleMu.Unlock()
	if recordFailure {
		h.health.RecordFailure(service.FailureStageRuntime, time.Now())
	}
	if recordFailure && serve.err != nil && h.logger != nil {
		h.logger.Errorf("Hysteria2 Serve error: %v", serve.err)
	}
}

func (h *Hysteria2Service) waitRuntime(serveDone, watcherDone <-chan struct{}) {
	ctx, cancel := service.WithDefaultTimeout(context.Background(), service.DefaultJoinTimeout)
	defer cancel()
	_ = h.waitRuntimeContext(ctx, serveDone, watcherDone)
}

func runtimeLifecycleJoined(doneChannels ...<-chan struct{}) bool {
	for _, done := range doneChannels {
		if done == nil {
			continue
		}
		select {
		case <-done:
		default:
			return false
		}
	}
	return true
}

func (h *Hysteria2Service) waitRuntimeContext(ctx context.Context, serveDone, watcherDone <-chan struct{}) error {
	for _, done := range []<-chan struct{}{serveDone, watcherDone} {
		if done == nil {
			continue
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-done:
		}
	}
	return nil
}
func (h *Hysteria2Service) finishExistingReload(state lifecycleState, runtimeErr error) {
	h.finishExistingReloadWithOwnership(nil, state, runtimeErr)
}

func (h *Hysteria2Service) finishExistingReloadWithOwnership(cleanupRuntimes []reloadRuntime, state lifecycleState, runtimeErr error) {
	h.lifecycleMu.Lock()
	h.cleanupRuntimes = append([]reloadRuntime(nil), cleanupRuntimes...)
	h.state = state
	h.runtimeErr = runtimeErr
	h.lifecycleMu.Unlock()
	if runtimeErr != nil {
		stage := service.FailureStageRuntime
		if len(cleanupRuntimes) != 0 {
			stage = service.FailureStageCleanup
		}
		h.health.RecordFailure(stage, time.Now())
	}
}

func (h *Hysteria2Service) finishReload(runtime runtimeServer, nodeInfo *api.NodeInfo, tag string, certConfig *mylego.CertConfig, rules []portHopRule, serve *runtimeServeOutcome, authGate *runtimeAuthGate, cancelTraffic context.CancelFunc, state lifecycleState, runtimeErr error) {
	h.finishReloadWithOwnership(runtime, nil, nodeInfo, tag, certConfig, rules, serve, authGate, cancelTraffic, state, runtimeErr)
}

func (h *Hysteria2Service) finishReloadWithOwnership(runtime runtimeServer, cleanupRuntimes []reloadRuntime, nodeInfo *api.NodeInfo, _ string, certConfig *mylego.CertConfig, rules []portHopRule, serve *runtimeServeOutcome, authGate *runtimeAuthGate, cancelTraffic context.CancelFunc, state lifecycleState, runtimeErr error) {
	var watcherDone chan struct{}
	if runtime != nil && serve != nil {
		watcherDone = make(chan struct{})
	}
	h.lifecycleMu.Lock()
	h.mu.Lock()
	var nodeLimit uint64
	if nodeInfo != nil {
		nodeLimit = nodeInfo.SpeedLimit
	}
	h.applyNodeRateLimitLocked(nodeLimit)
	h.mu.Unlock()
	h.server = runtime
	h.cleanupRuntimes = append([]reloadRuntime(nil), cleanupRuntimes...)
	h.nodeInfo = nodeInfo
	*h.config.CertConfig = *cloneCertConfig(certConfig)
	h.portHopRules = append([]portHopRule(nil), rules...)
	if serve != nil {
		h.serveDone = serve.done
	} else {
		h.serveDone = nil
	}
	h.watcherDone = watcherDone
	h.trafficCancel = cancelTraffic
	h.state = state
	h.runtimeErr = runtimeErr
	h.lifecycleMu.Unlock()
	if runtimeErr != nil {
		stage := service.FailureStageRuntime
		if len(cleanupRuntimes) != 0 {
			stage = service.FailureStageCleanup
		}
		h.health.RecordFailure(stage, time.Now())
	} else if state == stateRunning {
		h.health.RecordSuccessfulSync(time.Now())
		h.refreshCertificateExpiry()
	}
	authGate.resolve(runtime != nil)
	if watcherDone != nil {
		go h.watchRuntime(runtime, serve, cancelTraffic, watcherDone)
	}
}

func cloneNodeInfo(nodeInfo *api.NodeInfo) *api.NodeInfo {
	if nodeInfo == nil {
		return nil
	}
	cloned := *nodeInfo
	if nodeInfo.Hysteria2Config != nil {
		hysteria2Config := *nodeInfo.Hysteria2Config
		cloned.Hysteria2Config = &hysteria2Config
	}
	return &cloned
}

func cloneCertConfig(certConfig *mylego.CertConfig) *mylego.CertConfig {
	if certConfig == nil {
		return nil
	}
	cloned := *certConfig
	if certConfig.DNSEnv != nil {
		cloned.DNSEnv = make(map[string]string, len(certConfig.DNSEnv))
		for key, value := range certConfig.DNSEnv {
			cloned.DNSEnv[key] = value
		}
	}
	return &cloned
}

func deriveReloadCertConfig(current *mylego.CertConfig, oldInfo, candidate *api.NodeInfo) *mylego.CertConfig {
	cert := cloneCertConfig(current)
	if cert == nil || candidate == nil || !candidate.EnableTLS || candidate.EnableREALITY {
		return cert
	}
	sni := candidate.SNI
	if sni == "" {
		sni = candidate.Host
	}
	if sni == "" {
		return cert
	}
	var oldSNI, oldHost string
	if oldInfo != nil {
		oldSNI, oldHost = oldInfo.SNI, oldInfo.Host
	}
	switch cert.CertMode {
	case "file":
		if cert.CertFile == "" && cert.KeyFile == "" {
			cert.CertDomain = sni
			cert.CertFile = "/etc/XrayR/cert/" + sni + ".cert"
			cert.KeyFile = "/etc/XrayR/cert/" + sni + ".key"
		} else if cert.CertDomain == "" || cert.CertDomain == oldSNI || cert.CertDomain == oldHost {
			cert.CertDomain = sni
		}
	case "dns", "http", "tls":
		if cert.CertDomain == "" || cert.CertDomain == oldSNI || cert.CertDomain == oldHost {
			cert.CertDomain = sni
		}
	}
	return cert
}

func getHysteriaCoreVersion() string {
	info, ok := debug.ReadBuildInfo()
	if !ok {
		return "unknown"
	}
	for _, dep := range info.Deps {
		if dep.Path == "github.com/apernet/hysteria/core/v2" {
			if dep.Version != "" {
				return dep.Version
			}
			if dep.Replace != nil && dep.Replace.Version != "" {
				return dep.Replace.Version
			}
			break
		}
	}
	return "unknown"
}
