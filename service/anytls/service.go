package anytls

import (
	"context"
	"errors"
	"fmt"
	"runtime/debug"
	"time"

	"github.com/sagernet/sing-box/option"
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

var _ service.Service = (*AnyTLSService)(nil)

func defaultRuntimeFactory(s *AnyTLSService, spec runtimeBuildSpec) (runtimeInstance, string, error) {
	return s.buildSingBoxFor(spec)
}

func defaultReloadRuntimeFactory(s *AnyTLSService, spec runtimeBuildSpec) (runtimeInstance, string, error) {
	return s.buildSingBoxFor(spec)
}

func defaultStartRuntime(runtime runtimeInstance) error {
	return runtime.Start()
}

func defaultCloseRuntime(runtime runtimeInstance) error {
	return runtime.Close()
}

func defaultPrepareCertificateRenewal(certConfig *mylego.CertConfig) (preparedCertificateRenewal, error) {
	return mylego.PrepareRenewal(certConfig)
}

func New(apiClient PanelClient, cfg *controller.Config) *AnyTLSService {
	clientInfo := apiClient.Describe()
	logger := log.NewEntry(log.StandardLogger()).WithFields(log.Fields{
		"Host": clientInfo.APIHost,
		"ID":   clientInfo.NodeID,
	})
	serviceRuntime := &AnyTLSService{
		apiClient:            apiClient,
		config:               cfg,
		runtimeFactory:       defaultRuntimeFactory,
		reloadRuntimeFactory: defaultReloadRuntimeFactory,
		startRuntime:         defaultStartRuntime,
		closeRuntime:         defaultCloseRuntime,
		prepareRenewal:       defaultPrepareCertificateRenewal,
		logger:               logger,
		rules:                rule.New(),
		users:                make(map[string]userRecord),
		traffic:              make(map[string]*userTraffic),
		onlineIPs:            make(map[string]map[string]struct{}),
		ipLastActive:         make(map[string]map[string]time.Time),
	}
	serviceRuntime.initializeSnapshotSyncCoordinator()
	return serviceRuntime
}

func (s *AnyTLSService) buildRuntime(spec runtimeBuildSpec) (runtimeInstance, string, error) {
	factory := s.runtimeFactory
	if factory == nil {
		factory = defaultRuntimeFactory
	}
	return factory(s, cloneRuntimeBuildSpec(spec))
}

func (s *AnyTLSService) buildReloadRuntime(spec runtimeBuildSpec) (runtimeInstance, string, error) {
	if s.reloadRuntimeFactory == nil {
		return nil, "", errors.New("AnyTLS reload runtime factory is nil")
	}
	spec.authUsers = s.authUsersSnapshot()
	return s.reloadRuntimeFactory(s, cloneRuntimeBuildSpec(spec))
}

func (s *AnyTLSService) appliedStateSnapshot() (*api.NodeInfo, string, time.Time) {
	s.lifecycleMu.Lock()
	defer s.lifecycleMu.Unlock()
	return s.nodeInfo, s.tag, s.startAt
}

func (s *AnyTLSService) appliedTag() string {
	_, tag, _ := s.appliedStateSnapshot()
	return tag
}

func (s *AnyTLSService) failWithRuntimeOwnership(primary error, clientInfo api.ClientInfo, nodeInfo *api.NodeInfo, runtime runtimeInstance, inboundTag, tag string, startAt time.Time, tasks *specialruntime.Tasks) error {
	s.lifecycleMu.Lock()
	s.clientInfo = clientInfo
	s.nodeInfo = nodeInfo
	s.box = runtime
	s.inboundTag = inboundTag
	s.tag = tag
	s.startAt = startAt
	s.tasks = tasks
	s.state = stateFailed
	s.runtimeErr = primary
	s.closed = false
	s.lifecycleMu.Unlock()
	s.health.RecordFailure(service.FailureStageCleanup, time.Now())
	return primary
}

func (s *AnyTLSService) Start() error {
	ctx, cancel := service.WithDefaultTimeout(context.Background(), service.DefaultStartTimeout)
	defer cancel()
	return s.StartContext(ctx)
}

func (s *AnyTLSService) StartContext(parent context.Context) (err error) {
	ctx, cancel := service.WithDefaultTimeout(parent, service.DefaultStartTimeout)
	defer cancel()
	if err := ctx.Err(); err != nil {
		return err
	}
	s.lifecycleMu.Lock()
	if s.closed {
		s.lifecycleMu.Unlock()
		return errors.New("AnyTLS service cannot start after close")
	}
	if s.state != stateStopped {
		state := s.state
		s.lifecycleMu.Unlock()
		return fmt.Errorf("AnyTLS service cannot start from state %d", state)
	}
	s.state = stateStarting
	s.runtimeErr = nil
	s.lifecycleMu.Unlock()

	fail := func(primary error) error {
		s.lifecycleMu.Lock()
		s.state = stateFailed
		s.runtimeErr = primary
		s.lifecycleMu.Unlock()
		s.health.RecordFailure(service.FailureStageStart, time.Now())
		return primary
	}

	clientInfo := s.apiClient.Describe()
	nodeInfo, err := api.GetNodeInfoContext(ctx, s.apiClient)
	if err != nil {
		return fail(err)
	}
	if nodeInfo == nil || nodeInfo.NodeType != "AnyTLS" {
		return fail(fmt.Errorf("AnyTLSService can only be used with AnyTLS node, got %v", nodeInfo))
	}
	if nodeInfo.Port == 0 {
		return fail(errors.New("server port must > 0"))
	}
	nodeInfo = cloneNodeInfo(nodeInfo)
	if s.config == nil || s.config.CertConfig == nil {
		return fail(errors.New("CertConfig is required for AnyTLS"))
	}
	if nodeInfo.AnyTLSConfig == nil {
		nodeInfo.AnyTLSConfig = &api.AnyTLSConfig{}
	}

	tag := fmt.Sprintf("%s_%s_%d_%d", nodeInfo.NodeType, s.config.ListenIP, nodeInfo.Port, nodeInfo.NodeID)
	startAt := time.Now()

	userInfo, err := api.GetUserListContext(ctx, s.apiClient)
	if err != nil {
		return fail(err)
	}

	startupUsers := s.buildCandidateUserState(userInfo, nodeInfo)
	boxInstance, inboundTag, err := s.buildRuntime(runtimeBuildSpec{
		nodeInfo:   nodeInfo,
		inboundTag: tag,
		certConfig: cloneCertConfig(s.config.CertConfig),
		authUsers:  append([]option.AnyTLSUser(nil), startupUsers.authUsers...),
	})
	if err != nil {
		return fail(err)
	}

	closeRuntime := s.closeRuntime
	if closeRuntime == nil {
		closeRuntime = defaultCloseRuntime
	}

	rulesApplied := false
	if !s.config.DisableGetRule && s.rules != nil {
		ruleList, ruleErr := api.GetNodeRuleContext(ctx, s.apiClient)
		if ruleErr != nil {
			cleanupErr := closeRuntime(boxInstance)
			joined := errors.Join(fmt.Errorf("get rule list: %w", ruleErr), cleanupErr)
			if cleanupErr != nil {
				return s.failWithRuntimeOwnership(joined, clientInfo, nodeInfo, boxInstance, inboundTag, tag, startAt, nil)
			}
			return fail(joined)
		}
		var startupRules []api.DetectRule
		if ruleList != nil {
			startupRules = *ruleList
		}
		if ruleErr := s.rules.UpdateRule(tag, startupRules); ruleErr != nil {
			cleanupErr := closeRuntime(boxInstance)
			joined := errors.Join(ruleErr, cleanupErr)
			if cleanupErr != nil {
				return s.failWithRuntimeOwnership(joined, clientInfo, nodeInfo, boxInstance, inboundTag, tag, startAt, nil)
			}
			return fail(joined)
		}
		rulesApplied = true
	}

	shutdownRuntime := func() error {
		if runtimeErr := closeRuntime(boxInstance); runtimeErr != nil {
			return runtimeErr
		}
		if rulesApplied {
			return s.rules.UpdateRule(tag, nil)
		}
		return nil
	}

	startRuntime := s.startRuntime
	if startRuntime == nil {
		startRuntime = defaultStartRuntime
	}
	if err := startRuntime(boxInstance); err != nil {
		cleanupErr := shutdownRuntime()
		joined := errors.Join(err, cleanupErr)
		if cleanupErr != nil {
			return s.failWithRuntimeOwnership(joined, clientInfo, nodeInfo, boxInstance, inboundTag, tag, startAt, nil)
		}
		return fail(joined)
	}

	interval := time.Duration(s.config.UpdatePeriodic) * time.Second
	s.initializeSnapshotSyncCoordinator()
	tasks := specialruntime.NewTasks()
	tasks.Add(s.syncCoordinator)
	tasks.Add(s.newTask(tag, interval, s.userMonitorContext))
	tasks.Add(s.newTask("node monitor", interval, s.nodeMonitorContext))
	if nodeInfo.EnableTLS {
		tasks.Add(s.newTask("cert monitor", interval*60, s.certMonitorPeriodicContext))
	}

	startupShutdown := specialruntime.RuntimeShutdown{
		Stop:        shutdownRuntime,
		StopContext: func(context.Context) error { return shutdownRuntime() },
	}
	if err := tasks.StartContext(ctx, startupShutdown); err != nil {
		if specialruntime.StartCleanupFailed(err) {
			return s.failWithRuntimeOwnership(err, clientInfo, nodeInfo, boxInstance, inboundTag, tag, startAt, tasks)
		}
		return fail(err)
	}

	s.lifecycleMu.Lock()
	s.clientInfo = clientInfo
	s.nodeInfo = nodeInfo
	s.box = boxInstance
	s.inboundTag = inboundTag
	s.tag = tag
	s.startAt = startAt
	s.tasks = tasks
	s.mu.Lock()
	s.applyUserStateLocked(startupUsers)
	s.mu.Unlock()
	s.state = stateRunning
	s.runtimeErr = nil
	s.lifecycleMu.Unlock()
	s.health.RecordSuccessfulSync(time.Now())
	s.refreshCertificateExpiry()

	s.logger.Infof("AnyTLS node started on %s:%d (sing-box %s)", s.config.ListenIP, nodeInfo.Port, getSingBoxVersion())
	return nil
}

func (s *AnyTLSService) Close() error {
	ctx, cancel := service.WithDefaultTimeout(context.Background(), service.DefaultCloseTimeout)
	defer cancel()
	return s.CloseContext(ctx)
}

func (s *AnyTLSService) CloseContext(parent context.Context) error {
	ctx, cancel := service.WithDefaultTimeout(parent, service.DefaultCloseTimeout)
	defer cancel()

	s.lifecycleMu.Lock()
	if s.closed && s.state == stateStopped {
		s.lifecycleMu.Unlock()
		return nil
	}
	if s.state == stateStarting || s.state == stateStopping {
		s.lifecycleMu.Unlock()
		return errors.New("AnyTLS service cannot close while starting or stopping")
	}
	tasks := s.tasks
	s.lifecycleMu.Unlock()

	// Stop periodic producers before waiting for an in-flight node or
	// certificate replacement to release the operation gate.
	var producerStopErr error
	if tasks != nil {
		producerStopErr = tasks.StopContext(ctx)
	}
	var syncWaitErr error
	if s.syncCoordinator != nil {
		syncWaitErr = s.syncCoordinator.WaitContext(ctx)
	}
	if err := s.reloadMu.Lock(ctx); err != nil {
		return errors.Join(producerStopErr, syncWaitErr, err)
	}
	if err := ctx.Err(); err != nil {
		s.reloadMu.Unlock()
		return errors.Join(producerStopErr, syncWaitErr, err)
	}

	s.lifecycleMu.Lock()
	if s.closed && s.state == stateStopped {
		s.lifecycleMu.Unlock()
		s.reloadMu.Unlock()
		return errors.Join(producerStopErr, syncWaitErr)
	}
	if s.state == stateStarting || s.state == stateReloading || s.state == stateStopping {
		state := s.state
		s.lifecycleMu.Unlock()
		s.reloadMu.Unlock()
		return errors.Join(producerStopErr, syncWaitErr, fmt.Errorf("AnyTLS service cannot close from state %d", state))
	}
	s.state = stateStopping
	tasks = s.tasks
	boxInstance := s.box
	cleanupRuntimes := append([]runtimeInstance(nil), s.cleanupRuntimes...)
	tag := s.tag
	s.lifecycleMu.Unlock()
	s.reloadMu.Unlock()

	closeRuntime := s.closeRuntime
	if closeRuntime == nil {
		closeRuntime = defaultCloseRuntime
	}
	var runtimeCloseErr error
	shutdownRuntime := func() error {
		runtimeCloseErr = closeRuntime(boxInstance)
		return runtimeCloseErr
	}
	shutdown := specialruntime.RuntimeShutdown{
		Stop:        shutdownRuntime,
		StopContext: func(context.Context) error { return shutdownRuntime() },
	}
	var shutdownErr error
	if boxInstance != nil {
		if tasks != nil {
			shutdownErr = errors.Join(producerStopErr, syncWaitErr, tasks.CloseStoppedContext(ctx, shutdown))
		} else {
			shutdownErr = shutdownRuntime()
		}
	} else if tasks != nil {
		shutdownErr = errors.Join(producerStopErr, syncWaitErr, tasks.CloseStoppedContext(ctx, specialruntime.RuntimeShutdown{}))
	}

	remainingRuntimes := make([]runtimeInstance, 0, len(cleanupRuntimes))
	var cleanupErr error
	for _, runtime := range cleanupRuntimes {
		if runtime == nil {
			continue
		}
		if err := ctx.Err(); err != nil {
			remainingRuntimes = append(remainingRuntimes, runtime)
			cleanupErr = errors.Join(cleanupErr, err)
			continue
		}
		if err := closeRuntime(runtime); err != nil {
			remainingRuntimes = append(remainingRuntimes, runtime)
			cleanupErr = errors.Join(cleanupErr, err)
		}
	}
	closeErr := errors.Join(shutdownErr, cleanupErr)
	if closeErr == nil && s.rules != nil && tag != "" {
		closeErr = s.rules.UpdateRule(tag, nil)
	}

	s.lifecycleMu.Lock()
	if runtimeCloseErr == nil {
		s.box = nil
	}
	s.cleanupRuntimes = remainingRuntimes
	if shutdownErr == nil {
		s.tasks = nil
	}
	if closeErr != nil {
		s.state = stateFailed
		s.runtimeErr = closeErr
		s.closed = false
		s.lifecycleMu.Unlock()
		stage := service.FailureStageClose
		if runtimeCloseErr != nil || len(remainingRuntimes) != 0 {
			stage = service.FailureStageCleanup
		}
		s.health.RecordFailure(stage, time.Now())
		return closeErr
	}
	s.nodeInfo = nil
	s.inboundTag = ""
	s.tag = ""
	s.startAt = time.Time{}
	s.state = stateStopped
	s.runtimeErr = nil
	s.closed = true
	s.mu.Lock()
	s.users = make(map[string]userRecord)
	s.traffic = make(map[string]*userTraffic)
	s.onlineIPs = make(map[string]map[string]struct{})
	s.ipLastActive = make(map[string]map[string]time.Time)
	s.authUsers = nil
	s.rateLimiters = nil
	s.mu.Unlock()
	s.lifecycleMu.Unlock()
	return nil
}

// reloadNode replaces the active sing-box instance while preserving the last
// successfully applied node runtime state when replacement fails.
func (s *AnyTLSService) reloadNode(nodeInfo *api.NodeInfo) error {
	ctx, cancel := service.WithDefaultTimeout(context.Background(), service.DefaultSyncTimeout)
	defer cancel()
	return s.reloadNodeContext(ctx, nodeInfo)
}

func (s *AnyTLSService) reloadNodeContext(parent context.Context, nodeInfo *api.NodeInfo) error {
	if nodeInfo == nil {
		return nil
	}
	ctx, cancel := service.WithDefaultTimeout(parent, service.DefaultSyncTimeout)
	defer cancel()
	if err := s.reloadMu.Lock(ctx); err != nil {
		return err
	}
	defer s.reloadMu.Unlock()
	return s.reloadNodeLockedContext(ctx, nodeInfo)
}

func (s *AnyTLSService) reloadNodeLocked(nodeInfo *api.NodeInfo) error {
	ctx, cancel := service.WithDefaultTimeout(context.Background(), service.DefaultSyncTimeout)
	defer cancel()
	return s.reloadNodeLockedContext(ctx, nodeInfo)
}

func (s *AnyTLSService) reloadNodeLockedContext(ctx context.Context, nodeInfo *api.NodeInfo) error {
	return s.reloadNodeWithCertificateLockedContext(ctx, nodeInfo, nil)
}

func (s *AnyTLSService) reloadNodeWithCertificateLocked(nodeInfo *api.NodeInfo, renewal preparedCertificateRenewal) (err error) {
	ctx, cancel := service.WithDefaultTimeout(context.Background(), service.DefaultSyncTimeout)
	defer cancel()
	return s.reloadNodeWithCertificateLockedContext(ctx, nodeInfo, renewal)
}

func (s *AnyTLSService) reloadNodeWithCertificateLockedContext(ctx context.Context, nodeInfo *api.NodeInfo, renewal preparedCertificateRenewal) (err error) {
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
	if nodeInfo.NodeType != "AnyTLS" {
		return fmt.Errorf("AnyTLSService reloadNode: unexpected node type %s", nodeInfo.NodeType)
	}
	if nodeInfo.Port == 0 || nodeInfo.Port > 65535 {
		return errors.New("server port must be between 1 and 65535")
	}
	if s.config == nil || s.config.CertConfig == nil {
		return errors.New("CertConfig is required for AnyTLS")
	}
	if renewal != nil && (len(renewal.CertificatePEM()) == 0 || len(renewal.PrivateKeyPEM()) == 0) {
		return errors.New("prepared certificate renewal is missing certificate or private key PEM")
	}

	candidateNode := cloneNodeInfo(nodeInfo)
	if candidateNode.AnyTLSConfig == nil {
		candidateNode.AnyTLSConfig = &api.AnyTLSConfig{}
	}
	s.lifecycleMu.Lock()
	expectedState := stateRunning
	if renewal != nil {
		expectedState = stateReloading
	}
	if s.closed || s.state != expectedState || s.box == nil || s.nodeInfo == nil {
		state := s.state
		s.lifecycleMu.Unlock()
		return fmt.Errorf("AnyTLS service cannot reload from state %d", state)
	}
	s.state = stateReloading
	oldRuntime := s.box
	oldNodeInfo := s.nodeInfo
	oldTag := s.tag
	oldInboundTag := s.inboundTag
	oldCertConfig := cloneCertConfig(s.config.CertConfig)
	s.lifecycleMu.Unlock()

	candidateCertConfig := deriveReloadCertConfig(oldCertConfig, oldNodeInfo, candidateNode)
	spec := runtimeBuildSpec{
		nodeInfo:       candidateNode,
		inboundTag:     oldInboundTag,
		certConfig:     candidateCertConfig,
		certificatePEM: certificatePEM(renewal),
		privateKeyPEM:  privateKeyPEM(renewal),
	}
	candidateRuntime, _, err := s.buildReloadRuntime(spec)
	if err != nil {
		s.finishReload(oldRuntime, oldNodeInfo, oldTag, oldInboundTag, oldCertConfig, stateRunning, nil)
		return err
	}

	closeRuntime := s.closeRuntime
	if closeRuntime == nil {
		closeRuntime = defaultCloseRuntime
	}
	startRuntime := s.startRuntime
	if startRuntime == nil {
		startRuntime = defaultStartRuntime
	}
	restoreOldRuntime := func() (runtimeInstance, []runtimeInstance, error) {
		restoredRuntime, _, restoreErr := s.buildReloadRuntime(runtimeBuildSpec{
			nodeInfo:   oldNodeInfo,
			inboundTag: oldInboundTag,
			certConfig: oldCertConfig,
		})
		if restoreErr != nil {
			return nil, nil, restoreErr
		}
		if restoreErr = startRuntime(restoredRuntime); restoreErr != nil {
			cleanupErr := closeRuntime(restoredRuntime)
			var owned []runtimeInstance
			if cleanupErr != nil {
				owned = append(owned, restoredRuntime)
			}
			return nil, owned, errors.Join(restoreErr, cleanupErr)
		}
		return restoredRuntime, nil, nil
	}
	abortBeforeRetire := func(primary error) error {
		candidateCloseErr := closeRuntime(candidateRuntime)
		rollbackErr := rollbackCertificateRenewal(renewal)
		joined := errors.Join(primary, candidateCloseErr, rollbackErr)
		if candidateCloseErr != nil {
			s.finishReloadWithOwnership(oldRuntime, []runtimeInstance{candidateRuntime}, oldNodeInfo, oldTag, oldInboundTag, oldCertConfig, stateFailed, joined)
		} else {
			s.finishReload(oldRuntime, oldNodeInfo, oldTag, oldInboundTag, oldCertConfig, stateRunning, nil)
		}
		return joined
	}
	rollbackCandidate := func(primary error) error {
		candidateCloseErr := closeRuntime(candidateRuntime)
		rollbackErr := rollbackCertificateRenewal(renewal)
		reloadErr := errors.Join(primary, candidateCloseErr, rollbackErr)
		if candidateCloseErr != nil {
			s.finishReloadWithOwnership(nil, []runtimeInstance{candidateRuntime}, oldNodeInfo, oldTag, oldInboundTag, oldCertConfig, stateFailed, reloadErr)
			return reloadErr
		}
		restoredRuntime, owned, restoreErr := restoreOldRuntime()
		if restoreErr != nil {
			joined := errors.Join(reloadErr, restoreErr)
			s.finishReloadWithOwnership(nil, owned, oldNodeInfo, oldTag, oldInboundTag, oldCertConfig, stateFailed, joined)
			return joined
		}
		s.finishReload(restoredRuntime, oldNodeInfo, oldTag, oldInboundTag, oldCertConfig, stateRunning, nil)
		return reloadErr
	}

	if err := ctx.Err(); err != nil {
		return abortBeforeRetire(err)
	}
	if oldCloseErr := closeRuntime(oldRuntime); oldCloseErr != nil {
		candidateCloseErr := closeRuntime(candidateRuntime)
		rollbackErr := rollbackCertificateRenewal(renewal)
		var owned []runtimeInstance
		if candidateCloseErr != nil {
			owned = append(owned, candidateRuntime)
		}
		joined := errors.Join(oldCloseErr, candidateCloseErr, rollbackErr)
		s.finishReloadWithOwnership(oldRuntime, owned, oldNodeInfo, oldTag, oldInboundTag, oldCertConfig, stateFailed, joined)
		return joined
	}

	if err := ctx.Err(); err != nil {
		return rollbackCandidate(err)
	}
	if startErr := startRuntime(candidateRuntime); startErr != nil {
		return rollbackCandidate(startErr)
	}
	if err := ctx.Err(); err != nil {
		return rollbackCandidate(err)
	}

	if renewal != nil {
		if commitErr := renewal.Commit(); commitErr != nil {
			return rollbackCandidate(commitErr)
		}
	}

	s.finishReload(candidateRuntime, candidateNode, oldTag, oldInboundTag, candidateCertConfig, stateRunning, nil)
	s.logger.Infof("AnyTLS node reloaded on %s:%d", s.config.ListenIP, candidateNode.Port)
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

func (s *AnyTLSService) finishReload(runtime runtimeInstance, nodeInfo *api.NodeInfo, tag, inboundTag string, certConfig *mylego.CertConfig, state lifecycleState, runtimeErr error) {
	s.finishReloadWithOwnership(runtime, nil, nodeInfo, tag, inboundTag, certConfig, state, runtimeErr)
}

func (s *AnyTLSService) finishReloadWithOwnership(runtime runtimeInstance, cleanupRuntimes []runtimeInstance, nodeInfo *api.NodeInfo, _, _ string, certConfig *mylego.CertConfig, state lifecycleState, runtimeErr error) {
	s.lifecycleMu.Lock()
	s.mu.Lock()
	var nodeLimit uint64
	if nodeInfo != nil {
		nodeLimit = nodeInfo.SpeedLimit
	}
	s.applyNodeRateLimitLocked(nodeLimit)
	s.mu.Unlock()
	s.box = runtime
	s.cleanupRuntimes = append([]runtimeInstance(nil), cleanupRuntimes...)
	s.nodeInfo = nodeInfo
	*s.config.CertConfig = *cloneCertConfig(certConfig)
	s.state = state
	s.runtimeErr = runtimeErr
	s.lifecycleMu.Unlock()
	if runtimeErr != nil {
		stage := service.FailureStageRuntime
		if len(cleanupRuntimes) != 0 {
			stage = service.FailureStageCleanup
		}
		s.health.RecordFailure(stage, time.Now())
		return
	}
	if state == stateRunning {
		s.health.RecordSuccessfulSync(time.Now())
		s.refreshCertificateExpiry()
	}
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

func cloneNodeInfo(nodeInfo *api.NodeInfo) *api.NodeInfo {
	if nodeInfo == nil {
		return nil
	}
	cloned := *nodeInfo
	if nodeInfo.AnyTLSConfig != nil {
		anyTLSConfig := *nodeInfo.AnyTLSConfig
		anyTLSConfig.PaddingScheme = append([]string(nil), nodeInfo.AnyTLSConfig.PaddingScheme...)
		cloned.AnyTLSConfig = &anyTLSConfig
	}
	return &cloned
}

func cloneRuntimeBuildSpec(spec runtimeBuildSpec) runtimeBuildSpec {
	spec.nodeInfo = cloneNodeInfo(spec.nodeInfo)
	spec.certConfig = cloneCertConfig(spec.certConfig)
	spec.certificatePEM = append([]byte(nil), spec.certificatePEM...)
	spec.privateKeyPEM = append([]byte(nil), spec.privateKeyPEM...)
	spec.authUsers = append([]option.AnyTLSUser(nil), spec.authUsers...)
	return spec
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

func getSingBoxVersion() string {
	info, ok := debug.ReadBuildInfo()
	if !ok {
		return "unknown"
	}
	for _, dep := range info.Deps {
		if dep.Path == "github.com/sagernet/sing-box" {
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
