package hysteria2

import (
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
	return &Hysteria2Service{
		apiClient:            apiClient,
		config:               cfg,
		serverConfigFactory:  defaultServerConfigFactory,
		runtimeServerFactory: defaultRuntimeServerFactory,
		serveRuntime:         defaultServeRuntime,
		closeRuntime:         defaultCloseRuntime,
		prepareRenewal:       defaultPrepareCertificateRenewal,
		taskFactory:          defaultTaskFactory,
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

func (h *Hysteria2Service) startReloadCandidate(spec serverBuildSpec) (reloadRuntime, error) {
	authGate := newRuntimeAuthGate()
	spec.authGate = authGate
	runtime, err := h.buildRuntimeServer(spec)
	if err != nil {
		authGate.resolve(false)
		return reloadRuntime{}, err
	}
	serveRuntime := h.serveRuntime
	if serveRuntime == nil {
		serveRuntime = defaultServeRuntime
	}
	serve, err := h.startReloadRuntime(runtime, serveRuntime)
	if err != nil {
		authGate.resolve(false)
		closeRuntime := h.closeRuntime
		if closeRuntime == nil {
			closeRuntime = defaultCloseRuntime
		}
		cleanupErr := closeRuntime(runtime)
		h.waitRuntime(serve.done, nil)
		return reloadRuntime{}, errors.Join(err, cleanupErr)
	}
	return reloadRuntime{runtime: runtime, serve: serve, authGate: authGate}, nil
}

func (h *Hysteria2Service) Start() (err error) {
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
		return primary
	}

	clientInfo := h.apiClient.Describe()
	nodeInfo, err := h.apiClient.GetNodeInfo()
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

	tag := fmt.Sprintf("%s_%s_%d_%d", nodeInfo.NodeType, h.config.ListenIP, nodeInfo.Port, nodeInfo.NodeID)
	startAt := time.Now()

	userInfo, err := h.apiClient.GetUserList()
	if err != nil {
		return fail(err)
	}

	startupUsers := h.buildCandidateUserState(userInfo, nodeInfo)

	candidate, err := h.startReloadCandidate(serverBuildSpec{
		nodeInfo:   nodeInfo,
		certConfig: cloneCertConfig(h.config.CertConfig),
	})
	if err != nil {
		return fail(err)
	}
	srv := candidate.runtime
	serve := candidate.serve

	closeRuntime := h.closeRuntime
	if closeRuntime == nil {
		closeRuntime = defaultCloseRuntime
	}

	factory := h.taskFactory
	if factory == nil {
		factory = defaultTaskFactory
	}
	interval := time.Duration(h.config.UpdatePeriodic) * time.Second
	tasks := specialruntime.NewTasks()
	tasks.Add(factory(tag, interval, h.userMonitor))
	tasks.Add(factory("node monitor", interval, h.nodeMonitor))
	if nodeInfo.EnableTLS {
		tasks.Add(factory("cert monitor", interval*60, h.certMonitorPeriodic))
	}
	startupShutdown := specialruntime.RuntimeShutdown{
		Stop: func() error {
			candidate.authGate.resolve(false)
			return closeRuntime(srv)
		},
		Join: func() error {
			h.waitRuntime(serve.done, nil)
			return nil
		},
	}
	if err := tasks.Start(startupShutdown); err != nil {
		return fail(err)
	}

	h.reloadMu.Lock()
	_, ruleErr := h.replacePortHopRulesLocked(buildPortHopRulesFromNode(nodeInfo))
	h.reloadMu.Unlock()
	if ruleErr != nil {
		return fail(errors.Join(ruleErr, tasks.Rollback(startupShutdown)))
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
	h.lifecycleMu.Unlock()
	candidate.authGate.resolve(true)
	go h.watchRuntime(srv, serve, watcherDone)

	if !h.config.DisableGetRule && h.rules != nil {
		if ruleList, ruleErr := h.apiClient.GetNodeRule(); ruleErr != nil {
			h.logger.Printf("Get rule list filed: %s", ruleErr)
		} else if ruleList != nil && len(*ruleList) > 0 {
			if ruleErr := h.rules.UpdateRule(tag, *ruleList); ruleErr != nil {
				h.logger.Print(ruleErr)
			}
		}
	}

	h.logger.Infof("Hysteria2 node started on %s:%d (hysteria core %s)", h.config.ListenIP, nodeInfo.Port, getHysteriaCoreVersion())
	return nil
}

// Close implements service.Service.Close.
func (h *Hysteria2Service) Close() error {
	h.lifecycleMu.Lock()
	if h.closed {
		state := h.state
		h.lifecycleMu.Unlock()
		if state == stateStopped {
			return h.cleanupPortHopRules()
		}
		return nil
	}
	if h.state == stateStarting || h.state == stateReloading {
		h.lifecycleMu.Unlock()
		return errors.New("Hysteria2 service cannot close while starting or reloading")
	}
	h.closed = true
	h.state = stateStopping
	tasks := h.tasks
	srv := h.server
	serveDone := h.serveDone
	watcherDone := h.watcherDone
	h.lifecycleMu.Unlock()

	var shutdownErr error
	if srv != nil {
		closeRuntime := h.closeRuntime
		if closeRuntime == nil {
			closeRuntime = defaultCloseRuntime
		}
		shutdown := specialruntime.RuntimeShutdown{
			Stop: func() error { return closeRuntime(srv) },
			Join: func() error {
				h.waitRuntime(serveDone, watcherDone)
				return nil
			},
		}
		if tasks != nil {
			shutdownErr = tasks.Close(shutdown)
		} else {
			shutdownErr = errors.Join(shutdown.Stop(), shutdown.Join())
		}
	} else if tasks != nil {
		shutdownErr = tasks.Close(specialruntime.RuntimeShutdown{})
	}

	cleanupErr := h.cleanupPortHopRules()

	h.lifecycleMu.Lock()
	h.tasks = nil
	h.server = nil
	h.serveDone = nil
	h.watcherDone = nil
	h.runtimeErr = nil
	h.state = stateStopped
	h.lifecycleMu.Unlock()
	return errors.Join(shutdownErr, cleanupErr)
}

// reloadNode replaces the active Hysteria2 server while preserving the last
// successfully applied node runtime state when replacement fails.
func (h *Hysteria2Service) reloadNode(nodeInfo *api.NodeInfo) error {
	if nodeInfo == nil {
		return nil
	}
	h.reloadMu.Lock()
	defer h.reloadMu.Unlock()
	return h.reloadNodeLocked(nodeInfo)
}

func (h *Hysteria2Service) reloadNodeLocked(nodeInfo *api.NodeInfo) error {
	return h.reloadNodeWithCertificateLocked(nodeInfo, nil)
}

func (h *Hysteria2Service) reloadNodeWithCertificateLocked(nodeInfo *api.NodeInfo, renewal preparedCertificateRenewal) (err error) {
	if renewal != nil {
		defer func() {
			err = errors.Join(err, renewal.Rollback())
		}()
	}
	if nodeInfo == nil {
		return nil
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

	candidateNode := *nodeInfo
	candidateRules := buildPortHopRulesFromNode(&candidateNode)

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
	h.lifecycleMu.Unlock()

	candidateCertConfig := deriveReloadCertConfig(oldCertConfig, oldNodeInfo, &candidateNode)
	candidateSpec := serverBuildSpec{
		nodeInfo:       &candidateNode,
		certConfig:     candidateCertConfig,
		certificatePEM: certificatePEM(renewal),
		privateKeyPEM:  privateKeyPEM(renewal),
	}

	closeRuntime := h.closeRuntime
	if closeRuntime == nil {
		closeRuntime = defaultCloseRuntime
	}

	sameEndpoint := candidateNode.Port == oldNodeInfo.Port
	var (
		candidate   reloadRuntime
		oldCloseErr error
	)
	if sameEndpoint {
		oldCloseErr = closeRuntime(oldRuntime)
		h.waitRuntime(oldServeDone, oldWatcherDone)
		candidate, err = h.startReloadCandidate(candidateSpec)
	} else {
		candidate, err = h.startReloadCandidate(candidateSpec)
		if err == nil {
			oldCloseErr = closeRuntime(oldRuntime)
			h.waitRuntime(oldServeDone, oldWatcherDone)
		}
	}
	if err != nil {
		if !sameEndpoint {
			h.finishExistingReload(stateRunning, nil)
			return err
		}
		rollbackErr := rollbackCertificateRenewal(renewal)
		reloadErr := errors.Join(oldCloseErr, err, rollbackErr)
		restored, restoreErr := h.startReloadCandidate(serverBuildSpec{
			nodeInfo:   oldNodeInfo,
			certConfig: oldCertConfig,
		})
		if restoreErr != nil {
			joined := errors.Join(reloadErr, restoreErr)
			h.finishReload(nil, oldNodeInfo, oldTag, oldCertConfig, oldRules, nil, nil, stateFailed, joined)
			return joined
		}
		h.finishReload(restored.runtime, oldNodeInfo, oldTag, oldCertConfig, oldRules, restored.serve, restored.authGate, stateRunning, nil)
		return reloadErr
	}

	if !sameEndpoint {
		// Old close errors are surfaced, but the ready candidate remains the
		// last-known-good runtime because the old endpoint is already released.
	}
	rulesRestored, ruleErr := h.replacePortHopRulesLocked(candidateRules)
	if ruleErr != nil {
		rollbackErr := rollbackCertificateRenewal(renewal)
		candidate.authGate.resolve(false)
		cleanupErr := closeRuntime(candidate.runtime)
		h.waitRuntime(candidate.serve.done, nil)
		restored, restoreErr := h.startReloadCandidate(serverBuildSpec{
			nodeInfo:   oldNodeInfo,
			certConfig: oldCertConfig,
		})
		if restoreErr != nil {
			joined := errors.Join(oldCloseErr, ruleErr, cleanupErr, rollbackErr, restoreErr)
			restoredRules := oldRules
			if !rulesRestored {
				restoredRules = nil
			}
			h.finishReload(nil, oldNodeInfo, oldTag, oldCertConfig, restoredRules, nil, nil, stateFailed, joined)
			return joined
		}
		joined := errors.Join(oldCloseErr, ruleErr, cleanupErr, rollbackErr)
		if !rulesRestored {
			h.finishReload(restored.runtime, oldNodeInfo, oldTag, oldCertConfig, nil, restored.serve, restored.authGate, stateFailed, joined)
			return joined
		}
		h.finishReload(restored.runtime, oldNodeInfo, oldTag, oldCertConfig, oldRules, restored.serve, restored.authGate, stateRunning, nil)
		return joined
	}

	if renewal != nil {
		if commitErr := renewal.Commit(); commitErr != nil {
			candidate.authGate.resolve(false)
			cleanupErr := closeRuntime(candidate.runtime)
			h.waitRuntime(candidate.serve.done, nil)
			_, rulesErr := h.replacePortHopRulesLocked(oldRules)
			actualRules := append([]portHopRule(nil), h.portHopRules...)
			restored, restoreErr := h.startReloadCandidate(serverBuildSpec{
				nodeInfo:   oldNodeInfo,
				certConfig: oldCertConfig,
			})
			joined := errors.Join(oldCloseErr, commitErr, cleanupErr, rulesErr, restoreErr)
			if restoreErr != nil {
				h.finishReload(nil, oldNodeInfo, oldTag, oldCertConfig, actualRules, nil, nil, stateFailed, joined)
				return joined
			}
			if rulesErr != nil {
				h.finishReload(restored.runtime, oldNodeInfo, oldTag, oldCertConfig, actualRules, restored.serve, restored.authGate, stateFailed, joined)
				return joined
			}
			h.finishReload(restored.runtime, oldNodeInfo, oldTag, oldCertConfig, oldRules, restored.serve, restored.authGate, stateRunning, nil)
			return joined
		}
	}

	h.finishReload(candidate.runtime, &candidateNode, oldTag, candidateCertConfig, candidateRules, candidate.serve, candidate.authGate, stateRunning, nil)
	h.logger.Infof("Hysteria2 node reloaded on %s:%d", h.config.ListenIP, candidateNode.Port)
	return oldCloseErr
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
	if err := handshake(startServe, serveStarted, serveResult); err != nil {
		return serve, err
	}
	return serve, nil
}

func (h *Hysteria2Service) watchRuntime(runtime runtimeServer, serve *runtimeServeOutcome, watcherDone chan struct{}) {
	defer close(watcherDone)
	<-serve.done
	h.lifecycleMu.Lock()
	recordFailure := (h.state == stateRunning || h.state == stateFailed) && h.server == runtime
	if recordFailure {
		h.state = stateFailed
		if serve.err != nil {
			h.runtimeErr = errors.Join(h.runtimeErr, serve.err)
		}
	}
	h.lifecycleMu.Unlock()
	if recordFailure && serve.err != nil && h.logger != nil {
		h.logger.Errorf("Hysteria2 Serve error: %v", serve.err)
	}
}

func (h *Hysteria2Service) waitRuntime(serveDone, watcherDone <-chan struct{}) {
	if serveDone != nil {
		<-serveDone
	}
	if watcherDone != nil {
		<-watcherDone
	}
}

func (h *Hysteria2Service) finishExistingReload(state lifecycleState, runtimeErr error) {
	h.lifecycleMu.Lock()
	h.state = state
	h.runtimeErr = runtimeErr
	h.lifecycleMu.Unlock()
}

func (h *Hysteria2Service) finishReload(runtime runtimeServer, nodeInfo *api.NodeInfo, _ string, certConfig *mylego.CertConfig, rules []portHopRule, serve *runtimeServeOutcome, authGate *runtimeAuthGate, state lifecycleState, runtimeErr error) {
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
	h.nodeInfo = nodeInfo
	*h.config.CertConfig = *cloneCertConfig(certConfig)
	h.portHopRules = append([]portHopRule(nil), rules...)
	if serve != nil {
		h.serveDone = serve.done
	} else {
		h.serveDone = nil
	}
	h.watcherDone = watcherDone
	h.state = state
	h.runtimeErr = runtimeErr
	h.lifecycleMu.Unlock()
	authGate.resolve(runtime != nil)
	if watcherDone != nil {
		go h.watchRuntime(runtime, serve, watcherDone)
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
