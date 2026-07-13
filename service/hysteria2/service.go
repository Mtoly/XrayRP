package hysteria2

import (
	"errors"
	"fmt"
	"runtime/debug"
	"time"

	"github.com/apernet/hysteria/core/v2/server"
	log "github.com/sirupsen/logrus"
	"golang.org/x/time/rate"

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

func defaultServerConfigFactory(h *Hysteria2Service) (*server.Config, error) {
	return h.buildServerConfig()
}

func defaultReloadServerConfigFactory(h *Hysteria2Service, spec serverBuildSpec) (*server.Config, error) {
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

func defaultRenewCertificate(certConfig *mylego.CertConfig) (string, string, bool, error) {
	lego, err := mylego.New(certConfig)
	if err != nil {
		return "", "", false, err
	}
	return lego.RenewCert()
}

// New creates a new Hysteria2 service bound to a SSPanel node.
func New(apiClient PanelClient, cfg *controller.Config) *Hysteria2Service {
	clientInfo := apiClient.Describe()
	logger := log.NewEntry(log.StandardLogger()).WithFields(log.Fields{
		"Host": clientInfo.APIHost,
		"ID":   clientInfo.NodeID,
	})
	return &Hysteria2Service{
		apiClient:                 apiClient,
		config:                    cfg,
		serverConfigFactory:       defaultServerConfigFactory,
		reloadServerConfigFactory: defaultReloadServerConfigFactory,
		runtimeServerFactory:      defaultRuntimeServerFactory,
		serveRuntime:              defaultServeRuntime,
		closeRuntime:              defaultCloseRuntime,
		renewCertificate:          defaultRenewCertificate,
		taskFactory:               defaultTaskFactory,
		serveHandshake:            defaultServeHandshake,
		logger:                    logger,
		rules:                     rule.New(),
		users:                     make(map[string]userRecord),
		traffic:                   make(map[string]*userTraffic),
		overLimit:                 make(map[string]bool),
		onlineIPs:                 make(map[string]map[string]struct{}),
		ipLastActive:              make(map[string]map[string]time.Time),
		blockedIDs:                make(map[string]bool),
	}
}

func (h *Hysteria2Service) buildRuntimeServer() (runtimeServer, error) {
	configFactory := h.serverConfigFactory
	if configFactory == nil {
		configFactory = defaultServerConfigFactory
	}
	cfg, err := configFactory(h)
	if err != nil {
		return nil, err
	}

	runtimeFactory := h.runtimeServerFactory
	if runtimeFactory == nil {
		runtimeFactory = defaultRuntimeServerFactory
	}
	return runtimeFactory(cfg)
}

func (h *Hysteria2Service) buildReloadRuntimeServer(spec serverBuildSpec) (runtimeServer, error) {
	if h.reloadServerConfigFactory == nil {
		return nil, errors.New("Hysteria2 reload server config factory is nil")
	}
	cfg, err := h.reloadServerConfigFactory(h, spec)
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
	runtime, err := h.buildReloadRuntimeServer(spec)
	if err != nil {
		return reloadRuntime{}, err
	}
	serveRuntime := h.serveRuntime
	if serveRuntime == nil {
		serveRuntime = defaultServeRuntime
	}
	serve, err := h.startReloadRuntime(runtime, serveRuntime)
	if err != nil {
		closeRuntime := h.closeRuntime
		if closeRuntime == nil {
			closeRuntime = defaultCloseRuntime
		}
		cleanupErr := closeRuntime(runtime)
		h.waitRuntime(serve.done, nil)
		return reloadRuntime{}, errors.Join(err, cleanupErr)
	}
	return reloadRuntime{runtime: runtime, serve: serve}, nil
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

	oldNodeInfo, oldTag := h.nodeInfo, h.tag
	h.mu.Lock()
	oldUsers := h.users
	oldTraffic := h.traffic
	oldOverLimit := h.overLimit
	oldOnlineIPs := h.onlineIPs
	oldIPLastActive := h.ipLastActive
	oldRateLimiters := h.rateLimiters
	startupRateLimiters := make(map[string]*rate.Limiter, len(oldRateLimiters))
	for key, limiter := range oldRateLimiters {
		if limiter != nil {
			startupRateLimiters[key] = rate.NewLimiter(limiter.Limit(), limiter.Burst())
		}
	}
	h.rateLimiters = startupRateLimiters
	h.mu.Unlock()
	restoreStartupState := func() {
		h.nodeInfo, h.tag = oldNodeInfo, oldTag
		h.mu.Lock()
		h.users = oldUsers
		h.traffic = oldTraffic
		h.overLimit = oldOverLimit
		h.onlineIPs = oldOnlineIPs
		h.ipLastActive = oldIPLastActive
		h.rateLimiters = oldRateLimiters
		h.mu.Unlock()
	}
	h.nodeInfo, h.tag = nodeInfo, tag
	h.syncUsers(userInfo)
	h.mu.Lock()
	startupUsers := h.users
	startupTraffic := h.traffic
	startupOverLimit := h.overLimit
	startupOnlineIPs := h.onlineIPs
	startupIPLastActive := h.ipLastActive
	startupRateLimiters = h.rateLimiters
	h.mu.Unlock()

	srv, err := h.buildRuntimeServer()
	restoreStartupState()
	if err != nil {
		return fail(err)
	}

	closeRuntime := h.closeRuntime
	if closeRuntime == nil {
		closeRuntime = defaultCloseRuntime
	}
	serveRuntime := h.serveRuntime
	if serveRuntime == nil {
		serveRuntime = defaultServeRuntime
	}
	serve, err := h.startReloadRuntime(srv, serveRuntime)
	if err != nil {
		cleanupErr := closeRuntime(srv)
		h.waitRuntime(serve.done, nil)
		return fail(errors.Join(err, cleanupErr))
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
		tasks.Add(factory("cert monitor", interval*60, h.certMonitor))
	}
	startupShutdown := specialruntime.RuntimeShutdown{
		Stop: func() error { return closeRuntime(srv) },
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
	h.users = startupUsers
	h.traffic = startupTraffic
	h.overLimit = startupOverLimit
	h.onlineIPs = startupOnlineIPs
	h.ipLastActive = startupIPLastActive
	h.rateLimiters = startupRateLimiters
	h.mu.Unlock()
	h.state = stateRunning
	h.runtimeErr = nil
	h.serveDone = serve.done
	h.watcherDone = watcherDone
	h.lifecycleMu.Unlock()
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

	candidateNode := *nodeInfo
	candidateRules := buildPortHopRulesFromNode(&candidateNode)

	h.lifecycleMu.Lock()
	if h.closed || h.state != stateRunning || h.server == nil || h.nodeInfo == nil {
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
		nodeInfo:   &candidateNode,
		certConfig: candidateCertConfig,
	}

	closeRuntime := h.closeRuntime
	if closeRuntime == nil {
		closeRuntime = defaultCloseRuntime
	}

	sameEndpoint := candidateNode.Port == oldNodeInfo.Port
	var (
		candidate   reloadRuntime
		oldCloseErr error
		err         error
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
		reloadErr := errors.Join(oldCloseErr, err)
		restored, restoreErr := h.startReloadCandidate(serverBuildSpec{
			nodeInfo:   oldNodeInfo,
			certConfig: oldCertConfig,
		})
		if restoreErr != nil {
			joined := errors.Join(reloadErr, restoreErr)
			h.finishReload(nil, oldNodeInfo, oldTag, oldCertConfig, oldRules, nil, stateFailed, joined)
			return joined
		}
		h.finishReload(restored.runtime, oldNodeInfo, oldTag, oldCertConfig, oldRules, restored.serve, stateRunning, nil)
		return reloadErr
	}

	if !sameEndpoint {
		// Old close errors are surfaced, but the ready candidate remains the
		// last-known-good runtime because the old endpoint is already released.
	}
	rulesRestored, ruleErr := h.replacePortHopRulesLocked(candidateRules)
	if ruleErr != nil {
		cleanupErr := closeRuntime(candidate.runtime)
		h.waitRuntime(candidate.serve.done, nil)
		restored, restoreErr := h.startReloadCandidate(serverBuildSpec{
			nodeInfo:   oldNodeInfo,
			certConfig: oldCertConfig,
		})
		if restoreErr != nil {
			joined := errors.Join(oldCloseErr, ruleErr, cleanupErr, restoreErr)
			restoredRules := oldRules
			if !rulesRestored {
				restoredRules = nil
			}
			h.finishReload(nil, oldNodeInfo, oldTag, oldCertConfig, restoredRules, nil, stateFailed, joined)
			return joined
		}
		joined := errors.Join(oldCloseErr, ruleErr, cleanupErr)
		if !rulesRestored {
			h.finishReload(restored.runtime, oldNodeInfo, oldTag, oldCertConfig, nil, restored.serve, stateFailed, joined)
			return joined
		}
		h.finishReload(restored.runtime, oldNodeInfo, oldTag, oldCertConfig, oldRules, restored.serve, stateRunning, nil)
		return joined
	}
	h.finishReload(candidate.runtime, &candidateNode, oldTag, candidateCertConfig, candidateRules, candidate.serve, stateRunning, nil)
	h.logger.Infof("Hysteria2 node reloaded on %s:%d", h.config.ListenIP, candidateNode.Port)
	return oldCloseErr
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

func (h *Hysteria2Service) finishReload(runtime runtimeServer, nodeInfo *api.NodeInfo, _ string, certConfig *mylego.CertConfig, rules []portHopRule, serve *runtimeServeOutcome, state lifecycleState, runtimeErr error) {
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
