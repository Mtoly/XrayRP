package anytls

import (
	"errors"
	"fmt"
	"runtime/debug"
	"time"

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

var _ service.Service = (*AnyTLSService)(nil)

func defaultRuntimeFactory(s *AnyTLSService) (runtimeInstance, string, error) {
	return s.buildSingBox()
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

func defaultRenewCertificate(certConfig *mylego.CertConfig) (string, string, bool, error) {
	lego, err := mylego.New(certConfig)
	if err != nil {
		return "", "", false, err
	}
	return lego.RenewCert()
}

func New(apiClient PanelClient, cfg *controller.Config) *AnyTLSService {
	clientInfo := apiClient.Describe()
	logger := log.NewEntry(log.StandardLogger()).WithFields(log.Fields{
		"Host": clientInfo.APIHost,
		"ID":   clientInfo.NodeID,
	})
	return &AnyTLSService{
		apiClient:            apiClient,
		config:               cfg,
		runtimeFactory:       defaultRuntimeFactory,
		reloadRuntimeFactory: defaultReloadRuntimeFactory,
		startRuntime:         defaultStartRuntime,
		closeRuntime:         defaultCloseRuntime,
		renewCertificate:     defaultRenewCertificate,
		taskFactory:          defaultTaskFactory,
		logger:               logger,
		rules:                rule.New(),
		users:                make(map[string]userRecord),
		traffic:              make(map[string]*userTraffic),
		onlineIPs:            make(map[string]map[string]struct{}),
		ipLastActive:         make(map[string]map[string]time.Time),
	}
}

func (s *AnyTLSService) buildRuntime() (runtimeInstance, string, error) {
	factory := s.runtimeFactory
	if factory == nil {
		factory = defaultRuntimeFactory
	}
	return factory(s)
}

func (s *AnyTLSService) buildReloadRuntime(spec runtimeBuildSpec) (runtimeInstance, string, error) {
	if s.reloadRuntimeFactory == nil {
		return nil, "", errors.New("AnyTLS reload runtime factory is nil")
	}
	return s.reloadRuntimeFactory(s, spec)
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

func (s *AnyTLSService) Start() (err error) {
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
		return primary
	}

	clientInfo := s.apiClient.Describe()
	nodeInfo, err := s.apiClient.GetNodeInfo()
	if err != nil {
		return fail(err)
	}
	if nodeInfo == nil || nodeInfo.NodeType != "AnyTLS" {
		return fail(fmt.Errorf("AnyTLSService can only be used with AnyTLS node, got %v", nodeInfo))
	}
	if nodeInfo.Port == 0 {
		return fail(errors.New("server port must > 0"))
	}
	if s.config == nil || s.config.CertConfig == nil {
		return fail(errors.New("CertConfig is required for AnyTLS"))
	}
	if nodeInfo.AnyTLSConfig == nil {
		nodeInfo.AnyTLSConfig = &api.AnyTLSConfig{}
	}

	tag := fmt.Sprintf("%s_%s_%d_%d", nodeInfo.NodeType, s.config.ListenIP, nodeInfo.Port, nodeInfo.NodeID)
	startAt := time.Now()

	userInfo, err := s.apiClient.GetUserList()
	if err != nil {
		return fail(err)
	}

	oldNodeInfo, oldTag, oldInboundTag := s.nodeInfo, s.tag, s.inboundTag
	s.mu.Lock()
	oldUsers := s.users
	oldTraffic := s.traffic
	oldOnlineIPs := s.onlineIPs
	oldIPLastActive := s.ipLastActive
	oldAuthUsers := s.authUsers
	oldRateLimiters := s.rateLimiters
	startupRateLimiters := make(map[string]*rate.Limiter, len(oldRateLimiters))
	for key, limiter := range oldRateLimiters {
		if limiter != nil {
			startupRateLimiters[key] = rate.NewLimiter(limiter.Limit(), limiter.Burst())
		}
	}
	s.rateLimiters = startupRateLimiters
	s.mu.Unlock()
	restoreStartupState := func() {
		s.nodeInfo, s.tag, s.inboundTag = oldNodeInfo, oldTag, oldInboundTag
		s.mu.Lock()
		s.users = oldUsers
		s.traffic = oldTraffic
		s.onlineIPs = oldOnlineIPs
		s.ipLastActive = oldIPLastActive
		s.authUsers = oldAuthUsers
		s.rateLimiters = oldRateLimiters
		s.mu.Unlock()
	}
	s.nodeInfo, s.tag, s.inboundTag = nodeInfo, tag, tag
	s.syncUsers(userInfo)
	s.mu.Lock()
	startupUsers := s.users
	startupTraffic := s.traffic
	startupOnlineIPs := s.onlineIPs
	startupIPLastActive := s.ipLastActive
	startupAuthUsers := s.authUsers
	startupRateLimiters = s.rateLimiters
	s.mu.Unlock()

	boxInstance, inboundTag, err := s.buildRuntime()
	restoreStartupState()
	if err != nil {
		return fail(err)
	}

	closeRuntime := s.closeRuntime
	if closeRuntime == nil {
		closeRuntime = defaultCloseRuntime
	}
	cleanupRuntime := func(primary error) error {
		return errors.Join(primary, closeRuntime(boxInstance))
	}

	startRuntime := s.startRuntime
	if startRuntime == nil {
		startRuntime = defaultStartRuntime
	}
	if err := startRuntime(boxInstance); err != nil {
		return fail(cleanupRuntime(err))
	}

	factory := s.taskFactory
	if factory == nil {
		factory = defaultTaskFactory
	}
	interval := time.Duration(s.config.UpdatePeriodic) * time.Second
	tasks := specialruntime.NewTasks()
	tasks.Add(factory(tag, interval, s.userMonitor))
	tasks.Add(factory("node monitor", interval, s.nodeMonitor))
	if nodeInfo.EnableTLS {
		tasks.Add(factory("cert monitor", interval*60, s.certMonitor))
	}

	if err := tasks.Start(specialruntime.RuntimeShutdown{
		Stop: func() error { return closeRuntime(boxInstance) },
	}); err != nil {
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
	s.users = startupUsers
	s.traffic = startupTraffic
	s.onlineIPs = startupOnlineIPs
	s.ipLastActive = startupIPLastActive
	s.authUsers = startupAuthUsers
	s.rateLimiters = startupRateLimiters
	s.mu.Unlock()
	s.state = stateRunning
	s.runtimeErr = nil
	s.lifecycleMu.Unlock()

	if !s.config.DisableGetRule && s.rules != nil {
		if ruleList, ruleErr := s.apiClient.GetNodeRule(); ruleErr != nil {
			s.logger.Printf("Get rule list filed: %s", ruleErr)
		} else if ruleList != nil && len(*ruleList) > 0 {
			if ruleErr := s.rules.UpdateRule(tag, *ruleList); ruleErr != nil {
				s.logger.Print(ruleErr)
			}
		}
	}

	s.logger.Infof("AnyTLS node started on %s:%d (sing-box %s)", s.config.ListenIP, nodeInfo.Port, getSingBoxVersion())
	return nil
}

func (s *AnyTLSService) Close() error {
	s.lifecycleMu.Lock()
	if s.closed {
		s.lifecycleMu.Unlock()
		return nil
	}
	if s.state == stateStarting || s.state == stateReloading {
		s.lifecycleMu.Unlock()
		return errors.New("AnyTLS service cannot close while starting or reloading")
	}
	s.closed = true
	s.state = stateStopping
	tasks := s.tasks
	boxInstance := s.box
	s.lifecycleMu.Unlock()

	var closeErr error
	if boxInstance != nil {
		closeRuntime := s.closeRuntime
		if closeRuntime == nil {
			closeRuntime = defaultCloseRuntime
		}
		shutdown := specialruntime.RuntimeShutdown{
			Stop: func() error { return closeRuntime(boxInstance) },
		}
		if tasks != nil {
			closeErr = tasks.Close(shutdown)
		} else {
			closeErr = shutdown.Stop()
		}
	} else if tasks != nil {
		closeErr = tasks.Close(specialruntime.RuntimeShutdown{})
	}

	s.lifecycleMu.Lock()
	s.tasks = nil
	s.box = nil
	s.state = stateStopped
	s.lifecycleMu.Unlock()
	return closeErr
}

// reloadNode replaces the active sing-box instance while preserving the last
// successfully applied node runtime state when replacement fails.
func (s *AnyTLSService) reloadNode(nodeInfo *api.NodeInfo) error {
	if nodeInfo == nil {
		return nil
	}
	s.reloadMu.Lock()
	defer s.reloadMu.Unlock()
	return s.reloadNodeLocked(nodeInfo)
}

func (s *AnyTLSService) reloadNodeLocked(nodeInfo *api.NodeInfo) error {
	if nodeInfo == nil {
		return nil
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

	candidateNode := *nodeInfo
	if candidateNode.AnyTLSConfig == nil {
		candidateNode.AnyTLSConfig = &api.AnyTLSConfig{}
	}
	s.lifecycleMu.Lock()
	if s.closed || s.state != stateRunning || s.box == nil || s.nodeInfo == nil {
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

	candidateCertConfig := deriveReloadCertConfig(oldCertConfig, oldNodeInfo, &candidateNode)
	candidateRuntime, _, err := s.buildReloadRuntime(runtimeBuildSpec{
		nodeInfo:   &candidateNode,
		inboundTag: oldInboundTag,
		certConfig: candidateCertConfig,
	})
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

	oldCloseErr := closeRuntime(oldRuntime)
	if err := startRuntime(candidateRuntime); err != nil {
		reloadErr := errors.Join(oldCloseErr, err, closeRuntime(candidateRuntime))
		restoredRuntime, _, restoreErr := s.buildReloadRuntime(runtimeBuildSpec{
			nodeInfo:   oldNodeInfo,
			inboundTag: oldInboundTag,
			certConfig: oldCertConfig,
		})
		if restoreErr == nil {
			restoreErr = startRuntime(restoredRuntime)
			if restoreErr != nil {
				restoreErr = errors.Join(restoreErr, closeRuntime(restoredRuntime))
			}
		}
		if restoreErr != nil {
			joined := errors.Join(reloadErr, restoreErr)
			s.finishReload(nil, oldNodeInfo, oldTag, oldInboundTag, oldCertConfig, stateFailed, joined)
			return joined
		}
		s.finishReload(restoredRuntime, oldNodeInfo, oldTag, oldInboundTag, oldCertConfig, stateRunning, nil)
		return reloadErr
	}

	s.finishReload(candidateRuntime, &candidateNode, oldTag, oldInboundTag, candidateCertConfig, stateRunning, nil)
	s.logger.Infof("AnyTLS node reloaded on %s:%d", s.config.ListenIP, candidateNode.Port)
	return oldCloseErr
}

func (s *AnyTLSService) finishReload(runtime runtimeInstance, nodeInfo *api.NodeInfo, _, _ string, certConfig *mylego.CertConfig, state lifecycleState, runtimeErr error) {
	s.lifecycleMu.Lock()
	s.mu.Lock()
	var nodeLimit uint64
	if nodeInfo != nil {
		nodeLimit = nodeInfo.SpeedLimit
	}
	s.applyNodeRateLimitLocked(nodeLimit)
	s.mu.Unlock()
	s.box = runtime
	s.nodeInfo = nodeInfo
	*s.config.CertConfig = *cloneCertConfig(certConfig)
	s.state = state
	s.runtimeErr = runtimeErr
	s.lifecycleMu.Unlock()
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
