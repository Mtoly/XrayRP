package tuic

import (
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

var _ service.Service = (*TuicService)(nil)

func defaultRuntimeFactory(s *TuicService, spec runtimeBuildSpec) (runtimeInstance, string, error) {
	return s.buildSingBoxFor(spec)
}

func defaultReloadRuntimeFactory(s *TuicService, spec runtimeBuildSpec) (runtimeInstance, string, error) {
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

func New(apiClient PanelClient, cfg *controller.Config) *TuicService {
	clientInfo := apiClient.Describe()
	logger := log.NewEntry(log.StandardLogger()).WithFields(log.Fields{
		"Host": clientInfo.APIHost,
		"ID":   clientInfo.NodeID,
	})
	return &TuicService{
		apiClient:            apiClient,
		config:               cfg,
		runtimeFactory:       defaultRuntimeFactory,
		reloadRuntimeFactory: defaultReloadRuntimeFactory,
		startRuntime:         defaultStartRuntime,
		closeRuntime:         defaultCloseRuntime,
		prepareRenewal:       defaultPrepareCertificateRenewal,
		taskFactory:          defaultTaskFactory,
		logger:               logger,
		rules:                rule.New(),
		users:                make(map[string]userRecord),
		traffic:              make(map[string]*userTraffic),
		onlineIPs:            make(map[string]map[string]struct{}),
		ipLastActive:         make(map[string]map[string]time.Time),
	}
}

func (s *TuicService) buildRuntime(spec runtimeBuildSpec) (runtimeInstance, string, error) {
	factory := s.runtimeFactory
	if factory == nil {
		factory = defaultRuntimeFactory
	}
	return factory(s, cloneRuntimeBuildSpec(spec))
}

func (s *TuicService) buildReloadRuntime(spec runtimeBuildSpec) (runtimeInstance, string, error) {
	if s.reloadRuntimeFactory == nil {
		return nil, "", errors.New("TUIC reload runtime factory is nil")
	}
	spec.authUsers = s.authUsersSnapshot()
	return s.reloadRuntimeFactory(s, cloneRuntimeBuildSpec(spec))
}

func (s *TuicService) appliedStateSnapshot() (*api.NodeInfo, string, time.Time) {
	s.lifecycleMu.Lock()
	defer s.lifecycleMu.Unlock()
	return s.nodeInfo, s.tag, s.startAt
}

func (s *TuicService) appliedTag() string {
	_, tag, _ := s.appliedStateSnapshot()
	return tag
}

func (s *TuicService) Start() (err error) {
	s.lifecycleMu.Lock()
	if s.closed {
		s.lifecycleMu.Unlock()
		return errors.New("TUIC service cannot start after close")
	}
	if s.state != stateStopped {
		state := s.state
		s.lifecycleMu.Unlock()
		return fmt.Errorf("TUIC service cannot start from state %d", state)
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
	if nodeInfo == nil || nodeInfo.NodeType != "Tuic" {
		return fail(fmt.Errorf("TuicService can only be used with Tuic node, got %v", nodeInfo))
	}
	if nodeInfo.Port == 0 {
		return fail(errors.New("server port must > 0"))
	}
	nodeInfo = cloneNodeInfo(nodeInfo)
	if s.config == nil || s.config.CertConfig == nil {
		return fail(errors.New("CertConfig is required for TUIC"))
	}
	if nodeInfo.TuicConfig == nil {
		nodeInfo.TuicConfig = &api.TuicConfig{}
	}

	tag := fmt.Sprintf("%s_%s_%d_%d", nodeInfo.NodeType, s.config.ListenIP, nodeInfo.Port, nodeInfo.NodeID)
	startAt := time.Now()

	userInfo, err := s.apiClient.GetUserList()
	if err != nil {
		return fail(err)
	}
	if userInfo == nil || len(*userInfo) == 0 {
		s.logger.Warn("No users found for TUIC node, authentication may fail")
	} else {
		s.logger.Infof("Syncing %d users for TUIC node", len(*userInfo))
	}

	startupUsers := s.buildCandidateUserState(userInfo, nodeInfo)
	boxInstance, inboundTag, err := s.buildRuntime(runtimeBuildSpec{
		nodeInfo:   nodeInfo,
		inboundTag: tag,
		certConfig: cloneCertConfig(s.config.CertConfig),
		authUsers:  append([]option.TUICUser(nil), startupUsers.authUsers...),
	})
	if err != nil {
		return fail(err)
	}

	closeRuntime := s.closeRuntime
	if closeRuntime == nil {
		closeRuntime = defaultCloseRuntime
	}
	startRuntime := s.startRuntime
	if startRuntime == nil {
		startRuntime = defaultStartRuntime
	}
	if err := startRuntime(boxInstance); err != nil {
		return fail(errors.Join(err, closeRuntime(boxInstance)))
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
		tasks.Add(factory("cert monitor", interval*60, s.certMonitorPeriodic))
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
	s.applyUserStateLocked(startupUsers)
	s.mu.Unlock()
	s.state = stateRunning
	s.runtimeErr = nil
	s.lifecycleMu.Unlock()

	if !s.config.DisableGetRule && s.rules != nil {
		if ruleList, ruleErr := s.apiClient.GetNodeRule(); ruleErr != nil {
			s.logger.Printf("Get rule list filed: %s", ruleErr)
		} else if ruleList != nil {
			if ruleErr := s.rules.UpdateRule(tag, *ruleList); ruleErr != nil {
				s.logger.Print(ruleErr)
			}
		}
	}

	s.logger.Infof("TUIC node started on %s:%d (sing-box %s)", s.config.ListenIP, nodeInfo.Port, getSingBoxVersion())
	return nil
}

func (s *TuicService) Close() error {
	s.lifecycleMu.Lock()
	if s.closed {
		s.lifecycleMu.Unlock()
		return nil
	}
	if s.state == stateStarting || s.state == stateReloading {
		s.lifecycleMu.Unlock()
		return errors.New("TUIC service cannot close while starting or reloading")
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
func (s *TuicService) reloadNode(nodeInfo *api.NodeInfo) error {
	if nodeInfo == nil {
		return nil
	}
	s.reloadMu.Lock()
	defer s.reloadMu.Unlock()
	return s.reloadNodeLocked(nodeInfo)
}

func (s *TuicService) reloadNodeLocked(nodeInfo *api.NodeInfo) error {
	return s.reloadNodeWithCertificateLocked(nodeInfo, nil)
}

func (s *TuicService) reloadNodeWithCertificateLocked(nodeInfo *api.NodeInfo, renewal preparedCertificateRenewal) (err error) {
	if renewal != nil {
		defer func() {
			err = errors.Join(err, renewal.Rollback())
		}()
	}
	if nodeInfo == nil {
		return nil
	}
	if nodeInfo.NodeType != "Tuic" {
		return fmt.Errorf("TuicService reloadNode: unexpected node type %s", nodeInfo.NodeType)
	}
	if nodeInfo.Port == 0 || nodeInfo.Port > 65535 {
		return fmt.Errorf("server port must be between 1 and 65535")
	}
	if s.config == nil || s.config.CertConfig == nil {
		return errors.New("CertConfig is required for TUIC")
	}
	if renewal != nil && (len(renewal.CertificatePEM()) == 0 || len(renewal.PrivateKeyPEM()) == 0) {
		return errors.New("prepared certificate renewal is missing certificate or private key PEM")
	}

	candidateNode := cloneNodeInfo(nodeInfo)
	if candidateNode.TuicConfig == nil {
		candidateNode.TuicConfig = &api.TuicConfig{}
	}
	s.lifecycleMu.Lock()
	expectedState := stateRunning
	if renewal != nil {
		expectedState = stateReloading
	}
	if s.closed || s.state != expectedState || s.box == nil || s.nodeInfo == nil {
		state := s.state
		s.lifecycleMu.Unlock()
		return fmt.Errorf("TUIC service cannot reload from state %d", state)
	}
	s.state = stateReloading
	oldRuntime := s.box
	oldNodeInfo := s.nodeInfo
	oldTag := s.tag
	oldInboundTag := s.inboundTag
	oldCertConfig := cloneCertConfig(s.config.CertConfig)
	s.lifecycleMu.Unlock()

	candidateCertConfig := deriveReloadCertConfig(oldCertConfig, oldNodeInfo, candidateNode)
	candidateRuntime, _, err := s.buildReloadRuntime(runtimeBuildSpec{
		nodeInfo:       candidateNode,
		inboundTag:     oldInboundTag,
		certConfig:     candidateCertConfig,
		certificatePEM: certificatePEM(renewal),
		privateKeyPEM:  privateKeyPEM(renewal),
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
	if startErr := startRuntime(candidateRuntime); startErr != nil {
		rollbackErr := rollbackCertificateRenewal(renewal)
		reloadErr := errors.Join(oldCloseErr, startErr, closeRuntime(candidateRuntime), rollbackErr)
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

	if renewal != nil {
		if commitErr := renewal.Commit(); commitErr != nil {
			reloadErr := errors.Join(oldCloseErr, commitErr, closeRuntime(candidateRuntime))
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
	}

	s.finishReload(candidateRuntime, candidateNode, oldTag, oldInboundTag, candidateCertConfig, stateRunning, nil)
	s.logger.Infof("TUIC node reloaded on %s:%d", s.config.ListenIP, candidateNode.Port)
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

func (s *TuicService) finishReload(runtime runtimeInstance, nodeInfo *api.NodeInfo, _, _ string, certConfig *mylego.CertConfig, state lifecycleState, runtimeErr error) {
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

func cloneNodeInfo(nodeInfo *api.NodeInfo) *api.NodeInfo {
	if nodeInfo == nil {
		return nil
	}
	cloned := *nodeInfo
	if nodeInfo.TuicConfig != nil {
		tuicConfig := *nodeInfo.TuicConfig
		tuicConfig.ALPN = append([]string(nil), nodeInfo.TuicConfig.ALPN...)
		cloned.TuicConfig = &tuicConfig
	}
	return &cloned
}

func cloneRuntimeBuildSpec(spec runtimeBuildSpec) runtimeBuildSpec {
	spec.nodeInfo = cloneNodeInfo(spec.nodeInfo)
	spec.certConfig = cloneCertConfig(spec.certConfig)
	spec.certificatePEM = append([]byte(nil), spec.certificatePEM...)
	spec.privateKeyPEM = append([]byte(nil), spec.privateKeyPEM...)
	spec.authUsers = append([]option.TUICUser(nil), spec.authUsers...)
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
