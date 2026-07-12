package anytls

import (
	"errors"
	"fmt"
	"runtime/debug"
	"time"

	log "github.com/sirupsen/logrus"
	"golang.org/x/time/rate"

	"github.com/Mtoly/XrayRP/api"
	"github.com/Mtoly/XrayRP/common/rule"
	"github.com/Mtoly/XrayRP/service"
	"github.com/Mtoly/XrayRP/service/controller"
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

func defaultStartRuntime(runtime runtimeInstance) error {
	return runtime.Start()
}

func defaultCloseRuntime(runtime runtimeInstance) error {
	return runtime.Close()
}

func New(apiClient PanelClient, cfg *controller.Config) *AnyTLSService {
	clientInfo := apiClient.Describe()
	logger := log.NewEntry(log.StandardLogger()).WithFields(log.Fields{
		"Host": clientInfo.APIHost,
		"ID":   clientInfo.NodeID,
	})
	return &AnyTLSService{
		apiClient:      apiClient,
		config:         cfg,
		runtimeFactory: defaultRuntimeFactory,
		startRuntime:   defaultStartRuntime,
		closeRuntime:   defaultCloseRuntime,
		taskFactory:    defaultTaskFactory,
		logger:         logger,
		rules:          rule.New(),
		users:          make(map[string]userRecord),
		traffic:        make(map[string]*userTraffic),
		onlineIPs:      make(map[string]map[string]struct{}),
		ipLastActive:   make(map[string]map[string]time.Time),
	}
}

func (s *AnyTLSService) buildRuntime() (runtimeInstance, string, error) {
	factory := s.runtimeFactory
	if factory == nil {
		factory = defaultRuntimeFactory
	}
	return factory(s)
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
	tasks := []periodicTask{
		{tag: tag, task: factory(tag, interval, s.userMonitor)},
		{tag: "node monitor", task: factory("node monitor", interval, s.nodeMonitor)},
	}
	if nodeInfo.EnableTLS {
		tasks = append(tasks, periodicTask{
			tag:  "cert monitor",
			task: factory("cert monitor", interval*60, s.certMonitor),
		})
	}

	for i := range tasks {
		if err := tasks[i].Start(); err != nil {
			cleanupErrs := []error{err}
			for j := i; j >= 0; j-- {
				cleanupErrs = append(cleanupErrs, tasks[j].Close())
			}
			cleanupErrs = append(cleanupErrs, closeRuntime(boxInstance))
			return fail(errors.Join(cleanupErrs...))
		}
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
	if s.state == stateStarting {
		s.lifecycleMu.Unlock()
		return errors.New("AnyTLS service cannot close while starting")
	}
	s.closed = true
	s.state = stateStopping
	tasks := s.tasks
	boxInstance := s.box
	s.lifecycleMu.Unlock()

	var errs []error
	for i := len(tasks) - 1; i >= 0; i-- {
		errs = append(errs, tasks[i].Close())
	}
	if boxInstance != nil {
		closeRuntime := s.closeRuntime
		if closeRuntime == nil {
			closeRuntime = defaultCloseRuntime
		}
		errs = append(errs, closeRuntime(boxInstance))
	}

	s.lifecycleMu.Lock()
	s.tasks = nil
	s.box = nil
	s.state = stateStopped
	s.lifecycleMu.Unlock()
	return errors.Join(errs...)
}

// reloadNode replaces in-memory node information and rebuilds the underlying
// sing-box AnyTLS instance so that changes from the panel (port, TLS/SNI,
// padding options, etc.) and renewed certificates take effect without
// restarting the whole XrayR process.
func (s *AnyTLSService) reloadNode(nodeInfo *api.NodeInfo) error {
	if nodeInfo == nil {
		return nil
	}
	if nodeInfo.NodeType != "AnyTLS" {
		return fmt.Errorf("AnyTLSService reloadNode: unexpected node type %s", nodeInfo.NodeType)
	}
	if nodeInfo.Port == 0 {
		return errors.New("server port must > 0")
	}
	if s.config == nil || s.config.CertConfig == nil {
		return errors.New("CertConfig is required for AnyTLS")
	}
	if nodeInfo.AnyTLSConfig == nil {
		nodeInfo.AnyTLSConfig = &api.AnyTLSConfig{}
	}

	s.reloadMu.Lock()
	defer s.reloadMu.Unlock()

	oldInfo := s.nodeInfo
	s.nodeInfo = nodeInfo

	// Keep CertDomain in sync with the panel SNI when originally derived from
	// SNI/Host.
	if s.config.CertConfig != nil && s.nodeInfo.EnableTLS && !s.nodeInfo.EnableREALITY {
		sni := s.nodeInfo.SNI
		if sni == "" {
			sni = s.nodeInfo.Host
		}
		if sni != "" {
			cert := s.config.CertConfig
			var oldSNI, oldHost string
			if oldInfo != nil {
				oldSNI = oldInfo.SNI
				oldHost = oldInfo.Host
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
		}
	}

	if s.box != nil {
		closeRuntime := s.closeRuntime
		if closeRuntime == nil {
			closeRuntime = defaultCloseRuntime
		}
		if err := closeRuntime(s.box); err != nil {
			s.logger.Printf("AnyTLS reload: failed to close old box: %v", err)
		}
		s.box = nil
	}

	boxInstance, inboundTag, err := s.buildRuntime()
	if err != nil {
		return err
	}
	s.box = boxInstance
	s.inboundTag = inboundTag

	startRuntime := s.startRuntime
	if startRuntime == nil {
		startRuntime = defaultStartRuntime
	}
	go func(runtime runtimeInstance) {
		if err := startRuntime(runtime); err != nil {
			s.logger.Errorf("AnyTLS box start error after reload: %v", err)
		}
	}(boxInstance)

	s.logger.Infof("AnyTLS node reloaded on %s:%d", s.config.ListenIP, s.nodeInfo.Port)
	return nil
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
