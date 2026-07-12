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

var _ service.Service = (*Hysteria2Service)(nil)

func defaultServerConfigFactory(h *Hysteria2Service) (*server.Config, error) {
	return h.buildServerConfig()
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
	serveResult := make(chan error, 1)
	serveCallDone := make(chan struct{})
	serveStarted := make(chan struct{})
	startServe := func() {
		go func() {
			defer close(serveCallDone)
			close(serveStarted)
			serveResult <- serveRuntime(srv)
		}()
	}
	handshake := h.serveHandshake
	if handshake == nil {
		handshake = defaultServeHandshake
	}
	if err := handshake(startServe, serveStarted, serveResult); err != nil {
		cleanupErr := closeRuntime(srv)
		<-serveCallDone
		return fail(errors.Join(err, cleanupErr))
	}

	factory := h.taskFactory
	if factory == nil {
		factory = defaultTaskFactory
	}
	interval := time.Duration(h.config.UpdatePeriodic) * time.Second
	tasks := []periodicTask{
		{tag: tag, task: factory(tag, interval, h.userMonitor)},
		{tag: "node monitor", task: factory("node monitor", interval, h.nodeMonitor)},
	}
	if nodeInfo.EnableTLS {
		tasks = append(tasks, periodicTask{
			tag:  "cert monitor",
			task: factory("cert monitor", interval*60, h.certMonitor),
		})
	}
	for i := range tasks {
		if err := tasks[i].Start(); err != nil {
			var cleanupErrs []error
			cleanupErrs = append(cleanupErrs, err)
			for j := i; j >= 0; j-- {
				cleanupErrs = append(cleanupErrs, tasks[j].Stop())
			}
			cleanupErrs = append(cleanupErrs, closeRuntime(srv))
			<-serveCallDone
			for j := i; j >= 0; j-- {
				cleanupErrs = append(cleanupErrs, tasks[j].Wait())
			}
			return fail(errors.Join(cleanupErrs...))
		}
	}

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
	h.lifecycleMu.Unlock()

	h.reloadMu.Lock()
	h.updatePortHopRulesLocked()
	h.reloadMu.Unlock()

	h.lifecycleMu.Lock()
	h.state = stateRunning
	h.runtimeErr = nil
	h.serveDone = serveCallDone
	watcherDone := make(chan struct{})
	h.watcherDone = watcherDone
	h.lifecycleMu.Unlock()

	if !h.config.DisableGetRule && h.rules != nil {
		if ruleList, ruleErr := h.apiClient.GetNodeRule(); ruleErr != nil {
			h.logger.Printf("Get rule list filed: %s", ruleErr)
		} else if ruleList != nil && len(*ruleList) > 0 {
			if ruleErr := h.rules.UpdateRule(tag, *ruleList); ruleErr != nil {
				h.logger.Print(ruleErr)
			}
		}
	}

	go func() {
		defer close(watcherDone)
		serveErr := <-serveResult
		h.lifecycleMu.Lock()
		running := h.state == stateRunning
		if running {
			h.state = stateFailed
			h.runtimeErr = serveErr
		}
		h.lifecycleMu.Unlock()
		if running && serveErr != nil && h.logger != nil {
			h.logger.Errorf("Hysteria2 Serve error: %v", serveErr)
		}
	}()

	h.logger.Infof("Hysteria2 node started on %s:%d (hysteria core %s)", h.config.ListenIP, nodeInfo.Port, getHysteriaCoreVersion())
	return nil
}

// Close implements service.Service.Close.
func (h *Hysteria2Service) Close() error {
	h.lifecycleMu.Lock()
	if h.closed {
		h.lifecycleMu.Unlock()
		return nil
	}
	if h.state == stateStarting {
		h.lifecycleMu.Unlock()
		return errors.New("Hysteria2 service cannot close while starting")
	}
	h.closed = true
	h.state = stateStopping
	tasks := h.tasks
	srv := h.server
	serveDone := h.serveDone
	watcherDone := h.watcherDone
	h.lifecycleMu.Unlock()

	var errs []error
	for i := len(tasks) - 1; i >= 0; i-- {
		errs = append(errs, tasks[i].Stop())
	}
	if srv != nil {
		closeRuntime := h.closeRuntime
		if closeRuntime == nil {
			closeRuntime = defaultCloseRuntime
		}
		errs = append(errs, closeRuntime(srv))
	}
	for i := len(tasks) - 1; i >= 0; i-- {
		errs = append(errs, tasks[i].Wait())
	}
	if srv != nil && serveDone != nil {
		<-serveDone
		if watcherDone != nil {
			<-watcherDone
		}
	}

	h.reloadMu.Lock()
	if len(h.portHopRules) > 0 {
		deletePortHopRules(h.portHopRules, h.logger)
		h.portHopRules = nil
	}
	h.reloadMu.Unlock()

	h.lifecycleMu.Lock()
	h.tasks = nil
	h.server = nil
	h.serveDone = nil
	h.watcherDone = nil
	h.runtimeErr = nil
	h.state = stateStopped
	h.lifecycleMu.Unlock()
	return errors.Join(errs...)
}

// reloadNode replaces the in-memory node information and rebuilds the
// underlying Hysteria2 server so that changes from the panel (port, TLS,
// SNI, bandwidth, etc.) or renewed certificates take effect without
// restarting the whole XrayR process.
func (h *Hysteria2Service) reloadNode(nodeInfo *api.NodeInfo) error {
	if nodeInfo == nil {
		return nil
	}
	if nodeInfo.NodeType != "Hysteria2" {
		return fmt.Errorf("Hysteria2Service reloadNode: unexpected node type %s", nodeInfo.NodeType)
	}
	if nodeInfo.Port == 0 {
		return errors.New("server port must > 0")
	}
	if nodeInfo.Hysteria2Config == nil {
		return errors.New("Hysteria2Config is nil in node info")
	}
	if h.config == nil || h.config.CertConfig == nil {
		return errors.New("CertConfig is required for Hysteria2")
	}

	h.reloadMu.Lock()
	defer h.reloadMu.Unlock()

	oldInfo := h.nodeInfo
	h.nodeInfo = nodeInfo

	// Update port hopping iptables rules according to the latest node
	// configuration before we rebuild the underlying Hysteria2 server.
	h.updatePortHopRulesLocked()

	// Keep CertDomain in sync with the panel SNI when it was originally
	// derived from SNI/Host. If the user configured a custom CertDomain,
	// we respect it and do not override.
	if h.config.CertConfig != nil && h.nodeInfo.EnableTLS && !h.nodeInfo.EnableREALITY {
		sni := h.nodeInfo.SNI
		if sni == "" {
			sni = h.nodeInfo.Host
		}
		if sni != "" {
			cert := h.config.CertConfig
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

	if h.server != nil {
		closeRuntime := h.closeRuntime
		if closeRuntime == nil {
			closeRuntime = defaultCloseRuntime
		}
		if err := closeRuntime(h.server); err != nil {
			h.logger.Printf("Hysteria2 reload: failed to close old server: %v", err)
		}
		h.server = nil
	}

	srv, err := h.buildRuntimeServer()
	if err != nil {
		return err
	}
	h.server = srv

	serveRuntime := h.serveRuntime
	if serveRuntime == nil {
		serveRuntime = defaultServeRuntime
	}
	go func(runtime runtimeServer) {
		if err := serveRuntime(runtime); err != nil {
			h.logger.Errorf("Hysteria2 Serve error after reload: %v", err)
		}
	}(srv)

	h.logger.Infof("Hysteria2 node reloaded on %s:%d", h.config.ListenIP, h.nodeInfo.Port)
	return nil
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
