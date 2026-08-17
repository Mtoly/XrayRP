package controller

import (
	"context"
	"sync"
	"time"

	log "github.com/sirupsen/logrus"
	"github.com/xtls/xray-core/core"
	"github.com/xtls/xray-core/features/inbound"
	"github.com/xtls/xray-core/features/outbound"
	"github.com/xtls/xray-core/features/policy"
	"github.com/xtls/xray-core/features/stats"

	"github.com/Mtoly/XrayRP/api"
	"github.com/Mtoly/XrayRP/app/mydispatcher"
	"github.com/Mtoly/XrayRP/service"
)

type panelIdentityReader interface {
	Describe() api.ClientInfo
}

type panelSnapshotReader interface {
	GetNodeInfo() (*api.NodeInfo, error)
	GetUserList() (*[]api.UserInfo, error)
	GetNodeRule() (*[]api.DetectRule, error)
}

type panelReporter interface {
	ReportNodeStatus(*api.NodeStatus) error
	ReportNodeOnlineUsers(*[]api.OnlineUser) error
	ReportUserTraffic(*[]api.UserTraffic) error
	ReportIllegal(*[]api.DetectResult) error
}

type PanelClient interface {
	panelIdentityReader
	panelSnapshotReader
	panelReporter
}

type LimitInfo struct {
	end               int64
	currentSpeedLimit int
	originSpeedLimit  uint64
}

type Controller struct {
	server                         *core.Instance
	config                         *Config
	clientInfo                     api.ClientInfo
	apiClient                      PanelClient
	reloadMu                       sync.Mutex
	lifecycleMu                    sync.Mutex
	lifecycleState                 controllerLifecycleState
	lifecycleErr                   error
	ownedRuntime                   controllerRuntimeOwnership
	periodicMu                     sync.Mutex
	periodicJoinWG                 sync.WaitGroup
	periodicGeneration             uint64
	periodicAsyncErrs              []error
	periodicClosed                 bool
	periodicCloseDone              chan struct{}
	periodicCloseErr               error
	stateMu                        sync.RWMutex
	runtimeState                   nodeRuntimeState
	syncApplyHooks                 syncApplyHooks
	tasks                          []periodicTask
	limitedUsers                   map[api.UserInfo]LimitInfo
	warnedUsers                    map[api.UserInfo]int
	panelType                      string
	ibm                            inbound.Manager
	obm                            outbound.Manager
	stm                            stats.Manager
	pm                             policy.Manager
	dispatcher                     *mydispatcher.DefaultDispatcher
	startAt                        time.Time
	logger                         *log.Entry
	syncCoordinator                syncCoordinatorLifecycle
	wsRuntimeMu                    sync.RWMutex
	wsRuntime                      wsRuntimeLifecycle
	deviceReportState              *deviceReportState
	syncExecutionState             *syncExecutionState
	health                         service.RuntimeHealthState
	beforeUserMonitorLimiterUpdate func()
	prepareRenewal                 prepareCertificateRenewalFunc
	newPeriodicTask                periodicTaskFactory
	syncCoordinatorFactory         func(syncActionExecutor) syncCoordinatorLifecycle
	wsRuntimeFactory               func(context.Context, syncActionSubmitter) (wsRuntimeLifecycle, error)
}

type periodicTask = controllerPeriodicTask

// New return a Controller service with default parameters.
func New(server *core.Instance, apiClient PanelClient, config *Config, panelType string) *Controller {
	logger := log.NewEntry(log.StandardLogger()).WithFields(log.Fields{
		"Host": apiClient.Describe().APIHost,
		"Type": apiClient.Describe().NodeType,
		"ID":   apiClient.Describe().NodeID,
	})
	ibmRaw := server.GetFeature(inbound.ManagerType())
	ibmTyped, ok := ibmRaw.(inbound.Manager)
	if !ok {
		logger.Panicf("failed to get inbound.Manager feature, got %T", ibmRaw)
	}
	obmRaw := server.GetFeature(outbound.ManagerType())
	obmTyped, ok := obmRaw.(outbound.Manager)
	if !ok {
		logger.Panicf("failed to get outbound.Manager feature, got %T", obmRaw)
	}
	stmRaw := server.GetFeature(stats.ManagerType())
	stmTyped, ok := stmRaw.(stats.Manager)
	if !ok {
		logger.Panicf("failed to get stats.Manager feature, got %T", stmRaw)
	}
	pmRaw := server.GetFeature(policy.ManagerType())
	pmTyped, ok := pmRaw.(policy.Manager)
	if !ok {
		logger.Panicf("failed to get policy.Manager feature, got %T", pmRaw)
	}
	dispRaw := server.GetFeature(mydispatcher.Type())
	dispTyped, ok := dispRaw.(*mydispatcher.DefaultDispatcher)
	if !ok {
		logger.Panicf("failed to get mydispatcher.DefaultDispatcher feature, got %T", dispRaw)
	}

	controller := &Controller{
		server:     server,
		config:     config,
		apiClient:  apiClient,
		panelType:  panelType,
		ibm:        ibmTyped,
		obm:        obmTyped,
		stm:        stmTyped,
		pm:         pmTyped,
		dispatcher: dispTyped,
		startAt:    time.Now(),
		logger:     logger,
	}
	controller.deviceReportState = newDeviceReportState()
	controller.syncExecutionState = newSyncExecutionState()
	controller.prepareRenewal = defaultControllerPrepareCertificateRenewal
	controller.syncCoordinatorFactory = func(executor syncActionExecutor) syncCoordinatorLifecycle {
		return newSyncCoordinatorWithResultHandling(executor, controller.syncExecutionState, controller.logSyncExecutionResult)
	}
	controller.wsRuntimeFactory = controller.newConfiguredWSRuntimeContext

	return controller
}

// func (c *Controller) logPrefix() string {
// 	return fmt.Sprintf("[%s] %s(ID=%d)", c.clientInfo.APIHost, c.nodeInfo.NodeType, c.nodeInfo.NodeID)
// }
