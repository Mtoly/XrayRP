package tuic

import (
	"sync"
	"time"

	"github.com/sagernet/sing-box/option"
	log "github.com/sirupsen/logrus"
	"golang.org/x/time/rate"

	"github.com/Mtoly/XrayRP/api"
	xcommon "github.com/Mtoly/XrayRP/common"
	"github.com/Mtoly/XrayRP/common/mylego"
	"github.com/Mtoly/XrayRP/common/rule"
	"github.com/Mtoly/XrayRP/service/controller"
	"github.com/Mtoly/XrayRP/service/internal/specialruntime"
)

type runtimeInstance interface {
	Start() error
	Close() error
}

type runtimeFactory func(*TuicService) (runtimeInstance, string, error)
type runtimeBuildSpec struct {
	nodeInfo   *api.NodeInfo
	inboundTag string
	certConfig *mylego.CertConfig
}
type reloadRuntimeFactory func(*TuicService, runtimeBuildSpec) (runtimeInstance, string, error)
type startRuntimeFunc func(runtimeInstance) error
type closeRuntimeFunc func(runtimeInstance) error
type renewCertificateFunc func(*mylego.CertConfig) (certPath, keyPath string, renewed bool, err error)

type lifecycleState uint8

const (
	stateStopped lifecycleState = iota
	stateStarting
	stateRunning
	stateReloading
	stateStopping
	stateFailed
)

type lifecycleTask interface {
	Start() error
	Close() error
}

type taskFactory func(tag string, interval time.Duration, execute func() error) lifecycleTask

func defaultTaskFactory(tag string, interval time.Duration, execute func() error) lifecycleTask {
	return &xcommon.ManagedPeriodic{Interval: interval, Execute: execute}
}

type TuicService struct {
	apiClient PanelClient
	config    *controller.Config

	clientInfo api.ClientInfo
	nodeInfo   *api.NodeInfo

	box                  runtimeInstance
	runtimeFactory       runtimeFactory
	reloadRuntimeFactory reloadRuntimeFactory
	startRuntime         startRuntimeFunc
	closeRuntime         closeRuntimeFunc
	renewCertificate     renewCertificateFunc
	taskFactory          taskFactory
	inboundTag           string

	lifecycleMu sync.Mutex
	state       lifecycleState
	runtimeErr  error
	closed      bool

	tag     string
	startAt time.Time
	tasks   *specialruntime.Tasks
	logger  *log.Entry

	rules *rule.Manager

	mu           sync.RWMutex
	users        map[string]userRecord           // authKey -> user
	traffic      map[string]*userTraffic         // authKey -> counters
	onlineIPs    map[string]map[string]struct{}  // authKey -> set of IPs
	ipLastActive map[string]map[string]time.Time // authKey -> ip -> last active time
	authUsers    []option.TUICUser               // users for sing-box TUIC authentication
	rateLimiters map[string]*rate.Limiter        // authKey -> per-user speed limiter

	// reloadMu prevents concurrent rebuilds of the underlying sing-box
	// instance when node configuration or certificates change.
	reloadMu sync.Mutex
}

type userRecord struct {
	UID         int
	Email       string
	DeviceLimit int
	SpeedLimit  uint64
}

type userTraffic struct {
	Upload   int64
	Download int64
}
