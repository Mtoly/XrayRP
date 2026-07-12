package tuic

import (
	"errors"
	"sync"
	"time"

	"github.com/sagernet/sing-box/option"
	log "github.com/sirupsen/logrus"
	"golang.org/x/time/rate"

	"github.com/Mtoly/XrayRP/api"
	xcommon "github.com/Mtoly/XrayRP/common"
	"github.com/Mtoly/XrayRP/common/rule"
	"github.com/Mtoly/XrayRP/service/controller"
)

type runtimeInstance interface {
	Start() error
	Close() error
}

type runtimeFactory func(*TuicService) (runtimeInstance, string, error)
type startRuntimeFunc func(runtimeInstance) error
type closeRuntimeFunc func(runtimeInstance) error

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

	box            runtimeInstance
	runtimeFactory runtimeFactory
	startRuntime   startRuntimeFunc
	closeRuntime   closeRuntimeFunc
	taskFactory    taskFactory
	inboundTag     string

	lifecycleMu sync.Mutex
	state       lifecycleState
	runtimeErr  error
	closed      bool

	tag     string
	startAt time.Time
	tasks   []periodicTask
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

type periodicTask struct {
	tag  string
	task lifecycleTask
}

func (t periodicTask) Start() error {
	if t.task == nil {
		return nil
	}
	return t.task.Start()
}

func (t periodicTask) Stop() error {
	if t.task == nil {
		return nil
	}
	if managed, ok := t.task.(interface{ Stop() error }); ok {
		return managed.Stop()
	}
	return t.task.Close()
}

func (t periodicTask) Wait() error {
	if t.task == nil {
		return nil
	}
	if managed, ok := t.task.(interface{ Wait() error }); ok {
		return managed.Wait()
	}
	return nil
}

func (t periodicTask) Close() error {
	return errors.Join(t.Stop(), t.Wait())
}
