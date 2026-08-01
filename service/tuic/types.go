package tuic

import (
	"context"
	"sync"
	"time"

	"github.com/sagernet/sing-box/option"
	log "github.com/sirupsen/logrus"
	"golang.org/x/time/rate"

	"github.com/Mtoly/XrayRP/api"
	"github.com/Mtoly/XrayRP/common/mylego"
	"github.com/Mtoly/XrayRP/common/rule"
	"github.com/Mtoly/XrayRP/internal/operation"
	"github.com/Mtoly/XrayRP/service"
	"github.com/Mtoly/XrayRP/service/controller"
	"github.com/Mtoly/XrayRP/service/internal/specialruntime"
)

type runtimeInstance interface {
	Start() error
	Close() error
}

type runtimeFactory func(*TuicService, runtimeBuildSpec) (runtimeInstance, string, error)
type runtimeBuildSpec struct {
	nodeInfo       *api.NodeInfo
	inboundTag     string
	certConfig     *mylego.CertConfig
	certificatePEM []byte
	privateKeyPEM  []byte
	authUsers      []option.TUICUser
}
type reloadRuntimeFactory func(*TuicService, runtimeBuildSpec) (runtimeInstance, string, error)
type startRuntimeFunc func(runtimeInstance) error
type closeRuntimeFunc func(runtimeInstance) error

type preparedCertificateRenewal interface {
	Renewed() bool
	CertificatePEM() []byte
	PrivateKeyPEM() []byte
	Commit() error
	Rollback() error
}

type prepareCertificateRenewalFunc func(*mylego.CertConfig) (preparedCertificateRenewal, error)

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
	return specialruntime.NewPeriodic(interval, execute)
}

func (s *TuicService) newTask(tag string, interval time.Duration, execute func(context.Context) error) lifecycleTask {
	if s.taskFactory != nil {
		return s.taskFactory(tag, interval, func() error {
			ctx, cancel := service.WithDefaultTimeout(context.Background(), service.DefaultSyncTimeout)
			defer cancel()
			return execute(ctx)
		})
	}
	return specialruntime.NewPeriodicContext(interval, execute)
}

type TuicService struct {
	apiClient PanelClient
	config    *controller.Config

	clientInfo api.ClientInfo
	nodeInfo   *api.NodeInfo

	box                        runtimeInstance
	cleanupRuntimes            []runtimeInstance
	runtimeFactory             runtimeFactory
	reloadRuntimeFactory       reloadRuntimeFactory
	startRuntime               startRuntimeFunc
	closeRuntime               closeRuntimeFunc
	prepareRenewal             prepareCertificateRenewalFunc
	beforeCertificateStateRead func()
	taskFactory                taskFactory
	inboundTag                 string

	lifecycleMu sync.Mutex
	state       lifecycleState
	runtimeErr  error
	closed      bool
	health      service.RuntimeHealthState

	tag             string
	startAt         time.Time
	tasks           *specialruntime.Tasks
	syncCoordinator *specialruntime.SnapshotSyncCoordinator
	logger          *log.Entry

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
	reloadMu operation.Gate
}

type userRecord struct {
	UID         int
	Email       string
	DeviceLimit int
	SpeedLimit  uint64
}

type userState struct {
	users        map[string]userRecord
	traffic      map[string]*userTraffic
	onlineIPs    map[string]map[string]struct{}
	ipLastActive map[string]map[string]time.Time
	authUsers    []option.TUICUser
	rateLimiters map[string]*rate.Limiter
}

type userTraffic struct {
	Upload   int64
	Download int64
}
