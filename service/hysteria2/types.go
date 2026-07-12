package hysteria2

import (
	"sync"
	"time"

	"github.com/apernet/hysteria/core/v2/server"
	log "github.com/sirupsen/logrus"
	"github.com/xtls/xray-core/common/task"
	"golang.org/x/time/rate"

	"github.com/Mtoly/XrayRP/api"
	"github.com/Mtoly/XrayRP/common/rule"
	"github.com/Mtoly/XrayRP/service/controller"
)

const onlineIPTTL = 2 * time.Minute

type runtimeServer interface {
	Serve() error
	Close() error
}

type serverConfigFactory func(*Hysteria2Service) (*server.Config, error)
type runtimeServerFactory func(*server.Config) (runtimeServer, error)
type serveRuntimeFunc func(runtimeServer) error
type closeRuntimeFunc func(runtimeServer) error

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
type serveHandshakeFunc func(start func(), started <-chan struct{}, result <-chan error) error

func defaultTaskFactory(tag string, interval time.Duration, execute func() error) lifecycleTask {
	return &task.Periodic{Interval: interval, Execute: execute}
}

// defaultServeHandshake only establishes that the Serve goroutine reached the
// call point. A Serve error not already buffered is recorded by the watcher.
func defaultServeHandshake(start func(), started <-chan struct{}, result <-chan error) error {
	start()
	<-started
	select {
	case err := <-result:
		return err
	default:
		return nil
	}
}

type Hysteria2Service struct {
	apiClient PanelClient
	config    *controller.Config

	clientInfo api.ClientInfo
	nodeInfo   *api.NodeInfo

	server               runtimeServer
	serverConfigFactory  serverConfigFactory
	runtimeServerFactory runtimeServerFactory
	serveRuntime         serveRuntimeFunc
	closeRuntime         closeRuntimeFunc
	taskFactory          taskFactory
	serveHandshake       serveHandshakeFunc

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
	users        map[string]userRecord           // uuid -> user
	traffic      map[string]*userTraffic         // uuid -> counters
	overLimit    map[string]bool                 // uuid -> over device limit
	onlineIPs    map[string]map[string]struct{}  // uuid -> set of IPs
	ipLastActive map[string]map[string]time.Time // uuid -> ip -> last active time
	blockedIDs   map[string]bool                 // connection id -> blocked by audit
	rateLimiters map[string]*rate.Limiter        // uuid -> per-user speed limiter

	// reloadMu serializes hot-reload operations (node / cert changes) so that
	// we never rebuild the underlying Hysteria2 server concurrently from
	// multiple goroutines (nodeMonitor, certMonitor, Start).
	reloadMu sync.Mutex

	// portHopRules keeps track of the iptables rules we added for Hysteria2
	// port hopping so that we can reliably remove or update them when the
	// panel configuration changes or the service stops.
	portHopRules []portHopRule
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

// portHopRule describes a single iptables REDIRECT rule for a contiguous
// destination port range. FromPortStart and FromPortEnd are inclusive. ToPort
// is the underlying Hysteria2 server port (offset_port_node) to which traffic
// is redirected.
type portHopRule struct {
	FromPortStart uint16
	FromPortEnd   uint16
	ToPort        uint16
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

func (t periodicTask) Close() error {
	if t.task == nil {
		return nil
	}
	return t.task.Close()
}
