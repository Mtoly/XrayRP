package anytls

import (
	"sync"
	"time"

	"github.com/sagernet/sing-box/option"
	log "github.com/sirupsen/logrus"
	"github.com/xtls/xray-core/common/task"
	"golang.org/x/time/rate"

	"github.com/Mtoly/XrayRP/api"
	"github.com/Mtoly/XrayRP/common/rule"
	"github.com/Mtoly/XrayRP/service/controller"
)

type runtimeInstance interface {
	Start() error
	Close() error
}

type runtimeFactory func(*AnyTLSService) (runtimeInstance, string, error)
type startRuntimeFunc func(runtimeInstance) error
type closeRuntimeFunc func(runtimeInstance) error

type AnyTLSService struct {
	apiClient PanelClient
	config    *controller.Config

	clientInfo api.ClientInfo
	nodeInfo   *api.NodeInfo

	box            runtimeInstance
	runtimeFactory runtimeFactory
	startRuntime   startRuntimeFunc
	closeRuntime   closeRuntimeFunc
	inboundTag     string

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
	authUsers    []option.AnyTLSUser             // users for sing-anytls authentication
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
	tag string
	*task.Periodic
}
