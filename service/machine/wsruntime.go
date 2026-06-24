package machine

import (
	"context"
	"encoding/json"
	"errors"
	"math"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/Mtoly/XrayRP/api"
	"github.com/Mtoly/XrayRP/api/newV2board"
	"github.com/Mtoly/XrayRP/service/controller"
	log "github.com/sirupsen/logrus"
)

type SharedWSRuntimeConfig struct {
	Endpoint          string
	ReconnectBackoff  time.Duration
	HeartbeatInterval time.Duration
	ResyncOnReconnect bool
	Logger            *log.Entry
}

type sharedWSClient interface {
	Events() <-chan *newV2board.WSEvent
	Errors() <-chan error
	Done() <-chan struct{}
	KeepAlive() error
	Pong() error
	SendDeviceReport(map[int][]string) error
	SendNodeDeviceReport(int, map[int][]string) error
	SendNodeStatusReport(int, *api.NodeStatus) error
	Close() error
}

type sharedWSClientFactory func(context.Context) (sharedWSClient, error)

var maxIntValue = int64(^uint(0) >> 1)

type SharedWSRuntime struct {
	config     SharedWSRuntimeConfig
	factory    sharedWSClientFactory
	rediscover func() error
	sleep      func(context.Context, time.Duration) bool

	mu        sync.RWMutex
	started   bool
	cancel    context.CancelFunc
	done      chan struct{}
	client    sharedWSClient
	mailboxes map[int]*SharedWSMailbox
}

func NewSharedWSRuntime(config SharedWSRuntimeConfig) *SharedWSRuntime {
	if config.ReconnectBackoff < 0 {
		config.ReconnectBackoff = 0
	}
	if config.HeartbeatInterval < 0 {
		config.HeartbeatInterval = 0
	}

	runtime := &SharedWSRuntime{
		config:    config,
		sleep:     sleepWithContext,
		done:      make(chan struct{}),
		mailboxes: make(map[int]*SharedWSMailbox),
	}
	runtime.factory = func(ctx context.Context) (sharedWSClient, error) {
		return newV2board.NewWSClientContext(ctx, config.Endpoint)
	}
	return runtime
}

func (r *SharedWSRuntime) SetRediscover(rediscover func() error) {
	r.mu.Lock()
	r.rediscover = rediscover
	r.mu.Unlock()
}

func (r *SharedWSRuntime) NewNodeRuntimeFactory(nodeID int) controller.WSEventRuntimeFactory {
	return func(submitter controller.WSEventSubmitter) (controller.WSRuntimeLifecycle, error) {
		if nodeID <= 0 {
			return nil, errors.New("machine websocket mailbox node ID must be greater than 0")
		}
		if submitter == nil {
			return nil, errors.New("machine websocket mailbox submitter must not be nil")
		}
		return &SharedWSMailbox{
			runtime:   r,
			nodeID:    nodeID,
			submitter: submitter,
		}, nil
	}
}

func (r *SharedWSRuntime) Start() error {
	r.mu.Lock()
	if r.started {
		r.mu.Unlock()
		return nil
	}
	if r.done == nil || doneClosed(r.done) {
		r.done = make(chan struct{})
	}

	ctx, cancel := context.WithCancel(context.Background())
	done := r.done
	r.started = true
	r.cancel = cancel
	r.client = nil
	r.mu.Unlock()

	go r.run(ctx, done)
	return nil
}

func (r *SharedWSRuntime) Close() error {
	r.mu.RLock()
	if !r.started {
		r.mu.RUnlock()
		return nil
	}
	cancel := r.cancel
	client := r.client
	done := r.done
	r.mu.RUnlock()

	if cancel != nil {
		cancel()
	}
	if client != nil {
		_ = client.Close()
	}
	if done != nil {
		<-done
	}
	return nil
}

func (r *SharedWSRuntime) DeviceReporterReady() bool {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return r.client != nil
}

func (r *SharedWSRuntime) ReportNodeDevices(nodeID int, devices map[int][]string) error {
	r.mu.RLock()
	client := r.client
	r.mu.RUnlock()
	if client == nil {
		return nil
	}
	return client.SendNodeDeviceReport(nodeID, devices)
}

func (r *SharedWSRuntime) ReportNodeStatus(nodeID int, nodeStatus *api.NodeStatus) error {
	r.mu.RLock()
	client := r.client
	r.mu.RUnlock()
	if client == nil {
		return nil
	}
	return client.SendNodeStatusReport(nodeID, nodeStatus)
}

func (r *SharedWSRuntime) run(ctx context.Context, done chan struct{}) {
	defer func() {
		r.mu.Lock()
		if r.done == done {
			close(done)
			r.started = false
			r.cancel = nil
			r.client = nil
		}
		r.mu.Unlock()
	}()

	needsResyncOnConnect := false
	for {
		client, err := r.connect(ctx)
		if err != nil {
			if ctx.Err() != nil {
				return
			}
			needsResyncOnConnect = true
			if !r.sleep(ctx, r.config.ReconnectBackoff) {
				return
			}
			continue
		}

		r.setClient(client)
		if needsResyncOnConnect {
			r.broadcastReconnect()
			needsResyncOnConnect = false
		}

		disconnected := r.consumeClient(ctx, client)
		r.clearClient(client)
		_ = client.Close()

		if ctx.Err() != nil || !disconnected {
			return
		}

		r.broadcastDisconnect()
		needsResyncOnConnect = true
		if !r.sleep(ctx, r.config.ReconnectBackoff) {
			return
		}
	}
}

func (r *SharedWSRuntime) connect(ctx context.Context) (sharedWSClient, error) {
	client, err := r.factory(ctx)
	if err != nil {
		return nil, err
	}
	if client == nil {
		return nil, errors.New("machine websocket factory returned nil client")
	}
	return client, nil
}

func (r *SharedWSRuntime) consumeClient(ctx context.Context, client sharedWSClient) bool {
	var heartbeat <-chan time.Time
	var ticker *time.Ticker
	if r.config.HeartbeatInterval > 0 {
		ticker = time.NewTicker(r.config.HeartbeatInterval)
		heartbeat = ticker.C
		defer ticker.Stop()
	}

	for {
		select {
		case <-ctx.Done():
			return false
		case <-heartbeat:
			if err := client.KeepAlive(); err != nil {
				return true
			}
		case event, ok := <-client.Events():
			if !ok {
				return true
			}
			r.handleEvent(client, event)
		case err, ok := <-client.Errors():
			if !ok {
				return true
			}
			if r.handleError(err) {
				continue
			}
			return true
		case <-client.Done():
			return true
		}
	}
}

func (r *SharedWSRuntime) handleEvent(client sharedWSClient, event *newV2board.WSEvent) {
	if event == nil {
		return
	}

	switch event.Event {
	case newV2board.WSEventPing:
		if client != nil {
			_ = client.Pong()
		}
		return
	case newV2board.WSEventPong,
		newV2board.WSEventXboardAuthSuccess,
		newV2board.WSEventXboardError:
		return
	case newV2board.WSEventXboardSyncNodes:
		r.triggerRediscover()
		return
	}

	nodeID, ok := nodeIDFromWSEvent(event)
	if !ok {
		return
	}
	if mailbox := r.mailbox(nodeID); mailbox != nil {
		mailbox.deliver(event)
	}
}

func (r *SharedWSRuntime) handleError(err error) bool {
	if err == nil {
		return true
	}
	if errors.Is(err, newV2board.ErrWSClientParse) {
		r.broadcastParseError()
		return true
	}
	return false
}

func (r *SharedWSRuntime) triggerRediscover() {
	r.mu.RLock()
	rediscover := r.rediscover
	r.mu.RUnlock()
	if rediscover == nil {
		return
	}

	go func() {
		if err := rediscover(); err != nil && r.config.Logger != nil {
			r.config.Logger.Warn(err)
		}
	}()
}

func (r *SharedWSRuntime) registerMailbox(mailbox *SharedWSMailbox) {
	if mailbox == nil {
		return
	}
	r.mu.Lock()
	r.mailboxes[mailbox.nodeID] = mailbox
	r.mu.Unlock()
}

func (r *SharedWSRuntime) unregisterMailbox(mailbox *SharedWSMailbox) {
	if mailbox == nil {
		return
	}
	r.mu.Lock()
	if r.mailboxes[mailbox.nodeID] == mailbox {
		delete(r.mailboxes, mailbox.nodeID)
	}
	r.mu.Unlock()
}

func (r *SharedWSRuntime) mailbox(nodeID int) *SharedWSMailbox {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return r.mailboxes[nodeID]
}

func (r *SharedWSRuntime) broadcastParseError() {
	for _, mailbox := range r.mailboxSnapshot() {
		mailbox.submitParseError()
	}
}

func (r *SharedWSRuntime) broadcastDisconnect() {
	for _, mailbox := range r.mailboxSnapshot() {
		mailbox.submitDisconnect()
	}
}

func (r *SharedWSRuntime) broadcastReconnect() {
	if !r.config.ResyncOnReconnect {
		return
	}
	for _, mailbox := range r.mailboxSnapshot() {
		mailbox.submitReconnect()
	}
}

func (r *SharedWSRuntime) mailboxSnapshot() []*SharedWSMailbox {
	r.mu.RLock()
	defer r.mu.RUnlock()
	mailboxes := make([]*SharedWSMailbox, 0, len(r.mailboxes))
	for _, mailbox := range r.mailboxes {
		mailboxes = append(mailboxes, mailbox)
	}
	return mailboxes
}

func (r *SharedWSRuntime) setClient(client sharedWSClient) {
	r.mu.Lock()
	r.client = client
	r.mu.Unlock()
}

func (r *SharedWSRuntime) clearClient(client sharedWSClient) {
	r.mu.Lock()
	if r.client == client {
		r.client = nil
	}
	r.mu.Unlock()
}

type SharedWSMailbox struct {
	runtime   *SharedWSRuntime
	nodeID    int
	submitter controller.WSEventSubmitter

	mu      sync.RWMutex
	started bool
}

func (m *SharedWSMailbox) Start() {
	m.mu.Lock()
	if m.started {
		m.mu.Unlock()
		return
	}
	m.started = true
	m.mu.Unlock()

	if m.runtime != nil {
		m.runtime.registerMailbox(m)
	}
}

func (m *SharedWSMailbox) Stop() {
	if m.runtime != nil {
		m.runtime.unregisterMailbox(m)
	}

	m.mu.Lock()
	m.started = false
	m.mu.Unlock()
}

func (m *SharedWSMailbox) deliver(event *newV2board.WSEvent) {
	submitter, ok := m.currentSubmitter()
	if !ok {
		return
	}
	submitter.SubmitWSEvent(event)
}

func (m *SharedWSMailbox) submitParseError() {
	submitter, ok := m.currentSubmitter()
	if !ok {
		return
	}
	submitter.SubmitWSParseError()
}

func (m *SharedWSMailbox) submitDisconnect() {
	submitter, ok := m.currentSubmitter()
	if !ok {
		return
	}
	submitter.SubmitWSDisconnect()
}

func (m *SharedWSMailbox) submitReconnect() {
	submitter, ok := m.currentSubmitter()
	if !ok {
		return
	}
	submitter.SubmitWSReconnect()
}

func (m *SharedWSMailbox) currentSubmitter() (controller.WSEventSubmitter, bool) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.submitter, m.started && m.submitter != nil
}

func nodeIDFromWSEvent(event *newV2board.WSEvent) (int, bool) {
	if event == nil || event.Payload == nil {
		return 0, false
	}
	return nodeIDFromValue(event.Payload["node_id"])
}

func nodeIDFromValue(value any) (int, bool) {
	switch typed := value.(type) {
	case int:
		return positiveNodeID(typed)
	case int64:
		if typed > maxIntValue {
			return 0, false
		}
		return positiveNodeID(int(typed))
	case float64:
		if typed <= 0 || math.Trunc(typed) != typed || typed > float64(maxIntValue) {
			return 0, false
		}
		return int(typed), true
	case json.Number:
		nodeID, err := typed.Int64()
		if err != nil || nodeID > maxIntValue {
			return 0, false
		}
		return positiveNodeID(int(nodeID))
	case string:
		nodeID, err := strconv.Atoi(strings.TrimSpace(typed))
		if err != nil {
			return 0, false
		}
		return positiveNodeID(nodeID)
	default:
		return 0, false
	}
}

func positiveNodeID(nodeID int) (int, bool) {
	if nodeID <= 0 {
		return 0, false
	}
	return nodeID, true
}

func doneClosed(done <-chan struct{}) bool {
	select {
	case <-done:
		return true
	default:
		return false
	}
}

func sleepWithContext(ctx context.Context, d time.Duration) bool {
	if d <= 0 {
		select {
		case <-ctx.Done():
			return false
		default:
			return true
		}
	}

	timer := time.NewTimer(d)
	defer timer.Stop()

	select {
	case <-ctx.Done():
		return false
	case <-timer.C:
		return true
	}
}
