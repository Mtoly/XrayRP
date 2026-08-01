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
	"github.com/Mtoly/XrayRP/service"
	"github.com/Mtoly/XrayRP/service/controller"
	"github.com/Mtoly/XrayRP/service/internal/wslifecycle"
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
	lifecycle  *wslifecycle.Runtime
	rediscover func(context.Context) error

	lifecycleMu sync.Mutex
	closed      bool

	mu               sync.RWMutex
	mailboxes        map[int]*SharedWSMailbox
	degraded         bool
	lastFailureAt    time.Time
	rediscoverSignal chan struct{}
	rediscoverActive bool
	rediscoverCancel context.CancelFunc
	rediscoverDone   chan struct{}
}

func NewSharedWSRuntime(config SharedWSRuntimeConfig) *SharedWSRuntime {
	runtime := &SharedWSRuntime{
		config:           config,
		mailboxes:        make(map[int]*SharedWSMailbox),
		rediscoverSignal: make(chan struct{}, 1),
	}
	runtime.factory = func(ctx context.Context) (sharedWSClient, error) {
		return newV2board.NewWSClientContext(ctx, config.Endpoint)
	}
	runtime.lifecycle = wslifecycle.New(wslifecycle.Config{
		Factory: func(ctx context.Context) (wslifecycle.Client, error) {
			return runtime.factory(ctx)
		},
		HandleEvent:       runtime.handleEvent,
		HandleOutcome:     runtime.handleOutcome,
		ReconnectBackoff:  config.ReconnectBackoff,
		HeartbeatInterval: config.HeartbeatInterval,
	})
	return runtime
}

func (r *SharedWSRuntime) SetRediscover(rediscover func() error) {
	if rediscover == nil {
		r.SetRediscoverContext(nil)
		return
	}
	r.SetRediscoverContext(func(context.Context) error { return rediscover() })
}

func (r *SharedWSRuntime) SetRediscoverContext(rediscover func(context.Context) error) {
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
			runtime:        r,
			nodeID:         nodeID,
			eventSubmitter: submitter,
		}, nil
	}
}

func (r *SharedWSRuntime) NewSnapshotMailbox(nodeID int, submitter service.SnapshotSyncSubmitter) (*SharedWSMailbox, error) {
	if nodeID <= 0 {
		return nil, errors.New("machine websocket mailbox node ID must be greater than 0")
	}
	if submitter == nil {
		return nil, errors.New("machine websocket snapshot submitter must not be nil")
	}
	return &SharedWSMailbox{
		runtime:           r,
		nodeID:            nodeID,
		snapshotSubmitter: submitter,
	}, nil
}

func (r *SharedWSRuntime) Start() error {
	ctx, cancel := service.WithDefaultTimeout(context.Background(), service.DefaultStartTimeout)
	defer cancel()
	return r.StartContext(ctx)
}

func (r *SharedWSRuntime) StartContext(parent context.Context) error {
	ctx, cancel := service.WithDefaultTimeout(parent, service.DefaultStartTimeout)
	defer cancel()
	if err := ctx.Err(); err != nil {
		return err
	}

	r.lifecycleMu.Lock()
	defer r.lifecycleMu.Unlock()
	if r.closed {
		return nil
	}

	r.mu.Lock()
	if !r.rediscoverActive {
		runCtx, runCancel := context.WithCancel(context.WithoutCancel(ctx))
		done := make(chan struct{})
		r.rediscoverActive = true
		r.rediscoverCancel = runCancel
		r.rediscoverDone = done
		go r.runRediscover(runCtx, done)
	}
	r.mu.Unlock()

	r.lifecycle.StartContext(ctx)
	return ctx.Err()
}

func (r *SharedWSRuntime) Close() error {
	ctx, cancel := service.WithDefaultTimeout(context.Background(), service.DefaultCloseTimeout)
	defer cancel()
	return r.CloseContext(ctx)
}

func (r *SharedWSRuntime) CloseContext(parent context.Context) error {
	ctx, cancel := service.WithDefaultTimeout(parent, service.DefaultCloseTimeout)
	defer cancel()

	r.lifecycleMu.Lock()
	defer r.lifecycleMu.Unlock()
	if r.closed {
		return nil
	}

	r.mu.Lock()
	r.rediscoverActive = false
	cancelRediscover := r.rediscoverCancel
	done := r.rediscoverDone
	r.mu.Unlock()
	if cancelRediscover != nil {
		cancelRediscover()
	}

	var errs []error
	if err := r.lifecycle.CloseContext(ctx); err != nil {
		errs = append(errs, err)
	}
	if done != nil {
		select {
		case <-ctx.Done():
			errs = append(errs, ctx.Err())
		case <-done:
		}
	}
	closeErr := errors.Join(errs...)
	if closeErr != nil {
		return closeErr
	}

	r.mu.Lock()
	if r.rediscoverDone == done {
		r.rediscoverCancel = nil
		r.rediscoverDone = nil
	}
	r.mu.Unlock()
	r.closed = true
	return nil
}
func (r *SharedWSRuntime) DeviceReporterReady() bool {
	_, ok := r.lifecycle.Current().(sharedWSClient)
	return ok
}

func (r *SharedWSRuntime) WebSocketObservabilitySnapshot() service.WebSocketSnapshot {
	r.mu.RLock()
	degraded := r.degraded
	lastFailureAt := r.lastFailureAt
	r.mu.RUnlock()

	state := service.WebSocketDisconnected
	if r.lifecycle.Current() != nil {
		state = service.WebSocketConnected
	}
	if degraded {
		state = service.WebSocketDegraded
	}
	return service.WebSocketSnapshot{State: state, LastFailureAt: lastFailureAt}
}

func (r *SharedWSRuntime) ReportNodeDevices(nodeID int, devices map[int][]string) error {
	client, ok := r.lifecycle.Current().(sharedWSClient)
	if !ok {
		return nil
	}
	return client.SendNodeDeviceReport(nodeID, devices)
}

func (r *SharedWSRuntime) ReportNodeStatus(nodeID int, nodeStatus *api.NodeStatus) error {
	client, ok := r.lifecycle.Current().(sharedWSClient)
	if !ok {
		return nil
	}
	return client.SendNodeStatusReport(nodeID, nodeStatus)
}

func (r *SharedWSRuntime) handleEvent(client wslifecycle.Client, event *newV2board.WSEvent) {
	if event == nil {
		return
	}

	switch event.Event {
	case newV2board.WSEventPing:
		if ponger, ok := client.(interface{ Pong() error }); ok {
			_ = ponger.Pong()
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

func (r *SharedWSRuntime) handleOutcome(outcome wslifecycle.Outcome) {
	switch outcome {
	case wslifecycle.OutcomeConnectFailed:
		r.setWebSocketDegraded(true)
	case wslifecycle.OutcomeConnected:
		r.setWebSocketDegraded(false)
	case wslifecycle.OutcomeParseError:
		r.recordWebSocketFailure()
		r.broadcastParseError()
	case wslifecycle.OutcomeDisconnected:
		r.setWebSocketDegraded(true)
		r.broadcastDisconnect()
	case wslifecycle.OutcomeReconnected:
		r.broadcastReconnect()
	}
}

func (r *SharedWSRuntime) setWebSocketDegraded(degraded bool) {
	r.mu.Lock()
	r.degraded = degraded
	if degraded {
		r.lastFailureAt = time.Now()
	}
	r.mu.Unlock()
}

func (r *SharedWSRuntime) recordWebSocketFailure() {
	r.mu.Lock()
	r.lastFailureAt = time.Now()
	r.mu.Unlock()
}

func (r *SharedWSRuntime) triggerRediscover() {
	r.mu.RLock()
	active := r.rediscoverActive
	signal := r.rediscoverSignal
	r.mu.RUnlock()
	if !active {
		return
	}

	select {
	case signal <- struct{}{}:
	default:
	}
}

func (r *SharedWSRuntime) runRediscover(ctx context.Context, done chan<- struct{}) {
	defer close(done)
	for {
		select {
		case <-ctx.Done():
			return
		case <-r.rediscoverSignal:
		}
		if ctx.Err() != nil {
			return
		}

		r.mu.RLock()
		rediscover := r.rediscover
		r.mu.RUnlock()
		if rediscover == nil {
			continue
		}
		operationCtx, cancel := service.WithDefaultTimeout(ctx, service.DefaultSyncTimeout)
		err := rediscover(operationCtx)
		cancel()
		if err != nil && !errors.Is(err, context.Canceled) && r.config.Logger != nil {
			r.config.Logger.Warn(err)
		}
	}
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

type SharedWSMailbox struct {
	runtime           *SharedWSRuntime
	nodeID            int
	eventSubmitter    controller.WSEventSubmitter
	snapshotSubmitter service.SnapshotSyncSubmitter

	mu      sync.RWMutex
	started bool
}

func (m *SharedWSMailbox) Start() {
	_ = m.StartContext(context.Background())
}

func (m *SharedWSMailbox) StartContext(ctx context.Context) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	m.mu.Lock()
	if m.started {
		m.mu.Unlock()
		return nil
	}
	m.started = true
	m.mu.Unlock()

	if m.runtime != nil {
		m.runtime.registerMailbox(m)
	}
	return ctx.Err()
}

func (m *SharedWSMailbox) Stop() {
	_ = m.StopContext(context.Background())
}

func (m *SharedWSMailbox) StopContext(ctx context.Context) error {
	if m.runtime != nil {
		m.runtime.unregisterMailbox(m)
	}

	m.mu.Lock()
	m.started = false
	m.mu.Unlock()
	return ctx.Err()
}

func (m *SharedWSMailbox) deliver(event *newV2board.WSEvent) {
	if submitter, ok := m.currentEventSubmitter(); ok {
		submitter.SubmitWSEvent(event)
		return
	}
	submitter, ok := m.currentSnapshotSubmitter()
	if !ok {
		return
	}
	trigger, ok := snapshotSyncTriggerFromWSEvent(event, time.Now())
	if ok {
		submitter.SubmitSnapshotSync(trigger)
	}
}

func (m *SharedWSMailbox) submitParseError() {
	if submitter, ok := m.currentEventSubmitter(); ok {
		submitter.SubmitWSParseError()
		return
	}
	if submitter, ok := m.currentSnapshotSubmitter(); ok {
		submitter.SubmitSnapshotSync(service.SnapshotSyncTrigger{
			Scope:      service.SnapshotSyncAll,
			Source:     service.SnapshotSyncSourceParseError,
			OccurredAt: time.Now(),
		})
	}
}

func (m *SharedWSMailbox) submitDisconnect() {
	submitter, ok := m.currentEventSubmitter()
	if !ok {
		return
	}
	submitter.SubmitWSDisconnect()
}

func (m *SharedWSMailbox) submitReconnect() {
	if submitter, ok := m.currentEventSubmitter(); ok {
		submitter.SubmitWSReconnect()
		return
	}
	if submitter, ok := m.currentSnapshotSubmitter(); ok {
		submitter.SubmitSnapshotSync(service.SnapshotSyncTrigger{
			Scope:      service.SnapshotSyncAll,
			Source:     service.SnapshotSyncSourceReconnect,
			OccurredAt: time.Now(),
		})
	}
}

func (m *SharedWSMailbox) currentEventSubmitter() (controller.WSEventSubmitter, bool) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.eventSubmitter, m.started && m.eventSubmitter != nil
}

func (m *SharedWSMailbox) currentSnapshotSubmitter() (service.SnapshotSyncSubmitter, bool) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.snapshotSubmitter, m.started && m.snapshotSubmitter != nil
}

func (m *SharedWSMailbox) WebSocketObservabilitySnapshot() service.WebSocketSnapshot {
	if m == nil || m.runtime == nil {
		return service.WebSocketSnapshot{State: service.WebSocketDisconnected}
	}
	return m.runtime.WebSocketObservabilitySnapshot()
}

func snapshotSyncTriggerFromWSEvent(event *newV2board.WSEvent, occurredAt time.Time) (service.SnapshotSyncTrigger, bool) {
	if event == nil {
		return service.SnapshotSyncTrigger{}, false
	}
	var scope service.SnapshotSyncScope
	switch event.Event {
	case newV2board.WSEventNodeChanged,
		newV2board.WSEventCertChanged,
		newV2board.WSEventRoutesChanged,
		newV2board.WSEventOutboundsChanged,
		newV2board.WSEventXboardSyncConfig:
		scope = service.SnapshotSyncNode
	case newV2board.WSEventUsersChanged,
		newV2board.WSEventXboardSyncUsers,
		newV2board.WSEventXboardSyncUserDelta:
		scope = service.SnapshotSyncUsers
	case newV2board.WSEventResyncAll:
		scope = service.SnapshotSyncAll
	default:
		return service.SnapshotSyncTrigger{}, false
	}
	return service.SnapshotSyncTrigger{
		Scope:      scope,
		Source:     service.SnapshotSyncSourceWebSocket,
		OccurredAt: occurredAt,
	}, true
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
