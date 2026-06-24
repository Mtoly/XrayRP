package newV2board

import (
	"context"
	"errors"
	"strconv"
	"sync"
	"time"

	"github.com/Mtoly/XrayRP/api"
	"github.com/gorilla/websocket"
)

var (
	ErrWSClientParse     = errors.New("websocket client parse error")
	ErrWSClientTransport = errors.New("websocket client transport error")
)

// WSClient is a minimal websocket reader that parses upstream events.
type WSClient struct {
	conn      *websocket.Conn
	events    chan *WSEvent
	errs      chan error
	done      chan struct{}
	closing   chan struct{}
	closeOnce sync.Once
	writeMu   sync.Mutex
}

// NewWSClient dials the websocket endpoint and starts the read loop.
func NewWSClient(rawURL string) (*WSClient, error) {
	return NewWSClientContext(context.Background(), rawURL)
}

// NewWSClientContext dials the websocket endpoint with ctx and starts the read loop.
func NewWSClientContext(ctx context.Context, rawURL string) (*WSClient, error) {
	conn, _, err := websocket.DefaultDialer.DialContext(ctx, rawURL, nil)
	if err != nil {
		return nil, err
	}

	client := &WSClient{
		conn:    conn,
		events:  make(chan *WSEvent, 16),
		errs:    make(chan error, 16),
		done:    make(chan struct{}),
		closing: make(chan struct{}),
	}

	go client.readLoop()

	return client, nil
}

// Events returns parsed websocket events.
func (c *WSClient) Events() <-chan *WSEvent {
	return c.events
}

// Errors returns parse and transport errors produced by the read loop.
func (c *WSClient) Errors() <-chan error {
	return c.errs
}

// Done is closed when the read loop exits.
func (c *WSClient) Done() <-chan struct{} {
	return c.done
}

// KeepAlive sends a websocket ping control frame to keep the connection active.
func (c *WSClient) KeepAlive() error {
	if c == nil {
		return nil
	}
	if c.isClosing() {
		return nil
	}

	c.writeMu.Lock()
	defer c.writeMu.Unlock()

	if c.isClosing() {
		return nil
	}

	deadline := time.Now().Add(5 * time.Second)
	if err := c.conn.WriteControl(websocket.PingMessage, nil, deadline); err != nil {
		return errors.Join(ErrWSClientTransport, err)
	}
	return nil
}

// Pong sends an Xboard app-level pong event.
func (c *WSClient) Pong() error {
	return c.writeJSONEvent(WSEventPong, map[string]any{})
}

// SendDeviceReport sends the current online device snapshot to Xboard.
func (c *WSClient) SendDeviceReport(devices map[int][]string) error {
	payload := make(map[string]any, len(devices))
	for uid, ips := range devices {
		payload[strconv.Itoa(uid)] = append([]string(nil), ips...)
	}
	return c.writeJSONEvent(WSEventXboardReportDevices, payload)
}

func (c *WSClient) SendNodeStatusReport(nodeID int, nodeStatus *api.NodeStatus) error {
	payload, err := buildNodeStatusWSPayload(nodeID, nodeStatus)
	if err != nil {
		return err
	}
	return c.writeJSONEvent(WSEventXboardNodeStatus, payload)
}

func (c *WSClient) writeJSONEvent(event string, data map[string]any) error {
	if c == nil {
		return nil
	}
	if c.isClosing() {
		return nil
	}

	c.writeMu.Lock()
	defer c.writeMu.Unlock()

	if c.isClosing() {
		return nil
	}

	payload := map[string]any{
		"event": event,
		"data":  data,
	}
	if err := c.conn.WriteJSON(payload); err != nil {
		return errors.Join(ErrWSClientTransport, err)
	}
	return nil
}

// Close stops the client and closes the underlying websocket connection.
func (c *WSClient) Close() error {
	if c == nil {
		return nil
	}

	var err error
	c.closeOnce.Do(func() {
		close(c.closing)
		c.writeMu.Lock()
		defer c.writeMu.Unlock()
		err = c.conn.Close()
	})

	return err
}

func (c *WSClient) readLoop() {
	defer close(c.done)
	defer close(c.events)
	defer close(c.errs)

	for {
		_, data, err := c.conn.ReadMessage()
		if err != nil {
			if c.isClosing() {
				return
			}
			c.pushError(errors.Join(ErrWSClientTransport, err))
			return
		}

		event, err := ParseWSEvent(data)
		if err != nil {
			c.pushError(errors.Join(ErrWSClientParse, err))
			continue
		}

		c.pushEvent(event)
	}
}

func (c *WSClient) isClosing() bool {
	select {
	case <-c.closing:
		return true
	default:
		return false
	}
}

func (c *WSClient) pushEvent(event *WSEvent) {
	select {
	case c.events <- event:
	case <-c.closing:
	}
}

func (c *WSClient) pushError(err error) {
	select {
	case c.errs <- err:
	case <-c.closing:
	}
}
