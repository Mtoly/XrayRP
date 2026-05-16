package newV2board

import (
	"errors"
	"fmt"
	"sync"

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
}

// NewWSClient dials the websocket endpoint and starts the read loop.
func NewWSClient(rawURL string) (*WSClient, error) {
	conn, _, err := websocket.DefaultDialer.Dial(rawURL, nil)
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

// Close stops the client and closes the underlying websocket connection.
func (c *WSClient) Close() error {
	if c == nil {
		return nil
	}

	var err error
	c.closeOnce.Do(func() {
		close(c.closing)
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
			c.pushError(fmt.Errorf("%w: %v", ErrWSClientTransport, err))
			return
		}

		event, err := ParseWSEvent(data)
		if err != nil {
			c.pushError(fmt.Errorf("%w: %v", ErrWSClientParse, err))
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
