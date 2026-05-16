package newV2board_test

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/gorilla/websocket"

	"github.com/Mtoly/XrayRP/api/newV2board"
)

func TestWSClient_ReceivesEvent(t *testing.T) {
	t.Parallel()

	server, connected := newMockWSServer(t, func(conn *websocket.Conn) {
		if err := conn.WriteMessage(websocket.TextMessage, []byte(`{"event":"node_changed","payload":{"node_id":7}}`)); err != nil {
			t.Errorf("write message failed: %v", err)
			return
		}
		waitForPeerClose(t, conn)
	})

	client, err := newV2board.NewWSClient(wsURL(server.URL))
	if err != nil {
		t.Fatalf("NewWSClient returned error: %v", err)
	}
	defer client.Close()

	waitForConnection(t, connected)

	event := receiveEvent(t, client.Events())
	if event.Event != newV2board.WSEventNodeChanged {
		t.Fatalf("unexpected event: got %q want %q", event.Event, newV2board.WSEventNodeChanged)
	}
	if event.Category != newV2board.WSEventCategoryControl {
		t.Fatalf("unexpected category: got %q want %q", event.Category, newV2board.WSEventCategoryControl)
	}
	if got := event.Payload["node_id"]; got != float64(7) {
		t.Fatalf("unexpected payload node_id: got %#v want 7", got)
	}

	select {
	case err := <-client.Errors():
		t.Fatalf("unexpected error from client: %v", err)
	case <-time.After(100 * time.Millisecond):
	}
}

func TestWSClient_CloseStopsReadLoop(t *testing.T) {
	t.Parallel()

	server, connected := newMockWSServer(t, func(conn *websocket.Conn) {
		waitForPeerClose(t, conn)
	})

	client, err := newV2board.NewWSClient(wsURL(server.URL))
	if err != nil {
		t.Fatalf("NewWSClient returned error: %v", err)
	}

	waitForConnection(t, connected)

	if err := client.Close(); err != nil {
		t.Fatalf("Close returned error: %v", err)
	}

	waitDone(t, client.Done())
}

func TestWSClient_InvalidMessageDoesNotPanic(t *testing.T) {
	t.Parallel()

	server, connected := newMockWSServer(t, func(conn *websocket.Conn) {
		if err := conn.WriteMessage(websocket.TextMessage, []byte(`not-json`)); err != nil {
			t.Errorf("write invalid message failed: %v", err)
			return
		}
		if err := conn.WriteMessage(websocket.TextMessage, []byte(`{"event":"ping","payload":{"ack":true}}`)); err != nil {
			t.Errorf("write valid message failed: %v", err)
			return
		}
		waitForPeerClose(t, conn)
	})

	client, err := newV2board.NewWSClient(wsURL(server.URL))
	if err != nil {
		t.Fatalf("NewWSClient returned error: %v", err)
	}
	defer client.Close()

	waitForConnection(t, connected)

	parseErr := receiveError(t, client.Errors())
	if !errors.Is(parseErr, newV2board.ErrWSClientParse) {
		t.Fatalf("expected ErrWSClientParse, got %v", parseErr)
	}
	if !errors.Is(parseErr, newV2board.ErrInvalidWSJSON) {
		t.Fatalf("expected ErrInvalidWSJSON cause, got %v", parseErr)
	}

	event := receiveEvent(t, client.Events())
	if event.Event != newV2board.WSEventPing {
		t.Fatalf("unexpected event after invalid message: got %q want %q", event.Event, newV2board.WSEventPing)
	}
}

func TestWSClient_ReportsTransportError(t *testing.T) {
	t.Parallel()

	server, connected := newMockWSServer(t, func(conn *websocket.Conn) {
		deadline := time.Now().Add(time.Second)
		_ = conn.WriteControl(websocket.CloseMessage, websocket.FormatCloseMessage(websocket.CloseNormalClosure, "bye"), deadline)
	})

	client, err := newV2board.NewWSClient(wsURL(server.URL))
	if err != nil {
		t.Fatalf("NewWSClient returned error: %v", err)
	}
	defer client.Close()

	waitForConnection(t, connected)

	transportErr := receiveError(t, client.Errors())
	if !errors.Is(transportErr, newV2board.ErrWSClientTransport) {
		t.Fatalf("expected ErrWSClientTransport, got %v", transportErr)
	}

	var closeErr *websocket.CloseError
	if !errors.As(transportErr, &closeErr) {
		t.Fatalf("expected websocket.CloseError cause, got %T (%v)", transportErr, transportErr)
	}
	if closeErr.Code != websocket.CloseNormalClosure {
		t.Fatalf("unexpected close code: got %d want %d", closeErr.Code, websocket.CloseNormalClosure)
	}

	waitDone(t, client.Done())
}

func newMockWSServer(t *testing.T, handler func(*websocket.Conn)) (*httptest.Server, <-chan struct{}) {
	t.Helper()

	connected := make(chan struct{})
	upgrader := websocket.Upgrader{
		CheckOrigin: func(r *http.Request) bool { return true },
	}

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		conn, err := upgrader.Upgrade(w, r, nil)
		if err != nil {
			t.Errorf("upgrade failed: %v", err)
			return
		}
		close(connected)
		defer conn.Close()
		handler(conn)
	}))
	t.Cleanup(server.Close)

	return server, connected
}

func wsURL(serverURL string) string {
	return "ws" + strings.TrimPrefix(serverURL, "http")
}

func waitForConnection(t *testing.T, connected <-chan struct{}) {
	t.Helper()

	select {
	case <-connected:
	case <-time.After(2 * time.Second):
		t.Fatal("timeout waiting for websocket connection")
	}
}

func waitForPeerClose(t *testing.T, conn *websocket.Conn) {
	t.Helper()

	_ = conn.SetReadDeadline(time.Now().Add(2 * time.Second))
	_, _, _ = conn.ReadMessage()
}

func receiveEvent(t *testing.T, ch <-chan *newV2board.WSEvent) *newV2board.WSEvent {
	t.Helper()

	select {
	case event, ok := <-ch:
		if !ok {
			t.Fatal("event channel closed before receiving event")
		}
		return event
	case <-time.After(2 * time.Second):
		t.Fatal("timeout waiting for websocket event")
		return nil
	}
}

func receiveError(t *testing.T, ch <-chan error) error {
	t.Helper()

	select {
	case err, ok := <-ch:
		if !ok {
			t.Fatal("error channel closed before receiving error")
		}
		return err
	case <-time.After(2 * time.Second):
		t.Fatal("timeout waiting for websocket error")
		return nil
	}
}

func waitDone(t *testing.T, done <-chan struct{}) {
	t.Helper()

	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("timeout waiting for websocket client shutdown")
	}
}
