package newV2board

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/gorilla/websocket"
)

func TestWSClientWriteFailsWhenPeerStopsReading(t *testing.T) {
	release := make(chan struct{})
	upgrader := websocket.Upgrader{}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		conn, err := upgrader.Upgrade(w, r, nil)
		if err != nil {
			t.Errorf("upgrade failed: %v", err)
			return
		}
		defer conn.Close()
		<-release
	}))
	defer server.Close()
	defer close(release)

	client, err := NewWSClient("ws" + strings.TrimPrefix(server.URL, "http"))
	if err != nil {
		t.Fatalf("NewWSClient() error = %v", err)
	}
	client.writeTimeout = 100 * time.Millisecond

	// Larger than the loopback socket buffers, so the write blocks once the
	// peer stops reading.
	devices := map[int][]string{1: {strings.Repeat("x", 32<<20)}}
	written := make(chan error, 1)
	go func() { written <- client.SendDeviceReport(devices) }()
	select {
	case err := <-written:
		if !errors.Is(err, ErrWSClientTransport) {
			t.Fatalf("SendDeviceReport() error = %v, want %v", err, ErrWSClientTransport)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("SendDeviceReport() blocked on a peer that stopped reading")
	}

	closed := make(chan struct{})
	go func() {
		_ = client.Close()
		close(closed)
	}()
	select {
	case <-closed:
	case <-time.After(5 * time.Second):
		t.Fatal("Close() blocked after a write timeout")
	}
}
