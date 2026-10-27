package controller_test

import (
	"context"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"os"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/xtls/xray-core/common/uuid"
	"github.com/xtls/xray-core/core"
	"github.com/xtls/xray-core/features/outbound"
	"github.com/xtls/xray-core/infra/conf"

	"github.com/Mtoly/XrayRP/api"
	_ "github.com/Mtoly/XrayRP/cmd/distro/all"
	"github.com/Mtoly/XrayRP/common/limiter"
	"github.com/Mtoly/XrayRP/service/controller"
)

// TestRedisIntegrationXrayVLESSGlobalAdmissionAcrossRealNodes drives the real
// Xray data path: a plain VLESS client connection enters a managed inbound,
// the core dispatcher selects the managed dataPathWrapper, the wrapper calls
// limiter.AdmitContext, and a freedom outbound connects to a local TCP echo.
// Two controllers (two node tags) share one panel UID and one Redis namespace,
// so the quota is enforced across node tags inside one process.
//
// Requirements for running it:
//
//	XRAYRP_RUN_REDIS_INTEGRATION=1
//	XRAYRP_REDIS_ADDR=127.0.0.1:16379 (default when unset)
//
// A disposable Redis is required. The test skips when loopback source-address
// binding is unavailable in the host environment; it never fakes admission.
func TestRedisIntegrationXrayVLESSGlobalAdmissionAcrossRealNodes(t *testing.T) {
	redisAddr := requireXrayGlobalRedisIntegration(t)
	requireLoopbackSourceBinding(t, "127.0.0.2", "127.0.0.3", "127.0.0.4")
	echoAddr := startVLESSGlobalEchoServer(t)

	namespace := fmt.Sprintf("xray-controller-vless-global-%d", time.Now().UnixNano())
	const (
		uid         = 42
		deviceLimit = 2
		userID      = "1b4e28ba-2fa1-11d2-883f-0016d3cca427"
	)
	users := []api.UserInfo{{
		UID:         uid,
		Email:       "global-vless@example.test",
		UUID:        userID,
		DeviceLimit: deviceLimit,
	}}
	server := newRealControllerCore(t)
	// Xray-core blackholes private destinations for VLESS inbounds by default.
	// The destination here is a loopback echo, so route the node through a
	// test-only freedom outbound that explicitly allows loopback. Admission is
	// still enforced by the real dataPathWrapper before this outbound runs.
	//
	// The outbound is registered after the controllers start on purpose: the
	// outbound manager treats the first registered handler as the default, and
	// the default must be a managed data path wrapper so the wrapper's admission
	// runs before any test outbound. Registering it first would silently route
	// every connection around the wrapper.
	const echoOutboundTag = "test-echo-allow"
	routePolicy := &api.PanelRoutePolicy{
		Outbound: api.OutboundFilterPolicy{Candidates: []string{echoOutboundTag}},
	}
	portA := reserveLoopbackPort(t)
	portB := reserveLoopbackPort(t)
	for portB == portA {
		portB = reserveLoopbackPort(t)
	}
	addressA := net.JoinHostPort("127.0.0.1", strconv.Itoa(portA))
	addressB := net.JoinHostPort("127.0.0.1", strconv.Itoa(portB))

	newControllerConfig := func() *controller.Config {
		return &controller.Config{
			ListenIP:        "127.0.0.1",
			SendIP:          "127.0.0.1",
			UpdatePeriodic:  3600,
			DisableGetRule:  true,
			DisableSniffing: true,
			DisableIVCheck:  false,
			EnableFallback:  false,
			GlobalPanelType: "V2board",
			WebSocketConfig: nil,
			CertConfig:      nil,
			GlobalDeviceLimitConfig: &limiter.GlobalDeviceLimitConfig{
				Enable:    true,
				RedisAddr: redisAddr,
				Timeout:   2,
				Expiry:    3,
				Mode:      "strict",
				FailMode:  "closed",
				Namespace: namespace,
			},
		}
	}
	clientA := &vlessGlobalPanelClient{
		node: api.NodeInfo{
			NodeType:          "Vless",
			NodeID:            901,
			Port:              uint32(portA),
			TransportProtocol: "tcp",
			EnableVless:       true,
			RoutePolicy:       routePolicy,
		},
		users: users,
	}
	clientB := &vlessGlobalPanelClient{
		node: api.NodeInfo{
			NodeType:          "Vless",
			NodeID:            902,
			Port:              uint32(portB),
			TransportProtocol: "tcp",
			EnableVless:       true,
			RoutePolicy:       routePolicy,
		},
		users: users,
	}
	nodeA := controller.New(server, clientA, newControllerConfig(), "V2board")
	if err := nodeA.Start(); err != nil {
		t.Fatalf("node A start: %v", err)
	}
	t.Cleanup(func() {
		if err := nodeA.Close(); err != nil {
			t.Errorf("node A close: %v", err)
		}
	})
	nodeB := controller.New(server, clientB, newControllerConfig(), "V2board")
	if err := nodeB.Start(); err != nil {
		t.Fatalf("node B start: %v", err)
	}
	t.Cleanup(func() {
		if err := nodeB.Close(); err != nil {
			t.Errorf("node B close: %v", err)
		}
	})
	addVLESSGlobalEchoOutbound(t, server, echoOutboundTag)

	var held []net.Conn
	closeHeld := func() {
		for _, conn := range held {
			_ = conn.Close()
		}
		held = nil
	}
	t.Cleanup(closeHeld)

	// One source address occupies one shared slot. The second connection from
	// the same source on the other node tag must be deduplicated.
	connSameNodeA, err := dialVLESSGlobalEcho("127.0.0.2", addressA, echoAddr, userID)
	if err != nil {
		t.Fatalf("first source IP on node A: %v", err)
	}
	held = append(held, connSameNodeA)
	connSameNodeB, err := dialVLESSGlobalEcho("127.0.0.2", addressB, echoAddr, userID)
	if err != nil {
		t.Fatalf("same source IP deduplicated across nodes: %v", err)
	}
	held = append(held, connSameNodeB)

	// A second distinct source IP must still fit in the quota of two. If the
	// same source had been counted twice, this connection would be rejected.
	connSecondIP, err := dialVLESSGlobalEcho("127.0.0.3", addressB, echoAddr, userID)
	if err != nil {
		t.Fatalf("second distinct source IP after cross-node dedup: %v", err)
	}
	held = append(held, connSecondIP)

	// The third distinct source IP exceeds the shared quota on either node.
	expectVLESSGlobalRejection(t, "127.0.0.4", addressA, echoAddr, userID)
	expectVLESSGlobalRejection(t, "127.0.0.4", addressB, echoAddr, userID)

	// Idle connections must keep their leases across a full Expiry window. The
	// body round trip proves the held connection is still the live owner.
	time.Sleep(4500 * time.Millisecond)
	if err := writeVLESSGlobalBody(connSecondIP, "still-here"); err != nil {
		t.Fatalf("held idle connection did not survive the renewal window: %v", err)
	}
	expectVLESSGlobalRejection(t, "127.0.0.4", addressB, echoAddr, userID)

	// Closing the last connections stops renewal; once the leases expire in
	// Redis, the rejected source address must be admitted again.
	closeHeld()
	deadline := time.Now().Add(12 * time.Second)
	var lastErr error
	for {
		conn, err := dialVLESSGlobalEcho("127.0.0.4", addressA, echoAddr, userID)
		if err == nil {
			_ = conn.Close()
			break
		}
		lastErr = err
		if time.Now().After(deadline) {
			t.Fatalf("source IP was not admitted after lease expiry: %v", lastErr)
		}
		time.Sleep(300 * time.Millisecond)
	}
}

// expectVLESSGlobalRejection asserts the managed wrapper refuses this source
// IP. A quota rejection closes the stream promptly, so a slow failure is
// treated as an inconclusive hang instead of a pass.
func expectVLESSGlobalRejection(t *testing.T, sourceIP, serverAddress, echoAddress, userID string) {
	t.Helper()
	started := time.Now()
	conn, err := dialVLESSGlobalEcho(sourceIP, serverAddress, echoAddress, userID)
	elapsed := time.Since(started)
	if err == nil {
		_ = conn.Close()
		t.Fatalf("source IP %s was admitted to %s past the shared quota", sourceIP, serverAddress)
	}
	if elapsed > 3*time.Second {
		t.Fatalf("source IP %s was not promptly rejected by %s (took %s): %v", sourceIP, serverAddress, elapsed, err)
	}
}

// requireXrayGlobalRedisIntegration enforces the opt-in gate and verifies that
// a real Redis endpoint answers TCP before the test starts.
func requireXrayGlobalRedisIntegration(t *testing.T) string {
	t.Helper()
	if os.Getenv("XRAYRP_RUN_REDIS_INTEGRATION") != "1" {
		t.Skip("skipping real Redis/Xray integration test; set XRAYRP_RUN_REDIS_INTEGRATION=1 to enable")
	}
	address := strings.TrimSpace(os.Getenv("XRAYRP_REDIS_ADDR"))
	if address == "" {
		address = "127.0.0.1:16379"
	}
	conn, err := net.DialTimeout("tcp", address, 2*time.Second)
	if err != nil {
		t.Fatalf("real Redis is required at %s: %v", address, err)
	}
	_ = conn.Close()
	return address
}

// requireLoopbackSourceBinding skips only when the host cannot bind the
// loopback source aliases the test needs. This is an environment limitation,
// not an admission result.
func requireLoopbackSourceBinding(t *testing.T, ips ...string) {
	t.Helper()
	for _, ip := range ips {
		listener, err := net.Listen("tcp", net.JoinHostPort(ip, "0"))
		if err != nil {
			t.Skipf("host cannot bind loopback source %s: %v", ip, err)
		}
		_ = listener.Close()
	}
}

// vlessGlobalEchoServer owns the test echo listener and every accepted
// connection so cleanup can close them and wait for the goroutines to finish.
type vlessGlobalEchoServer struct {
	listener net.Listener
	mu       sync.Mutex
	conns    map[net.Conn]struct{}
	closed   bool
	wg       sync.WaitGroup
}

// startVLESSGlobalEchoServer starts a local TCP echo service and returns its
// address. The Xray freedom outbound connects here through the real data path.
//
// Its cleanup is registered before the controllers start, so LIFO cleanup runs
// the controller shutdown first and this echo shutdown last.
func startVLESSGlobalEchoServer(t *testing.T) string {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("echo listener: %v", err)
	}
	server := &vlessGlobalEchoServer{listener: listener, conns: make(map[net.Conn]struct{})}
	server.wg.Add(1)
	go server.serve()
	t.Cleanup(server.shutdown)
	return listener.Addr().String()
}

func (s *vlessGlobalEchoServer) serve() {
	defer s.wg.Done()
	for {
		conn, err := s.listener.Accept()
		if err != nil {
			return
		}
		if !s.track(conn) {
			_ = conn.Close()
			return
		}
		go func() {
			defer s.wg.Done()
			defer s.untrack(conn)
			defer conn.Close()
			_, _ = io.Copy(conn, conn)
		}()
	}
}

// track registers an accepted connection unless shutdown already started.
// Adding under the same mutex that shutdown sets `closed` with guarantees no
// WaitGroup Add can race past shutdown's Wait.
func (s *vlessGlobalEchoServer) track(conn net.Conn) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return false
	}
	s.conns[conn] = struct{}{}
	s.wg.Add(1)
	return true
}

func (s *vlessGlobalEchoServer) untrack(conn net.Conn) {
	s.mu.Lock()
	delete(s.conns, conn)
	s.mu.Unlock()
}

// shutdown stops accepting, closes every accepted connection, and joins the
// listener and connection goroutines.
func (s *vlessGlobalEchoServer) shutdown() {
	_ = s.listener.Close()
	s.mu.Lock()
	s.closed = true
	for conn := range s.conns {
		_ = conn.Close()
	}
	s.mu.Unlock()
	s.wg.Wait()
}

// addVLESSGlobalEchoOutbound registers a freedom outbound that explicitly
// allows loopback destinations. Xray-core's default freedom final rule blocks
// private IPs for VLESS-family inbounds, which would blackhole the test echo.
// The outbound is test-only and lives outside the production controller path.
func addVLESSGlobalEchoOutbound(t *testing.T, server *core.Instance, tag string) {
	t.Helper()
	settings := json.RawMessage(`{"finalRules":[{"action":"allow","ip":["127.0.0.0/8"]}]}`)
	config, err := (&conf.OutboundDetourConfig{
		Protocol: "freedom",
		Tag:      tag,
		Settings: &settings,
	}).Build()
	if err != nil {
		t.Fatalf("build echo outbound: %v", err)
	}
	rawHandler, err := core.CreateObject(server, config)
	if err != nil {
		t.Fatalf("create echo outbound: %v", err)
	}
	handler, ok := rawHandler.(outbound.Handler)
	if !ok {
		t.Fatalf("echo outbound is not an outbound.Handler: %T", rawHandler)
	}
	manager, ok := server.GetFeature(outbound.ManagerType()).(outbound.Manager)
	if !ok {
		t.Fatalf("outbound manager feature unavailable")
	}
	if err := manager.AddHandler(context.Background(), handler); err != nil {
		t.Fatalf("register echo outbound: %v", err)
	}
}

// vlessGlobalPanelClient is a minimal in-process panel snapshot source. It
// keeps the test on the real controller.Start path without HTTP or production
// endpoints.
type vlessGlobalPanelClient struct {
	node  api.NodeInfo
	users []api.UserInfo
}

func (c *vlessGlobalPanelClient) Describe() api.ClientInfo {
	return api.ClientInfo{
		APIHost:  "http://127.0.0.1",
		NodeID:   c.node.NodeID,
		NodeType: c.node.NodeType,
	}
}

func (c *vlessGlobalPanelClient) GetNodeInfo() (*api.NodeInfo, error) {
	node := c.node
	return &node, nil
}

func (c *vlessGlobalPanelClient) GetUserList() (*[]api.UserInfo, error) {
	users := append([]api.UserInfo(nil), c.users...)
	return &users, nil
}

func (*vlessGlobalPanelClient) GetNodeRule() (*[]api.DetectRule, error) {
	rules := []api.DetectRule{}
	return &rules, nil
}

func (*vlessGlobalPanelClient) ReportNodeStatus(*api.NodeStatus) error        { return nil }
func (*vlessGlobalPanelClient) ReportNodeOnlineUsers(*[]api.OnlineUser) error { return nil }
func (*vlessGlobalPanelClient) ReportUserTraffic(*[]api.UserTraffic) error    { return nil }
func (*vlessGlobalPanelClient) ReportIllegal(*[]api.DetectResult) error       { return nil }

// dialVLESSGlobalEcho opens a real TCP connection from sourceIP, performs the
// VLESS request header and one echo round trip. Errors include quota rejection:
// the managed wrapper closes the stream before any response header is written.
func dialVLESSGlobalEcho(sourceIP, serverAddress, echoAddress, userID string) (net.Conn, error) {
	id, err := uuid.ParseString(userID)
	if err != nil {
		return nil, fmt.Errorf("parse client UUID: %w", err)
	}
	payload := []byte("ping")
	header, err := vlessGlobalRequestHeader(id, echoAddress, payload)
	if err != nil {
		return nil, err
	}

	dialer := net.Dialer{
		Timeout:   4 * time.Second,
		LocalAddr: &net.TCPAddr{IP: net.ParseIP(sourceIP)},
	}
	conn, err := dialer.Dial("tcp", serverAddress)
	if err != nil {
		return nil, fmt.Errorf("dial %s from %s: %w", serverAddress, sourceIP, err)
	}
	fail := func(err error) (net.Conn, error) {
		_ = conn.Close()
		return nil, err
	}
	if err := conn.SetDeadline(time.Now().Add(6 * time.Second)); err != nil {
		return fail(err)
	}
	if _, err := conn.Write(header); err != nil {
		return fail(fmt.Errorf("write VLESS request: %w", err))
	}

	responseHeader := make([]byte, 2)
	if _, err := io.ReadFull(conn, responseHeader); err != nil {
		return fail(fmt.Errorf("read VLESS response header: %w", err))
	}
	if responseHeader[0] != 0 {
		return fail(fmt.Errorf("unexpected VLESS response version %d", responseHeader[0]))
	}
	if addonsLength := int(responseHeader[1]); addonsLength > 0 {
		addons := make([]byte, addonsLength)
		if _, err := io.ReadFull(conn, addons); err != nil {
			return fail(fmt.Errorf("read VLESS response addons: %w", err))
		}
	}
	reply := make([]byte, len(payload))
	if _, err := io.ReadFull(conn, reply); err != nil {
		return fail(fmt.Errorf("read echo reply: %w", err))
	}
	if string(reply) != string(payload) {
		return fail(fmt.Errorf("echo reply = %q, want %q", reply, payload))
	}
	if err := conn.SetDeadline(time.Time{}); err != nil {
		return fail(err)
	}
	return conn, nil
}

// writeVLESSGlobalBody sends another body-only payload on a held VLESS
// connection and verifies the echo. It proves the connection is still live, so
// a held slot is owned by an active connection rather than stale state.
func writeVLESSGlobalBody(conn net.Conn, payload string) error {
	if err := conn.SetDeadline(time.Now().Add(5 * time.Second)); err != nil {
		return err
	}
	defer func() { _ = conn.SetDeadline(time.Time{}) }()
	if _, err := conn.Write([]byte(payload)); err != nil {
		return fmt.Errorf("write body: %w", err)
	}
	reply := make([]byte, len(payload))
	if _, err := io.ReadFull(conn, reply); err != nil {
		return fmt.Errorf("read body: %w", err)
	}
	if string(reply) != payload {
		return fmt.Errorf("body echo = %q, want %q", reply, payload)
	}
	return nil
}

// vlessGlobalRequestHeader encodes the VLESS TCP request: version, 16-byte
// user ID, empty addons, command, then port followed by the IPv4 address.
func vlessGlobalRequestHeader(id uuid.UUID, destination string, payload []byte) ([]byte, error) {
	host, portText, err := net.SplitHostPort(destination)
	if err != nil {
		return nil, fmt.Errorf("parse echo address %q: %w", destination, err)
	}
	ip := net.ParseIP(host).To4()
	if ip == nil {
		return nil, fmt.Errorf("echo address %q is not an IPv4 address", destination)
	}
	port, err := strconv.Atoi(portText)
	if err != nil || port <= 0 || port > 65535 {
		return nil, fmt.Errorf("invalid echo port %q", portText)
	}
	header := make([]byte, 0, 1+16+1+1+2+1+4+len(payload))
	header = append(header, 0) // VLESS request version
	header = append(header, id.Bytes()...)
	header = append(header, 0) // request addons length
	header = append(header, 1) // command: TCP
	portBytes := make([]byte, 2)
	binary.BigEndian.PutUint16(portBytes, uint16(port))
	header = append(header, portBytes...)
	header = append(header, 1) // address type: IPv4
	header = append(header, ip...)
	header = append(header, payload...)
	return header, nil
}
