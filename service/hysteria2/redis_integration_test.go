package hysteria2

import (
	"fmt"
	"io"
	"net"
	"os"
	"sync"
	"testing"
	"time"

	hclient "github.com/apernet/hysteria/core/v2/client"

	"github.com/Mtoly/XrayRP/api"
	commonlimiter "github.com/Mtoly/XrayRP/common/limiter"
	"github.com/Mtoly/XrayRP/common/mylego"
	"github.com/Mtoly/XrayRP/service/controller"
)

const redisIntegrationEnv = "XRAYRP_RUN_REDIS_INTEGRATION"

// redisTestAddr returns the Redis address for optional integration runs.
func redisTestAddr(t *testing.T) string {
	t.Helper()
	if os.Getenv(redisIntegrationEnv) != "1" {
		t.Skip("skipping Redis integration test; set XRAYRP_RUN_REDIS_INTEGRATION=1 to enable")
	}
	if addr := os.Getenv("XRAYRP_REDIS_ADDR"); addr != "" {
		return addr
	}
	return "127.0.0.1:16379"
}

// startHysteriaNode starts one real Hysteria2 service that shares the supplied
// Redis namespace. Each call represents one node.
func startHysteriaNode(t *testing.T, redisAddr, namespace, listenIP string, port uint16, users []api.UserInfo) *Hysteria2Service {
	t.Helper()
	client := &configurablePanelClient{
		nodeInfo: &api.NodeInfo{
			NodeType:        "Hysteria2",
			NodeID:          9,
			Port:            uint32(port),
			EnableTLS:       true,
			Hysteria2Config: &api.Hysteria2Config{Obfs: "none"},
		},
		users: users,
	}
	certFile, keyFile := writeTestCertificate(t)
	svc := New(client, &controller.Config{
		ListenIP:       listenIP,
		UpdatePeriodic: 3600,
		DisableGetRule: true,
		CertConfig: &mylego.CertConfig{
			CertMode: "file",
			CertFile: certFile,
			KeyFile:  keyFile,
		},
		GlobalDeviceLimitConfig: &commonlimiter.GlobalDeviceLimitConfig{
			Enable:    true,
			RedisAddr: redisAddr,
			Timeout:   2,
			Expiry:    3,
			Namespace: namespace,
		},
	})
	if err := svc.Start(); err != nil {
		t.Fatalf("Hysteria2 node start on %s:%d: %v", listenIP, port, err)
	}
	t.Cleanup(func() {
		if err := svc.Close(); err != nil {
			t.Errorf("Hysteria2 node close: %v", err)
		}
	})
	return svc
}

// sourceBoundConnFactory gives the Hysteria2 client a UDP socket bound to a
// specific loopback source address so several distinct source IPs can connect
// from one test process.
type sourceBoundConnFactory struct {
	source string
}

func (f sourceBoundConnFactory) New(net.Addr) (net.PacketConn, error) {
	return net.ListenUDP("udp", &net.UDPAddr{IP: net.ParseIP(f.source)})
}

// hysteriaConnect dials one real Hysteria2 session from sourceIP, opens a TCP
// stream to echoAddr, and returns the live client plus its stream. The caller
// owns closing both.
func hysteriaConnect(sourceIP string, port uint16, echoAddr, auth string) (hclient.Client, net.Conn, error) {
	client, _, err := hclient.NewClient(&hclient.Config{
		ConnFactory: sourceBoundConnFactory{source: sourceIP},
		ServerAddr:  &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: int(port)},
		Auth:        auth,
		TLSConfig: hclient.TLSConfig{
			ServerName:         "localhost",
			InsecureSkipVerify: true, // self-signed test certificate
		},
	})
	if err != nil {
		return nil, nil, err
	}
	conn, err := client.TCP(echoAddr)
	if err != nil {
		_ = client.Close()
		return nil, nil, err
	}
	return client, conn, nil
}

// hysteriaEchoOnce performs one real Hysteria2 session and returns nil only
// when the echo round trip succeeds.
func hysteriaEchoOnce(sourceIP string, port uint16, echoAddr, auth string) error {
	client, conn, err := hysteriaConnect(sourceIP, port, echoAddr, auth)
	if err != nil {
		return err
	}
	defer client.Close()
	defer conn.Close()

	if err := conn.SetDeadline(time.Now().Add(4 * time.Second)); err != nil {
		return err
	}
	if _, err := conn.Write([]byte("ping")); err != nil {
		return err
	}
	reply := make([]byte, 4)
	if _, err := io.ReadFull(conn, reply); err != nil {
		return err
	}
	if string(reply) != "ping" {
		return fmt.Errorf("echo reply = %q", reply)
	}
	return nil
}

// holdHysteriaConnection opens a real Hysteria2 session and keeps it open
// until the returned close function runs or the test ends.
func holdHysteriaConnection(t *testing.T, sourceIP string, port uint16, echoAddr, auth string) func() {
	t.Helper()
	client, conn, err := hysteriaConnect(sourceIP, port, echoAddr, auth)
	if err != nil {
		t.Fatalf("hold Hysteria2 connection: %v", err)
	}
	if _, err := conn.Write([]byte("ping")); err != nil {
		_ = conn.Close()
		_ = client.Close()
		t.Fatalf("idle hold write: %v", err)
	}
	reply := make([]byte, 4)
	if _, err := io.ReadFull(conn, reply); err != nil {
		_ = conn.Close()
		_ = client.Close()
		t.Fatalf("idle hold read: %v", err)
	}
	var once sync.Once
	closeFn := func() {
		once.Do(func() {
			_ = conn.Close()
			_ = client.Close()
		})
	}
	t.Cleanup(closeFn)
	return closeFn
}

func TestRedisGlobalAdmissionAcrossRealHysteria2Nodes(t *testing.T) {
	redisAddr := redisTestAddr(t)
	namespace := fmt.Sprintf("hysteria2-integration-%d", time.Now().UnixNano())
	echoAddr := startHysteriaEchoServer(t)
	users := []api.UserInfo{{UID: 42, UUID: "redis-user", Passwd: "redis-user-pass", DeviceLimit: 2}}

	portA := freeHysteriaPort(t)
	portB := freeHysteriaPort(t)
	nodeA := startHysteriaNode(t, redisAddr, namespace, "127.0.0.1", portA, users)
	nodeB := startHysteriaNode(t, redisAddr, namespace, "127.0.0.1", portB, users)

	// Two distinct source IPs consume the shared quota of two.
	if err := hysteriaEchoOnce("127.0.0.2", portA, echoAddr, "redis-user"); err != nil {
		t.Fatalf("first source IP on node A: %v", err)
	}
	if err := hysteriaEchoOnce("127.0.0.3", portB, echoAddr, "redis-user"); err != nil {
		t.Fatalf("second source IP on node B: %v", err)
	}

	// The same source IP is deduplicated across nodes, not counted twice.
	if err := hysteriaEchoOnce("127.0.0.2", portB, echoAddr, "redis-user"); err != nil {
		t.Fatalf("same source IP on node B: %v", err)
	}

	// A third distinct source IP exceeds the shared quota on either node.
	if err := hysteriaEchoOnce("127.0.0.4", portB, echoAddr, "redis-user"); err == nil {
		t.Fatal("third source IP was admitted on node B past the shared quota")
	}
	if err := hysteriaEchoOnce("127.0.0.4", portA, echoAddr, "redis-user"); err == nil {
		t.Fatal("third source IP was admitted on node A past the shared quota")
	}

	// An idle live connection keeps its lease across renewal windows. Hold one
	// connection per source IP, then sleep well past Expiry without traffic.
	closeA := holdHysteriaConnection(t, "127.0.0.2", portA, echoAddr, "redis-user")
	closeB := holdHysteriaConnection(t, "127.0.0.3", portB, echoAddr, "redis-user")
	closeSameIPA := holdHysteriaConnection(t, "127.0.0.2", portB, echoAddr, "redis-user")
	time.Sleep(4500 * time.Millisecond)
	if err := hysteriaEchoOnce("127.0.0.4", portB, echoAddr, "redis-user"); err == nil {
		t.Fatal("idle connection lease expired or renewal stopped")
	}

	// Closing one of two same-IP connections must keep the source IP live: the
	// surviving 127.0.0.2 session runs on node A while node B keeps 127.0.0.3.
	closeSameIPA()
	waitForHysteriaSessions(t, nodeB, 1)
	waitForHysteriaSessions(t, nodeA, 1)
	assertSessionOnline(t, nodeA, "127.0.0.2")
	assertSessionOnline(t, nodeB, "127.0.0.3")
	if err := hysteriaEchoOnce("127.0.0.4", portA, echoAddr, "redis-user"); err == nil {
		t.Fatal("source IP slot released while another same-IP session was still live")
	}

	// Last close stops renewal without deleting shared state; each lease then
	// expires by TTL and frees its slot.
	closeA()
	closeB()
	waitForHysteriaAdmission(t, echoAddr, "127.0.0.4", portB, 12*time.Second)
}

// waitForHysteriaSessions polls until a node tracks want live sessions.
func waitForHysteriaSessions(t *testing.T, svc *Hysteria2Service, want int) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		svc.mu.RLock()
		got := len(svc.sessions)
		svc.mu.RUnlock()
		if got == want {
			return
		}
		time.Sleep(50 * time.Millisecond)
	}
	svc.mu.RLock()
	got := len(svc.sessions)
	svc.mu.RUnlock()
	t.Fatalf("node sessions = %d, want %d", got, want)
}

// assertSessionOnline checks a node still reports the source IP as online.
func assertSessionOnline(t *testing.T, svc *Hysteria2Service, ip string) {
	t.Helper()
	svc.mu.RLock()
	live := svc.liveSessionIPsLocked()
	svc.mu.RUnlock()
	for _, ips := range live {
		for _, candidate := range ips {
			if candidate == ip {
				return
			}
		}
	}
	t.Fatalf("node no longer reports live session IP %s: %#v", ip, live)
}

// waitForHysteriaAdmission polls until a fresh source IP is admitted or the
// deadline passes.
func waitForHysteriaAdmission(t *testing.T, echoAddr, sourceIP string, port uint16, timeout time.Duration) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	var lastErr error
	for time.Now().Before(deadline) {
		lastErr = hysteriaEchoOnce(sourceIP, port, echoAddr, "redis-user")
		if lastErr == nil {
			return
		}
		time.Sleep(250 * time.Millisecond)
	}
	t.Fatalf("source IP %s was not admitted after lease expiry: %v", sourceIP, lastErr)
}

func freeHysteriaPort(t *testing.T) uint16 {
	t.Helper()
	conn, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	return uint16(conn.LocalAddr().(*net.UDPAddr).Port)
}

// startHysteriaEchoServer starts a loopback TCP echo server used as the
// Hysteria2 destination for real wire tests.
func startHysteriaEchoServer(t *testing.T) string {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = listener.Close() })
	go func() {
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			go func() {
				defer conn.Close()
				_, _ = io.Copy(conn, conn)
			}()
		}
	}()
	return listener.Addr().String()
}
