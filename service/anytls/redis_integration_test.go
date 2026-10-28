package anytls

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"io"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"sync"
	"testing"
	"time"

	anytlsclient "github.com/anytls/sing-anytls"
	"github.com/sagernet/sing/common/logger"
	M "github.com/sagernet/sing/common/metadata"

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

// startAnyTLSNode starts one real AnyTLS service instance that shares the
// supplied Redis namespace. Each call represents one node.
func startAnyTLSNode(t *testing.T, redisAddr, namespace, listenIP string, port uint16, users []api.UserInfo) *AnyTLSService {
	t.Helper()
	client := &configurablePanelClient{
		nodeInfo: &api.NodeInfo{
			NodeType:     "AnyTLS",
			NodeID:       7,
			Port:         uint32(port),
			EnableTLS:    true,
			AnyTLSConfig: &api.AnyTLSConfig{},
		},
		users: users,
	}
	svc := New(client, &controller.Config{
		ListenIP:       listenIP,
		UpdatePeriodic: 3600,
		DisableGetRule: true,
		CertConfig: &mylego.CertConfig{
			CertMode:    "file",
			CertDomain:  "127.0.0.1",
			CertFile:    anyTLSTestCertFile(t),
			KeyFile:     anyTLSTestKeyFile(t),
			CertContent: "",
			KeyContent:  "",
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
		t.Fatalf("AnyTLS node start on %s:%d: %v", listenIP, port, err)
	}
	t.Cleanup(func() {
		if err := svc.Close(); err != nil {
			t.Errorf("AnyTLS node close: %v", err)
		}
	})
	return svc
}

// anyTLSConnectOnce performs one real AnyTLS session from sourceIP to node
// and returns nil only when the echo round trip succeeds.
func anyTLSConnectOnce(sourceIP, nodeIP string, port uint16, echoAddr, password string) error {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	serverAddr := net.JoinHostPort(nodeIP, strconv.Itoa(int(port)))
	client, err := anytlsclient.NewClient(ctx, anytlsclient.ClientConfig{
		Password: password,
		DialOut: func(ctx context.Context) (net.Conn, error) {
			dialer := net.Dialer{
				Timeout:   4 * time.Second,
				LocalAddr: &net.TCPAddr{IP: net.ParseIP(sourceIP)},
			}
			raw, err := dialer.DialContext(ctx, "tcp", serverAddr)
			if err != nil {
				return nil, err
			}
			tlsConn := tls.Client(raw, &tls.Config{
				InsecureSkipVerify: true, // self-signed test certificate
				ServerName:         nodeIP,
				MinVersion:         tls.VersionTLS12,
			})
			if err := tlsConn.HandshakeContext(ctx); err != nil {
				_ = raw.Close()
				return nil, err
			}
			return tlsConn, nil
		},
		Logger: logger.NOP(),
	})
	if err != nil {
		return err
	}
	defer client.Close()
	conn, err := client.CreateProxy(ctx, M.ParseSocksaddr(echoAddr))
	if err != nil {
		return err
	}
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

// holdAnyTLSConnection opens a real AnyTLS session and keeps it open until
// the returned close function runs or the test ends.
func holdAnyTLSConnection(t *testing.T, sourceIP, nodeIP string, port uint16, echoAddr, password string) func() {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	serverAddr := net.JoinHostPort(nodeIP, strconv.Itoa(int(port)))
	client, err := anytlsclient.NewClient(ctx, anytlsclient.ClientConfig{
		Password: password,
		DialOut: func(ctx context.Context) (net.Conn, error) {
			dialer := net.Dialer{
				Timeout:   4 * time.Second,
				LocalAddr: &net.TCPAddr{IP: net.ParseIP(sourceIP)},
			}
			raw, err := dialer.DialContext(ctx, "tcp", serverAddr)
			if err != nil {
				return nil, err
			}
			tlsConn := tls.Client(raw, &tls.Config{
				InsecureSkipVerify: true, // self-signed test certificate
				ServerName:         nodeIP,
				MinVersion:         tls.VersionTLS12,
			})
			if err := tlsConn.HandshakeContext(ctx); err != nil {
				_ = raw.Close()
				return nil, err
			}
			return tlsConn, nil
		},
		Logger: logger.NOP(),
	})
	if err != nil {
		cancel()
		t.Fatalf("AnyTLS client: %v", err)
	}
	conn, err := client.CreateProxy(ctx, M.ParseSocksaddr(echoAddr))
	if err != nil {
		cancel()
		client.Close()
		t.Fatalf("AnyTLS proxy session: %v", err)
	}
	if _, err := conn.Write([]byte("ping")); err != nil {
		cancel()
		conn.Close()
		client.Close()
		t.Fatalf("AnyTLS idle hold write: %v", err)
	}
	reply := make([]byte, 4)
	if _, err := io.ReadFull(conn, reply); err != nil {
		cancel()
		conn.Close()
		client.Close()
		t.Fatalf("AnyTLS idle hold read: %v", err)
	}
	closeOnce := func() {
		_ = conn.Close()
		_ = client.Close()
		cancel()
	}
	t.Cleanup(closeOnce)
	return closeOnce
}

func TestRedisGlobalAdmissionAcrossRealAnyTLSNodes(t *testing.T) {
	redisAddr := redisTestAddr(t)
	namespace := fmt.Sprintf("anytls-integration-%d", time.Now().UnixNano())
	echoAddr := startEchoServer(t)
	users := []api.UserInfo{{UID: 42, UUID: "redis-user", Passwd: "redis-user-pass", DeviceLimit: 1}}

	portA := freePort(t, "tcp")
	portB := freePort(t, "tcp")
	startAnyTLSNode(t, redisAddr, namespace, "127.0.0.1", portA, users)
	startAnyTLSNode(t, redisAddr, namespace, "127.0.0.2", portB, users)

	// Node A keeps one real connection open for the whole assertion window, so
	// its lease must be renewed and the shared quota must hold across nodes.
	closeIdle := holdAnyTLSConnection(t, "127.0.0.2", "127.0.0.1", portA, echoAddr, "redis-user")

	// The same source IP is deduplicated across nodes, not counted twice.
	if err := anyTLSConnectOnce("127.0.0.2", "127.0.0.2", portB, echoAddr, "redis-user"); err != nil {
		t.Fatalf("same source IP on node B: %v", err)
	}

	// A second distinct source IP exceeds the shared quota on either node.
	if err := anyTLSConnectOnce("127.0.0.3", "127.0.0.2", portB, echoAddr, "redis-user"); err == nil {
		t.Fatal("second source IP was admitted on node B past the shared quota")
	}
	if err := anyTLSConnectOnce("127.0.0.3", "127.0.0.1", portA, echoAddr, "redis-user"); err == nil {
		t.Fatal("second source IP was admitted on node A past the shared quota")
	}

	// An idle live connection keeps its lease across renewal windows.
	time.Sleep(4500 * time.Millisecond)
	if err := anyTLSConnectOnce("127.0.0.3", "127.0.0.2", portB, echoAddr, "redis-user"); err == nil {
		t.Fatal("idle connection lease expired or renewal stopped")
	}

	// Last close stops renewal without deleting shared state; the lease then
	// expires and frees the slot for another source IP.
	closeIdle()
	waitForAnyTLSAdmission(t, echoAddr, "127.0.0.3", portB, 12*time.Second)
}

// waitForAnyTLSAdmission polls until a fresh source IP is admitted or the
// deadline passes.
func waitForAnyTLSAdmission(t *testing.T, echoAddr, sourceIP string, port uint16, timeout time.Duration) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	var lastErr error
	for time.Now().Before(deadline) {
		lastErr = anyTLSConnectOnce(sourceIP, "127.0.0.2", port, echoAddr, "redis-user")
		if lastErr == nil {
			return
		}
		time.Sleep(250 * time.Millisecond)
	}
	t.Fatalf("source IP %s was not admitted after lease expiry: %v", sourceIP, lastErr)
}

func freePort(t *testing.T, network string) uint16 {
	t.Helper()
	if network == "tcp" {
		listener, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		defer listener.Close()
		return uint16(listener.Addr().(*net.TCPAddr).Port)
	}
	conn, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	return uint16(conn.LocalAddr().(*net.UDPAddr).Port)
}

var (
	anyTLSTestCertOnce sync.Once
	anyTLSTestCertPath string
	anyTLSTestKeyPath  string
	anyTLSTestCertErr  error
)

// anyTLSTestCertFile returns a shared self-signed certificate for the real
// integration nodes. The certificate is generated once per test binary.
func anyTLSTestCertFile(t *testing.T) string {
	t.Helper()
	anyTLSTestCertOnce.Do(func() {
		dir, err := os.MkdirTemp("", "xrayrp-anytls-integration-")
		if err != nil {
			anyTLSTestCertErr = err
			return
		}
		anyTLSTestCertPath = filepath.Join(dir, "cert.pem")
		anyTLSTestKeyPath = filepath.Join(dir, "key.pem")
		certPEM, keyPEM, err := generateSelfSignedCertificate()
		if err != nil {
			anyTLSTestCertErr = err
			return
		}
		if err := os.WriteFile(anyTLSTestCertPath, certPEM, 0o600); err != nil {
			anyTLSTestCertErr = err
			return
		}
		anyTLSTestCertErr = os.WriteFile(anyTLSTestKeyPath, keyPEM, 0o600)
	})
	if anyTLSTestCertErr != nil {
		t.Fatalf("generate integration certificate: %v", anyTLSTestCertErr)
	}
	return anyTLSTestCertPath
}

func anyTLSTestKeyFile(t *testing.T) string {
	t.Helper()
	anyTLSTestCertFile(t)
	return anyTLSTestKeyPath
}

func generateSelfSignedCertificate() ([]byte, []byte, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, nil, err
	}
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "127.0.0.1"},
		NotBefore:    time.Now().Add(-time.Minute),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		IPAddresses:  []net.IP{net.ParseIP("127.0.0.1"), net.ParseIP("127.0.0.2")},
	}
	certificateDER, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		return nil, nil, err
	}
	keyDER, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return nil, nil, err
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certificateDER}),
		pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER}), nil
}

// startEchoServer starts a loopback TCP echo server used as the AnyTLS
// destination for real wire tests.
func startEchoServer(t *testing.T) string {
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
