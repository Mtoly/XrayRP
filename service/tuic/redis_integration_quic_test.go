//go:build with_quic

package tuic

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/gofrs/uuid/v5"
	"github.com/sagernet/sing-box/common/tls"
	"github.com/sagernet/sing-box/option"
	tuicclient "github.com/sagernet/sing-quic/tuic"
	"github.com/sagernet/sing/common/json/badoption"
	"github.com/sagernet/sing/common/logger"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"

	"github.com/Mtoly/XrayRP/api"
	commonlimiter "github.com/Mtoly/XrayRP/common/limiter"
	"github.com/Mtoly/XrayRP/common/mylego"
	"github.com/Mtoly/XrayRP/service/controller"
)

const tuicRedisIntegrationEnv = "XRAYRP_RUN_REDIS_INTEGRATION"

func tuicRedisTestAddr(t *testing.T) string {
	t.Helper()
	if os.Getenv(tuicRedisIntegrationEnv) != "1" {
		t.Skip("skipping Redis integration test; set XRAYRP_RUN_REDIS_INTEGRATION=1 to enable")
	}
	if addr := os.Getenv("XRAYRP_REDIS_ADDR"); addr != "" {
		return addr
	}
	return "127.0.0.1:16379"
}

// localAddrDialer dials QUIC from a specific loopback source address so a
// single host can present distinct client source IPs.
type localAddrDialer struct {
	sourceIP string
}

func (d localAddrDialer) DialContext(ctx context.Context, network string, destination M.Socksaddr) (net.Conn, error) {
	dialer := net.Dialer{LocalAddr: &net.UDPAddr{IP: net.ParseIP(d.sourceIP)}}
	return dialer.DialContext(ctx, "udp", destination.String())
}

func (d localAddrDialer) ListenPacket(ctx context.Context, _ M.Socksaddr) (net.PacketConn, error) {
	listenConfig := net.ListenConfig{}
	return listenConfig.ListenPacket(ctx, "udp", net.JoinHostPort(d.sourceIP, "0"))
}

func startTUICNode(t *testing.T, redisAddr, namespace, listenIP string, port uint16, users []api.UserInfo) *TuicService {
	t.Helper()
	client := &configurablePanelClient{
		nodeInfo: &api.NodeInfo{
			NodeType:   "Tuic",
			NodeID:     7,
			Port:       uint32(port),
			EnableTLS:  true,
			TuicConfig: &api.TuicConfig{ALPN: []string{"h3"}},
		},
		users: users,
	}
	svc := New(client, &controller.Config{
		ListenIP:       listenIP,
		UpdatePeriodic: 3600,
		DisableGetRule: true,
		CertConfig: &mylego.CertConfig{
			CertMode: "file",
			CertFile: tuicTestCertFile(t),
			KeyFile:  tuicTestKeyFile(t),
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
		t.Fatalf("TUIC node start on %s:%d: %v", listenIP, port, err)
	}
	t.Cleanup(func() {
		if err := svc.Close(); err != nil {
			t.Errorf("TUIC node close: %v", err)
		}
	})
	return svc
}

func tuicConnectOnce(sourceIP, nodeIP string, port uint16, echoAddr, userUUID string) error {
	ctx, cancel := context.WithTimeout(context.Background(), 6*time.Second)
	defer cancel()
	serverAddr := M.SocksaddrFrom(netip.MustParseAddr(nodeIP), port)
	tlsConfig, err := tls.NewClient(ctx, logger.NOP(), serverAddr.AddrString(), option.OutboundTLSOptions{
		Enabled:  true,
		Insecure: true,
		ALPN:     badoption.Listable[string]{"h3"},
	})
	if err != nil {
		return err
	}
	client, err := tuicclient.NewClient(tuicclient.ClientOptions{
		Context:       ctx,
		Dialer:        localAddrDialer{sourceIP: sourceIP},
		ServerAddress: serverAddr,
		TLSConfig:     tlsConfig,
		UUID:          uuid.Must(uuid.FromString(userUUID)),
		Password:      userUUID,
	})
	if err != nil {
		return err
	}
	defer client.CloseWithError(nil)
	conn, err := client.DialConn(ctx, M.ParseSocksaddr(echoAddr))
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

func TestRedisGlobalAdmissionAcrossRealTUICNodes(t *testing.T) {
	redisAddr := tuicRedisTestAddr(t)
	const userUUID = "33333333-3333-3333-3333-333333333333"
	namespace := fmt.Sprintf("tuic-integration-%d", time.Now().UnixNano())
	echoAddr := startTUICTestEchoServer(t)
	users := []api.UserInfo{{UID: 51, UUID: userUUID, Passwd: userUUID, DeviceLimit: 1}}

	portA := freeUDPTestPort(t)
	portB := freeUDPTestPort(t)
	startTUICNode(t, redisAddr, namespace, "127.0.0.1", portA, users)
	startTUICNode(t, redisAddr, namespace, "127.0.0.2", portB, users)

	// Node A keeps one real TUIC connection open for the assertion window, so
	// its lease must be renewed and the shared quota must hold across nodes.
	closeIdle := holdTUICConnection(t, "127.0.0.2", "127.0.0.1", portA, echoAddr, userUUID)

	if err := tuicConnectOnce("127.0.0.2", "127.0.0.2", portB, echoAddr, userUUID); err != nil {
		t.Fatalf("same source IP on node B: %v", err)
	}
	if err := tuicConnectOnce("127.0.0.3", "127.0.0.2", portB, echoAddr, userUUID); err == nil {
		t.Fatal("second source IP was admitted on node B past the shared quota")
	}
	if err := tuicConnectOnce("127.0.0.3", "127.0.0.1", portA, echoAddr, userUUID); err == nil {
		t.Fatal("second source IP was admitted on node A past the shared quota")
	}

	// An idle live connection keeps its lease across renewal windows.
	time.Sleep(4500 * time.Millisecond)
	if err := tuicConnectOnce("127.0.0.3", "127.0.0.2", portB, echoAddr, userUUID); err == nil {
		t.Fatal("idle connection lease expired or renewal stopped")
	}
	closeIdle()

	// Last close stops renewal without deleting shared state; the lease then
	// expires and frees the slot for a fresh source IP.
	deadline := time.Now().Add(12 * time.Second)
	var lastErr error
	for time.Now().Before(deadline) {
		if lastErr = tuicConnectOnce("127.0.0.3", "127.0.0.2", portB, echoAddr, userUUID); lastErr == nil {
			break
		}
		time.Sleep(250 * time.Millisecond)
	}
	if lastErr != nil {
		t.Fatalf("source IP was not admitted after lease expiry: %v", lastErr)
	}
}

// holdTUICConnection opens one real TUIC session and keeps it open until the
// returned close function runs or the test ends.
func holdTUICConnection(t *testing.T, sourceIP, nodeIP string, port uint16, echoAddr, userUUID string) func() {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	serverAddr := M.SocksaddrFrom(netip.MustParseAddr(nodeIP), port)
	tlsConfig, err := tls.NewClient(ctx, logger.NOP(), serverAddr.AddrString(), option.OutboundTLSOptions{
		Enabled:  true,
		Insecure: true,
		ALPN:     badoption.Listable[string]{"h3"},
	})
	if err != nil {
		cancel()
		t.Fatalf("TUIC TLS client: %v", err)
	}
	client, err := tuicclient.NewClient(tuicclient.ClientOptions{
		Context:       ctx,
		Dialer:        localAddrDialer{sourceIP: sourceIP},
		ServerAddress: serverAddr,
		TLSConfig:     tlsConfig,
		UUID:          uuid.Must(uuid.FromString(userUUID)),
		Password:      userUUID,
	})
	if err != nil {
		cancel()
		t.Fatalf("TUIC client: %v", err)
	}
	conn, err := client.DialConn(ctx, M.ParseSocksaddr(echoAddr))
	if err != nil {
		cancel()
		client.CloseWithError(nil)
		t.Fatalf("TUIC idle hold dial: %v", err)
	}
	if _, err := conn.Write([]byte("ping")); err != nil {
		cancel()
		conn.Close()
		client.CloseWithError(nil)
		t.Fatalf("TUIC idle hold write: %v", err)
	}
	reply := make([]byte, 4)
	if _, err := io.ReadFull(conn, reply); err != nil {
		cancel()
		conn.Close()
		client.CloseWithError(nil)
		t.Fatalf("TUIC idle hold read: %v", err)
	}
	closeOnce := func() {
		_ = conn.Close()
		client.CloseWithError(nil)
		cancel()
	}
	t.Cleanup(closeOnce)
	return closeOnce
}

func startTUICTestEchoServer(t *testing.T) string {
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

func freeUDPTestPort(t *testing.T) uint16 {
	t.Helper()
	conn, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	return uint16(conn.LocalAddr().(*net.UDPAddr).Port)
}

var (
	tuicTestCertOnce sync.Once
	tuicTestCertPath string
	tuicTestKeyPath  string
	tuicTestCertErr  error
)

func tuicTestCertFile(t *testing.T) string {
	t.Helper()
	tuicTestCertOnce.Do(func() {
		dir, err := os.MkdirTemp("", "xrayrp-tuic-integration-")
		if err != nil {
			tuicTestCertErr = err
			return
		}
		tuicTestCertPath = filepath.Join(dir, "cert.pem")
		tuicTestKeyPath = filepath.Join(dir, "key.pem")
		certPEM, keyPEM, err := generateTUICSelfSignedCertificate()
		if err != nil {
			tuicTestCertErr = err
			return
		}
		if err := os.WriteFile(tuicTestCertPath, certPEM, 0o600); err != nil {
			tuicTestCertErr = err
			return
		}
		tuicTestCertErr = os.WriteFile(tuicTestKeyPath, keyPEM, 0o600)
	})
	if tuicTestCertErr != nil {
		t.Fatalf("generate integration certificate: %v", tuicTestCertErr)
	}
	return tuicTestCertPath
}

func tuicTestKeyFile(t *testing.T) string {
	t.Helper()
	tuicTestCertFile(t)
	return tuicTestKeyPath
}

func generateTUICSelfSignedCertificate() ([]byte, []byte, error) {
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

var _ N.Dialer = localAddrDialer{}
