//go:build with_quic

package singboxregistry

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"net"
	"net/netip"
	"testing"
	"time"

	"github.com/gofrs/uuid/v5"
	box "github.com/sagernet/sing-box"
	"github.com/sagernet/sing-box/common/tls"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing-quic/tuic"
	"github.com/sagernet/sing/common/json/badoption"
	"github.com/sagernet/sing/common/logger"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
)

func TestTUICInboundAppliesUserUpdatesWhileRunning(t *testing.T) {
	const (
		oldUUID = "11111111-1111-1111-1111-111111111111"
		newUUID = "22222222-2222-2222-2222-222222222222"
	)
	echoAddr := startEchoServer(t)
	certificatePEM, keyPEM := testCertificatePEM(t)
	listenAddr := netip.MustParseAddr("127.0.0.1")
	port := freeUDPPort(t)
	instance, err := box.New(box.Options{
		Context: WithFullRegistry(context.Background()),
		Options: option.Options{
			Log: &option.LogOptions{Disabled: true},
			Inbounds: []option.Inbound{{
				Type: C.TypeTUIC,
				Tag:  "tuic-in",
				Options: &option.TUICInboundOptions{
					ListenOptions: option.ListenOptions{
						Listen:     (*badoption.Addr)(&listenAddr),
						ListenPort: port,
					},
					Users: []option.TUICUser{{Name: oldUUID, UUID: oldUUID, Password: oldUUID}},
					InboundTLSOptionsContainer: option.InboundTLSOptionsContainer{TLS: &option.InboundTLSOptions{
						Enabled:     true,
						ALPN:        badoption.Listable[string]{"h3"},
						Certificate: badoption.Listable[string]{certificatePEM},
						Key:         badoption.Listable[string]{keyPEM},
					}},
				},
			}},
			Outbounds: []option.Outbound{{Type: C.TypeDirect, Tag: "direct", Options: &option.DirectOutboundOptions{}}},
		},
	})
	if err != nil {
		t.Fatalf("box.New() error = %v", err)
	}
	if err := instance.Start(); err != nil {
		t.Fatalf("box.Start() error = %v", err)
	}
	t.Cleanup(func() {
		if err := instance.Close(); err != nil {
			t.Errorf("box.Close() error = %v", err)
		}
	})
	registered, _ := instance.Inbound().Get("tuic-in")
	inbound, ok := registered.(*TUICInbound)
	if !ok {
		t.Fatalf("registered TUIC inbound = %T, want *TUICInbound", registered)
	}
	serverAddr := M.SocksaddrFrom(listenAddr, port)

	if err := tuicEcho(serverAddr, oldUUID, echoAddr); err != nil {
		t.Fatalf("initial user: %v", err)
	}
	if err := tuicEcho(serverAddr, newUUID, echoAddr); err == nil {
		t.Fatal("new user connected before the user update")
	}
	if err := inbound.UpdateUsers([]option.TUICUser{{Name: newUUID, UUID: newUUID, Password: newUUID}}); err != nil {
		t.Fatalf("UpdateUsers() error = %v", err)
	}
	if err := tuicEcho(serverAddr, newUUID, echoAddr); err != nil {
		t.Fatalf("new user after update: %v", err)
	}
	if err := tuicEcho(serverAddr, oldUUID, echoAddr); err == nil {
		t.Fatal("removed user still connected after the user update")
	}
	if err := inbound.UpdateUsers([]option.TUICUser{{Name: "bad", UUID: "not-a-uuid"}}); err == nil {
		t.Fatal("UpdateUsers() accepted an invalid UUID")
	}
	if err := tuicEcho(serverAddr, newUUID, echoAddr); err != nil {
		t.Fatalf("rejected update replaced the user table: %v", err)
	}
}

func tuicEcho(serverAddr M.Socksaddr, userUUID, echoAddr string) error {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	tlsConfig, err := tls.NewClient(ctx, logger.NOP(), serverAddr.AddrString(), option.OutboundTLSOptions{
		Enabled:  true,
		Insecure: true,
		ALPN:     badoption.Listable[string]{"h3"},
	})
	if err != nil {
		return err
	}
	client, err := tuic.NewClient(tuic.ClientOptions{
		Context:       ctx,
		Dialer:        N.SystemDialer,
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
	return echoRoundTrip(conn)
}

func testCertificatePEM(t *testing.T) (string, string) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "127.0.0.1"},
		NotBefore:    time.Now().Add(-time.Minute),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		IPAddresses:  []net.IP{net.ParseIP("127.0.0.1")},
	}
	certificateDER, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	keyDER, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certificateDER})),
		string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER}))
}

func freeUDPPort(t *testing.T) uint16 {
	t.Helper()
	conn, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	return uint16(conn.LocalAddr().(*net.UDPAddr).Port)
}
