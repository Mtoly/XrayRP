package controller

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/pem"
	"errors"
	"math/big"
	"testing"
	"time"

	xraytls "github.com/xtls/xray-core/transport/internet/tls"
)

func TestXrayTLSDefaultRootsExcludeDistrustedEmSign(t *testing.T) {
	pool := (&xraytls.Config{}).GetTLSConfig().RootCAs
	if pool == nil {
		t.Fatal("default Xray TLS roots unexpectedly use the platform verifier")
	}
	distrusted := map[string]bool{
		"emSign ECC Root CA - C3": true,
		"emSign ECC Root CA - G3": true,
		"emSign Root CA - C1":     true,
	}
	retained := false
	// Inspect the effective pool without relying on the host's trust store or external TLS endpoints.
	for _, subject := range pool.Subjects() {
		var sequence pkix.RDNSequence
		if _, err := asn1.Unmarshal(subject, &sequence); err != nil {
			t.Fatalf("decode root subject: %v", err)
		}
		var name pkix.Name
		name.FillFromRDNSequence(&sequence)
		if distrusted[name.CommonName] {
			t.Errorf("default Xray TLS pool still trusts %s", name.CommonName)
		}
		if name.CommonName == "ISRG Root X1" {
			retained = true
		}
	}
	if !retained {
		t.Fatal("default Xray TLS pool lost ISRG Root X1")
	}
}

func TestXrayTLSExplicitCAPreservesCertificateVerification(t *testing.T) {
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	caTemplate := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "XrayRP test CA"},
		NotBefore:             now.Add(-time.Hour),
		NotAfter:              now.Add(time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign,
	}
	caDER, err := x509.CreateCertificate(rand.Reader, caTemplate, caTemplate, publicKey, privateKey)
	if err != nil {
		t.Fatal(err)
	}
	ca, err := x509.ParseCertificate(caDER)
	if err != nil {
		t.Fatal(err)
	}
	leafTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(2),
		DNSNames:     []string{"outbound.example"},
		NotBefore:    ca.NotBefore,
		NotAfter:     ca.NotAfter,
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	leafDER, err := x509.CreateCertificate(rand.Reader, leafTemplate, ca, publicKey, privateKey)
	if err != nil {
		t.Fatal(err)
	}
	leaf, err := x509.ParseCertificate(leafDER)
	if err != nil {
		t.Fatal(err)
	}
	options := x509.VerifyOptions{
		DNSName:     "outbound.example",
		CurrentTime: now,
		Roots:       (&xraytls.Config{}).GetTLSConfig().RootCAs,
	}
	var unknownAuthority x509.UnknownAuthorityError
	if _, err := leaf.Verify(options); !errors.As(err, &unknownAuthority) {
		t.Fatalf("private CA without explicit trust: got %v, want unknown authority", err)
	}
	for _, test := range []struct {
		name     string
		isolated bool
	}{
		{name: "append to default roots"},
		{name: "explicit roots only", isolated: true},
	} {
		t.Run(test.name, func(t *testing.T) {
			config := (&xraytls.Config{
				DisableSystemRoot: test.isolated,
				Certificate: []*xraytls.Certificate{{
					Certificate: pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: caDER}),
					Usage:       xraytls.Certificate_AUTHORITY_VERIFY,
				}},
			}).GetTLSConfig()
			if config.RootCAs == nil || config.InsecureSkipVerify {
				t.Fatal("explicit CA did not preserve verified TLS with an explicit root pool")
			}
			opts := options
			opts.Roots = config.RootCAs
			if _, err := leaf.Verify(opts); err != nil {
				t.Fatalf("verify leaf with explicit CA: %v", err)
			}
			opts.DNSName = "other.example"
			var hostnameError x509.HostnameError
			if _, err := leaf.Verify(opts); !errors.As(err, &hostnameError) {
				t.Fatalf("wrong hostname: got %v, want hostname error", err)
			}
		})
	}
}
