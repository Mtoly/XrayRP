package mylego

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestCertificateExpiryFromContentAndFile(t *testing.T) {
	first := time.Date(2026, 8, 1, 0, 0, 0, 0, time.UTC)
	second := first.Add(24 * time.Hour)
	bundle := append(testCertificatePEM(t, second), testCertificatePEM(t, first)...)

	contentExpiry, err := CertificateExpiry(&CertConfig{CertMode: "file", CertContent: string(bundle)})
	if err != nil {
		t.Fatalf("CertificateExpiry(content) error = %v", err)
	}
	if !contentExpiry.Equal(first) {
		t.Fatalf("content expiry = %v, want %v", contentExpiry, first)
	}

	path := filepath.Join(t.TempDir(), "node.crt")
	if err := os.WriteFile(path, bundle, 0o600); err != nil {
		t.Fatal(err)
	}
	fileExpiry, err := CertificateExpiry(&CertConfig{CertMode: "file", CertFile: path})
	if err != nil {
		t.Fatalf("CertificateExpiry(file) error = %v", err)
	}
	if !fileExpiry.Equal(first) {
		t.Fatalf("file expiry = %v, want %v", fileExpiry, first)
	}
}

func TestCertificateExpiryRejectsOversizedOrInvalidPEM(t *testing.T) {
	path := filepath.Join(t.TempDir(), "oversized.crt")
	if err := os.WriteFile(path, []byte(strings.Repeat("x", maxObservedCertificateBytes+1)), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := CertificateExpiry(&CertConfig{CertMode: "file", CertFile: path}); err == nil {
		t.Fatal("CertificateExpiry(oversized) error = nil")
	}
	if _, err := CertificateExpiry(&CertConfig{CertMode: "file", CertContent: "not pem"}); err == nil {
		t.Fatal("CertificateExpiry(invalid) error = nil")
	}
}

func testCertificatePEM(t *testing.T, notAfter time.Time) []byte {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 1024)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{
		SerialNumber: big.NewInt(notAfter.Unix()),
		Subject:      pkix.Name{CommonName: "node.example.com"},
		NotBefore:    notAfter.Add(-24 * time.Hour),
		NotAfter:     notAfter,
		KeyUsage:     x509.KeyUsageDigitalSignature,
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
}
