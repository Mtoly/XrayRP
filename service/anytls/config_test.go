package anytls

import (
	"path/filepath"
	"testing"

	"github.com/Mtoly/XrayRP/common/mylego"
)

func TestCertMonitorAcquiresReloadLockBeforeReadingCertificateState(t *testing.T) {
	service := &AnyTLSService{}
	lockHeld := false
	service.beforeCertificateStateRead = func() {
		if service.reloadMu.TryLock() {
			service.reloadMu.Unlock()
			return
		}
		lockHeld = true
	}

	if err := service.certMonitor(); err != nil {
		t.Fatalf("certMonitor() error = %v", err)
	}
	if !lockHeld {
		t.Fatal("certMonitor read certificate state before acquiring reloadMu")
	}
}

func TestBuildSingBoxForUsesCandidateCertificatePEM(t *testing.T) {
	certificatePEM := []byte("candidate-certificate")
	privateKeyPEM := []byte("candidate-private-key")
	missingDir := t.TempDir()
	tlsOptions, err := buildInboundTLSOptions(runtimeBuildSpec{
		certConfig: &mylego.CertConfig{
			CertMode: "file",
			CertFile: filepath.Join(missingDir, "missing.crt"),
			KeyFile:  filepath.Join(missingDir, "missing.key"),
		},
		certificatePEM: certificatePEM,
		privateKeyPEM:  privateKeyPEM,
	})
	if err != nil {
		t.Fatalf("buildInboundTLSOptions() error = %v", err)
	}
	if len(tlsOptions.Certificate) != 1 || tlsOptions.Certificate[0] != string(certificatePEM) {
		t.Fatalf("TLS Certificate = %q, want candidate PEM", tlsOptions.Certificate)
	}
	if len(tlsOptions.Key) != 1 || tlsOptions.Key[0] != string(privateKeyPEM) {
		t.Fatalf("TLS Key = %q, want candidate PEM", tlsOptions.Key)
	}
	if tlsOptions.CertificatePath != "" || tlsOptions.KeyPath != "" {
		t.Fatalf("candidate TLS options published file paths %q/%q", tlsOptions.CertificatePath, tlsOptions.KeyPath)
	}
}
