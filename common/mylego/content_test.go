package mylego

import (
	"os"
	"path/filepath"
	"testing"
)

func TestContentCertWritesPanelProvidedPEM(t *testing.T) {
	configDir := t.TempDir()
	t.Setenv("XRAY_LOCATION_CONFIG", configDir)
	certConfig := &CertConfig{
		CertDomain:  "*.example.com/edge:443",
		CertContent: "-----BEGIN CERTIFICATE-----\ncert\n-----END CERTIFICATE-----\n",
		KeyContent:  "-----BEGIN PRIVATE KEY-----\nkey\n-----END PRIVATE KEY-----\n",
	}

	certFile, keyFile, err := ContentCert(certConfig)
	if err != nil {
		t.Fatalf("ContentCert returned error: %v", err)
	}

	wantCertFile := filepath.Join(configDir, "cert", "panel", "_.example.com_edge_443.crt")
	wantKeyFile := filepath.Join(configDir, "cert", "panel", "_.example.com_edge_443.key")
	if certFile != wantCertFile || keyFile != wantKeyFile {
		t.Fatalf("unexpected cert files: cert=%q key=%q", certFile, keyFile)
	}
	assertFileContent(t, certFile, certConfig.CertContent)
	assertFileContent(t, keyFile, certConfig.KeyContent)
}

func TestContentCertRejectsMissingContent(t *testing.T) {
	_, _, err := ContentCert(&CertConfig{CertContent: "cert only"})
	if err == nil {
		t.Fatal("expected missing key content error")
	}
}

func TestContentCertUsesFallbackFileBase(t *testing.T) {
	configDir := t.TempDir()
	t.Setenv("XRAY_LOCATION_CONFIG", configDir)
	certFile, keyFile, err := ContentCert(&CertConfig{
		CertDomain:  " .. ",
		CertContent: "cert",
		KeyContent:  "key",
	})
	if err != nil {
		t.Fatalf("ContentCert returned error: %v", err)
	}

	if certFile != filepath.Join(configDir, "cert", "panel", "panel.crt") || keyFile != filepath.Join(configDir, "cert", "panel", "panel.key") {
		t.Fatalf("expected fallback panel file base, got cert=%q key=%q", certFile, keyFile)
	}
}

func assertFileContent(t *testing.T, path, want string) {
	t.Helper()
	content, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	if string(content) != want {
		t.Fatalf("unexpected file content for %s: %q", path, content)
	}
}
