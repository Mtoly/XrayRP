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

	if filepath.Base(certFile) == "_.example.com_edge_443.crt" || filepath.Base(keyFile) == "_.example.com_edge_443.key" {
		t.Fatalf("expected content certificate paths to include an isolation suffix: cert=%q key=%q", certFile, keyFile)
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

	if filepath.Base(certFile) == "panel.crt" || filepath.Base(keyFile) == "panel.key" {
		t.Fatalf("expected fallback content certificate paths to include an isolation suffix, got cert=%q key=%q", certFile, keyFile)
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

func TestContentCertIsolatesIdentitiesAndSanitizedDomains(t *testing.T) {
	configDir := t.TempDir()
	t.Setenv("XRAY_LOCATION_CONFIG", configDir)
	first := &CertConfig{CertDomain: "a/b", CertContent: "cert-A", KeyContent: "key-A"}
	second := &CertConfig{CertDomain: "a?b", CertContent: "cert-B", KeyContent: "key-B"}
	firstCert, firstKey, err := ContentCert(first, "panel-A", "node-1")
	if err != nil {
		t.Fatal(err)
	}
	secondCert, secondKey, err := ContentCert(second, "panel-B", "node-2")
	if err != nil {
		t.Fatal(err)
	}
	if firstCert == secondCert || firstKey == secondKey {
		t.Fatalf("content certificate identities collided: first=(%q,%q) second=(%q,%q)", firstCert, firstKey, secondCert, secondKey)
	}
	assertFileContent(t, firstCert, first.CertContent)
	assertFileContent(t, firstKey, first.KeyContent)
	assertFileContent(t, secondCert, second.CertContent)
	assertFileContent(t, secondKey, second.KeyContent)
}

func TestContentCertIdentityIsStable(t *testing.T) {
	configDir := t.TempDir()
	t.Setenv("XRAY_LOCATION_CONFIG", configDir)
	config := &CertConfig{CertDomain: "node.example.com", CertContent: "cert", KeyContent: "key"}
	firstCert, firstKey, err := ContentCert(config, "panel", "node")
	if err != nil {
		t.Fatal(err)
	}
	secondCert, secondKey, err := ContentCert(config, "panel", "node")
	if err != nil {
		t.Fatal(err)
	}
	if firstCert != secondCert || firstKey != secondKey {
		t.Fatalf("content certificate identity is unstable: first=(%q,%q) second=(%q,%q)", firstCert, firstKey, secondCert, secondKey)
	}
}
