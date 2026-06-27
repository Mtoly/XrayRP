package mylego

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

func ContentCert(certConfig *CertConfig) (string, string, error) {
	if certConfig == nil {
		return "", "", fmt.Errorf("CertConfig is nil")
	}
	if strings.TrimSpace(certConfig.CertContent) == "" || strings.TrimSpace(certConfig.KeyContent) == "" {
		return "", "", fmt.Errorf("cert_mode content requires both cert_content and key_content")
	}

	certDir, err := panelContentCertDir()
	if err != nil {
		return "", "", err
	}
	fileBase := safeContentCertFileBase(certConfig.CertDomain)
	certFile := filepath.Join(certDir, fileBase+".crt")
	keyFile := filepath.Join(certDir, fileBase+".key")

	if err := os.WriteFile(certFile, []byte(certConfig.CertContent), filePerm); err != nil {
		return "", "", err
	}
	if err := os.WriteFile(keyFile, []byte(certConfig.KeyContent), filePerm); err != nil {
		return "", "", err
	}
	return certFile, keyFile, nil
}

func panelContentCertDir() (string, error) {
	basePath := os.Getenv("XRAY_LOCATION_CONFIG")
	if basePath == "" {
		cwd, err := os.Getwd()
		if err != nil {
			basePath = "."
		} else {
			basePath = cwd
		}
	}
	certDir := filepath.Join(basePath, "cert", "panel")
	if err := os.MkdirAll(certDir, 0o700); err != nil {
		return "", err
	}
	return certDir, nil
}

func safeContentCertFileBase(domain string) string {
	replacer := strings.NewReplacer("*", "_", "/", "_", "\\", "_", ":", "_", "?", "_", "\"", "_", "<", "_", ">", "_", "|", "_")
	base := strings.Trim(replacer.Replace(strings.TrimSpace(domain)), " .")
	base = strings.ReplaceAll(base, "..", "_")
	if base == "" || base == "." || base == ".." {
		return "panel"
	}
	return base
}
