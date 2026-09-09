package mylego

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

func ContentCert(certConfig *CertConfig, identity ...string) (string, string, error) {
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
	contentIdentity := strings.Join(identity, "\x00")
	if strings.TrimSpace(contentIdentity) == "" {
		contentIdentity = strings.Join([]string{certConfig.CertDomain, certConfig.CertContent, certConfig.KeyContent}, "\x00")
	}
	fileBase := contentCertFileBase(certConfig.CertDomain, contentIdentity)
	certFile := filepath.Join(certDir, fileBase+".crt")
	keyFile := filepath.Join(certDir, fileBase+".key")

	err = executeCertificateOperation(nil, func() error {
		return writeFileTransaction([]fileTransactionEntry{
			{path: certFile, data: []byte(certConfig.CertContent), perm: filePerm},
			{path: keyFile, data: []byte(certConfig.KeyContent), perm: filePerm},
		}, nil)
	})
	if err != nil {
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
	if err := rejectSymlinkPathComponents(filepath.Join(certDir, ".panel-certificate")); err != nil {
		return "", err
	}
	if err := createDirectoryAllDurable(certDir, 0o700); err != nil {
		return "", err
	}
	return certDir, nil
}

func contentCertFileBase(domain, identity string) string {
	hash := sha256.Sum256([]byte(identity))
	return fmt.Sprintf("%s-%s", safeContentCertFileBase(domain), hex.EncodeToString(hash[:8]))
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
