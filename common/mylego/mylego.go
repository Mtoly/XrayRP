package mylego

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

var errCertificateFilesMissing = errors.New("certificate files are missing")

func New(certConf *CertConfig) (*LegoCMD, error) {
	if certConf == nil {
		return nil, errors.New("certificate config is nil")
	}
	// Set default path to configPath/cert
	var p = ""
	configPath := os.Getenv("XRAY_LOCATION_CONFIG")
	if configPath != "" {
		p = configPath
	} else if cwd, err := os.Getwd(); err == nil {
		p = cwd
	} else {
		p = "."
	}

	lego := &LegoCMD{
		C:    certConf,
		path: filepath.Join(p, "cert"),
	}

	return lego, nil
}

func (l *LegoCMD) getPath() string {
	return l.path
}

func (l *LegoCMD) getCertConfig() *CertConfig {
	return l.C
}

func (l *LegoCMD) validate() error {
	if l == nil {
		return errors.New("certificate client is nil")
	}
	if l.C == nil {
		return errors.New("certificate config is nil")
	}
	if strings.TrimSpace(l.path) == "" {
		return errors.New("certificate storage path is empty")
	}
	if err := rejectSymlinkPathComponents(filepath.Join(l.path, ".certificate-operation")); err != nil {
		return err
	}
	return nil
}

func validateAccountEmail(email string) error {
	if strings.TrimSpace(email) != email {
		return errors.New("ACME account email contains surrounding whitespace")
	}
	if email == "." || email == ".." ||
		strings.ContainsAny(email, `:/\`) ||
		strings.ContainsRune(email, '\x00') ||
		filepath.IsAbs(email) ||
		filepath.VolumeName(email) != "" {
		return errors.New("ACME account email must not contain path syntax")
	}
	return nil
}

// allowedDNSEnvPrefixes is a whitelist of environment variable prefixes
// used by known DNS providers in lego. This prevents arbitrary env var injection
// (e.g., PATH, LD_PRELOAD) through the DNSEnv configuration.
var allowedDNSEnvPrefixes = []string{
	// Cloudflare
	"CF_", "CLOUDFLARE_",
	// Alibaba Cloud (AliDNS)
	"ALICLOUD_",
	// AWS Route53
	"AWS_",
	// GoDaddy
	"GODADDY_",
	// Gandi
	"GANDI_",
	// DigitalOcean
	"DO_",
	// DNSPod / Tencent Cloud
	"DNSPOD_", "TENCENTCLOUD_",
	// Namecheap
	"NAMECHEAP_",
	// Vultr
	"VULTR_",
	// Linode
	"LINODE_",
	// Name.com
	"NAMECOM_",
	// NS1
	"NS1_",
	// OVH
	"OVH_",
	// Hetzner
	"HETZNER_",
	// Google Cloud DNS
	"GCE_",
	// Azure
	"AZURE_",
	// Porkbun
	"PORKBUN_",
	// Duck DNS
	"DUCKDNS_",
	// Hurricane Electric
	"HURRICANE_",
	// Desec
	"DESEC_",
	// ACME_DNS
	"ACME_DNS_",
	// Generic lego
	"LEGO_",
}

func isAllowedDNSEnvKey(key string) bool {
	for _, prefix := range allowedDNSEnvPrefixes {
		if strings.HasPrefix(key, prefix) {
			return true
		}
	}
	return false
}

func checkCertFile(rootPath, domain string) (string, string, error) {
	safeDomain, err := sanitizeDomain(domain)
	if err != nil {
		return "", "", err
	}
	keyPath := filepath.Join(rootPath, "certificates", fmt.Sprintf("%s.key", safeDomain))
	certPath := filepath.Join(rootPath, "certificates", fmt.Sprintf("%s.crt", safeDomain))
	if err := recoverFileTransaction(filepath.Dir(certPath)); err != nil {
		return "", "", fmt.Errorf("recover certificate transaction for %s: %w", domain, err)
	}
	if err := validateExistingRegularFile(keyPath); err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return "", "", fmt.Errorf("%w: certificate key for %s", errCertificateFilesMissing, domain)
		}
		return "", "", fmt.Errorf("inspect certificate key for %s: %w", domain, err)
	}
	if err := validateExistingRegularFile(certPath); err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return "", "", fmt.Errorf("%w: certificate for %s", errCertificateFilesMissing, domain)
		}
		return "", "", fmt.Errorf("inspect certificate for %s: %w", domain, err)
	}
	absKeyPath, err := filepath.Abs(keyPath)
	if err != nil {
		return "", "", err
	}
	absCertPath, err := filepath.Abs(certPath)
	if err != nil {
		return "", "", err
	}
	return absCertPath, absKeyPath, nil
}
