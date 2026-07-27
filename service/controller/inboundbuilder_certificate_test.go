package controller

import (
	"testing"

	"github.com/Mtoly/XrayRP/common/mylego"
)

func TestBuildTLSCertificateConfigKeepsContentCandidateInMemory(t *testing.T) {
	const certificatePEM = "-----BEGIN CERTIFICATE-----\ncandidate\n-----END CERTIFICATE-----\n"
	const privateKeyPEM = "-----BEGIN PRIVATE KEY-----\ncandidate\n-----END PRIVATE KEY-----\n"
	config := &Config{
		CertConfig: &mylego.CertConfig{
			CertMode:    "content",
			CertContent: certificatePEM,
			KeyContent:  privateKeyPEM,
		},
	}

	certificate, err := buildTLSCertificateConfig(config)
	if err != nil {
		t.Fatalf("buildTLSCertificateConfig() error = %v", err)
	}
	if certificate.CertFile != "" || certificate.KeyFile != "" {
		t.Fatalf("content candidate published file paths %q/%q", certificate.CertFile, certificate.KeyFile)
	}
	if len(certificate.CertStr) != 1 || certificate.CertStr[0] != certificatePEM {
		t.Fatalf("certificate content = %#v", certificate.CertStr)
	}
	if len(certificate.KeyStr) != 1 || certificate.KeyStr[0] != privateKeyPEM {
		t.Fatalf("private key content = %#v", certificate.KeyStr)
	}
}
