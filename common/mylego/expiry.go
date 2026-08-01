package mylego

import (
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"
	"time"
)

const maxObservedCertificateBytes = 1 << 20

func CertificateExpiry(config *CertConfig) (time.Time, error) {
	if config == nil || strings.EqualFold(strings.TrimSpace(config.CertMode), "none") {
		return time.Time{}, nil
	}

	var content []byte
	if strings.TrimSpace(config.CertContent) != "" {
		content = []byte(config.CertContent)
	} else if strings.TrimSpace(config.CertFile) != "" {
		file, err := os.Open(config.CertFile)
		if err != nil {
			return time.Time{}, fmt.Errorf("open certificate: %w", err)
		}
		defer file.Close()

		content, err = io.ReadAll(io.LimitReader(file, maxObservedCertificateBytes+1))
		if err != nil {
			return time.Time{}, fmt.Errorf("read certificate: %w", err)
		}
		if len(content) > maxObservedCertificateBytes {
			return time.Time{}, errors.New("certificate exceeds observation size limit")
		}
	} else {
		return time.Time{}, nil
	}

	var earliest time.Time
	for len(content) > 0 {
		block, rest := pem.Decode(content)
		if block == nil {
			break
		}
		content = rest
		if block.Type != "CERTIFICATE" {
			continue
		}
		certificate, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return time.Time{}, fmt.Errorf("parse certificate: %w", err)
		}
		if earliest.IsZero() || certificate.NotAfter.Before(earliest) {
			earliest = certificate.NotAfter
		}
	}
	if earliest.IsZero() {
		return time.Time{}, errors.New("certificate PEM contains no certificate")
	}
	return earliest, nil
}
