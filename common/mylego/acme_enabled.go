package mylego

import "errors"

// DNSCert certifies a domain using a DNS provider.
func (l *LegoCMD) DNSCert() (certPath string, keyPath string, err error) {
	if err := l.validate(); err != nil {
		return "", "", err
	}
	err = executeCertificateOperation(l.C.DNSEnv, func() error {
		certPath, keyPath, err = checkCertFile(l.path, l.C.CertDomain)
		if err == nil {
			return nil
		}
		if !errors.Is(err, errCertificateFilesMissing) {
			return err
		}
		if err := l.run(); err != nil {
			return err
		}
		certPath, keyPath, err = checkCertFile(l.path, l.C.CertDomain)
		return err
	})
	if err != nil {
		return "", "", err
	}
	return certPath, keyPath, nil
}

// HTTPCert certifies a domain using an HTTP or TLS-ALPN challenge.
func (l *LegoCMD) HTTPCert() (certPath string, keyPath string, err error) {
	if err := l.validate(); err != nil {
		return "", "", err
	}
	err = executeCertificateOperation(nil, func() error {
		certPath, keyPath, err = checkCertFile(l.path, l.C.CertDomain)
		if err == nil {
			return nil
		}
		if !errors.Is(err, errCertificateFilesMissing) {
			return err
		}
		if err := l.run(); err != nil {
			return err
		}
		certPath, keyPath, err = checkCertFile(l.path, l.C.CertDomain)
		return err
	})
	if err != nil {
		return "", "", err
	}
	return certPath, keyPath, nil
}

func (l *LegoCMD) RenewCert() (certPath string, keyPath string, renewed bool, err error) {
	prepared, err := l.PrepareRenewal()
	if err != nil {
		return "", "", false, err
	}
	renewed = prepared.Renewed()
	if renewed {
		if err := prepared.Commit(); err != nil {
			return "", "", false, err
		}
	} else if err := prepared.Rollback(); err != nil {
		return "", "", false, err
	}
	certPath, keyPath, err = checkCertFile(l.path, l.C.CertDomain)
	if err != nil {
		return "", "", false, err
	}
	return certPath, keyPath, renewed, nil
}
