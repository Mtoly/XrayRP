package mylego

import (
	"crypto"
	"crypto/x509"
	"errors"
	"fmt"
	"time"

	log "github.com/sirupsen/logrus"

	"github.com/go-acme/lego/v4/certcrypto"
	"github.com/go-acme/lego/v4/certificate"
	"github.com/go-acme/lego/v4/lego"
)

func (l *LegoCMD) Renew() (bool, error) {
	prepared, err := l.PrepareRenewal()
	if err != nil {
		return false, err
	}
	if !prepared.Renewed() {
		return false, prepared.Rollback()
	}
	if err := prepared.Commit(); err != nil {
		return false, err
	}
	return true, nil
}

func (l *LegoCMD) PrepareRenewal() (prepared *PreparedRenewal, err error) {
	if err := l.validate(); err != nil {
		return nil, err
	}

	certificateOperationMu.Lock()
	transferred := false
	var restore func() error
	defer func() {
		var restoreErr error
		if restore != nil {
			restoreErr = restore()
		}
		err = errors.Join(err, panicValueError(recover()), restoreErr)
		if err != nil || !transferred {
			certificateOperationMu.Unlock()
			prepared = nil
		}
	}()

	var dnsEnv map[string]string
	if l.C.CertMode == "dns" {
		dnsEnv = l.C.DNSEnv
	}
	restore, err = applyDNSEnvironment(dnsEnv)
	if err != nil {
		return nil, err
	}

	resource, renewed, err := l.prepareRenewal()
	if err != nil {
		return nil, err
	}
	prepared = newPreparedRenewal(NewCertificatesStorage(l.path), resource, renewed, true)
	transferred = true
	return prepared, nil
}

func (l *LegoCMD) prepareRenewal() (*certificate.Resource, bool, error) {
	account, client := setup(NewAccountsStorage(l))
	setupChallenges(l, client)

	if account.Registration == nil {
		return nil, false, fmt.Errorf("ACME account %s is not registered", account.Email)
	}

	return renewForDomains(l.C.CertDomain, client, NewCertificatesStorage(l.path))
}

func renewForDomains(domain string, client *lego.Client, certsStorage *CertificatesStorage) (*certificate.Resource, bool, error) {
	// load the cert resource from files.
	// We store the certificate, private key and metadata in different files
	// as web servers would not be able to work with a combined file.
	certificates, err := certsStorage.ReadCertificate(domain, ".crt")
	if err != nil {
		return nil, false, fmt.Errorf("load certificate for domain %s: %w", domain, err)
	}

	cert := certificates[0]

	if !needRenewal(cert, domain, 30) {
		return nil, false, nil
	}

	// This is just meant to be informal for the user.
	timeLeft := cert.NotAfter.Sub(time.Now().UTC())
	log.Printf("[%s] acme: Trying renewal with %d hours remaining", domain, int(timeLeft.Hours()))

	certDomains := certcrypto.ExtractDomains(cert)

	var privateKey crypto.PrivateKey
	request := certificate.ObtainRequest{
		Domains:    certDomains,
		Bundle:     true,
		PrivateKey: privateKey,
	}
	certRes, err := client.Certificate.Obtain(request)
	if err != nil {
		return nil, false, err
	}
	return certRes, true, nil
}

func needRenewal(x509Cert *x509.Certificate, domain string, days int) bool {
	if x509Cert.IsCA {
		panic(fmt.Errorf("[%s] certificate bundle starts with a CA certificate", domain))
	}

	if days >= 0 {
		notAfter := int(time.Until(x509Cert.NotAfter).Hours() / 24.0)
		if notAfter > days {
			log.Printf("[%s] The certificate expires in %d days, the number of days defined to perform the renewal is %d: no renewal.",
				domain, notAfter, days)
			return false
		}
	}

	return true
}
