package mylego

import (
	"fmt"

	"github.com/go-acme/lego/v4/certificate"
	"github.com/go-acme/lego/v4/lego"
	"github.com/go-acme/lego/v4/registration"
)

const rootPathWarningMessage = `!!!! HEADS UP !!!!

Your account credentials have been saved in your Let's Encrypt
configuration directory at "%s".

You should make a secure backup of this folder now. This
configuration directory will also contain certificates and
private keys obtained from Let's Encrypt so making regular
backups of this folder is ideal.
`

func (l *LegoCMD) Run() error {
	if err := l.validate(); err != nil {
		return err
	}
	var dnsEnv map[string]string
	if l.C.CertMode == "dns" {
		dnsEnv = l.C.DNSEnv
	}
	return executeCertificateOperation(dnsEnv, l.run)
}

func (l *LegoCMD) run() error {
	accountsStorage := NewAccountsStorage(l)

	account, client := setup(accountsStorage)
	setupChallenges(l, client)

	if account.Registration == nil {
		reg, err := client.Registration.Register(registration.RegisterOptions{TermsOfServiceAgreed: true})
		if err != nil {
			return fmt.Errorf("complete ACME registration: %w", err)
		}

		account.Registration = reg
		if err = accountsStorage.Save(account); err != nil {
			return err
		}

		fmt.Printf(rootPathWarningMessage, accountsStorage.GetRootPath())
	}

	certsStorage := NewCertificatesStorage(l.path)
	if err := certsStorage.createRootFolder(); err != nil {
		return err
	}

	cert, err := obtainCertificate([]string{l.C.CertDomain}, client)
	if err != nil {
		return fmt.Errorf("obtain certificate: %w", err)
	}

	return certsStorage.storeResource(cert)
}

func obtainCertificate(domains []string, client *lego.Client) (*certificate.Resource, error) {
	if len(domains) > 0 {
		// obtain a certificate, generating a new private key
		request := certificate.ObtainRequest{
			Domains: domains,
			Bundle:  true,
		}
		return client.Certificate.Obtain(request)
	}
	return nil, fmt.Errorf("not a valid domain")
}
