package mylego_test

import (
	"os"
	"testing"

	"github.com/Mtoly/XrayRP/common/mylego"
)

func requireLegoIntegration(t *testing.T) {
	t.Helper()
	if os.Getenv("XRAYRP_RUN_LEGO_INTEGRATION") != "1" {
		t.Skip("skipping lego integration test; set XRAYRP_RUN_LEGO_INTEGRATION=1 to enable")
	}
}

func TestLegoClient(t *testing.T) {
	_, err := mylego.New(&mylego.CertConfig{})
	if err != nil {
		t.Error(err)
	}
}

func TestLegoDNSCert(t *testing.T) {
	requireLegoIntegration(t)
	lego, err := mylego.New(&mylego.CertConfig{
		CertDomain: "node1.test.com",
		Provider:   "alidns",
		Email:      "test@gmail.com",
		DNSEnv: map[string]string{
			"ALICLOUD_ACCESS_KEY": "aaa",
			"ALICLOUD_SECRET_KEY": "bbb",
		},
	},
	)
	if err != nil {
		t.Error(err)
	}

	certPath, keyPath, err := lego.DNSCert()
	if err != nil {
		t.Error(err)
	}
	t.Log(certPath)
	t.Log(keyPath)
}

func TestLegoHTTPCert(t *testing.T) {
	requireLegoIntegration(t)
	lego, err := mylego.New(&mylego.CertConfig{
		CertMode:   "http",
		CertDomain: "node1.test.com",
		Email:      "test@gmail.com",
	})
	if err != nil {
		t.Error(err)
	}

	certPath, keyPath, err := lego.HTTPCert()
	if err != nil {
		t.Error(err)
	}
	t.Log(certPath)
	t.Log(keyPath)
}

func TestLegoRenewCert(t *testing.T) {
	requireLegoIntegration(t)
	lego, err := mylego.New(&mylego.CertConfig{
		CertDomain: "node1.test.com",
		Email:      "test@gmail.com",
		Provider:   "alidns",
		DNSEnv: map[string]string{
			"ALICLOUD_ACCESS_KEY": "aaa",
			"ALICLOUD_SECRET_KEY": "bbb",
		},
	})
	if err != nil {
		t.Error(err)
	}
	lego.C.CertMode = "http"
	certPath, keyPath, ok, err := lego.RenewCert()
	if err != nil {
		t.Error(err)
	}
	t.Log(certPath)
	t.Log(keyPath)
	t.Log(ok)

	lego.C.CertMode = "dns"
	certPath, keyPath, ok, err = lego.RenewCert()
	if err != nil {
		t.Error(err)
	}
	t.Log(certPath)
	t.Log(keyPath)
	t.Log(ok)
}
