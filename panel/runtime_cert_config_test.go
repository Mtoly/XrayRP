package panel

import (
	"errors"
	"io"
	"reflect"
	"testing"

	log "github.com/sirupsen/logrus"

	"github.com/Mtoly/XrayRP/api"
	"github.com/Mtoly/XrayRP/common/mylego"
	"github.com/Mtoly/XrayRP/service/controller"
)

func TestMergeRuntimePanelCertConfigKeepsLocalWhenPanelEmpty(t *testing.T) {
	localCert := &mylego.CertConfig{
		CertMode:    "file",
		CertDomain:  "local.example.com",
		CertFile:    "/etc/xray/local.crt",
		KeyFile:     "/etc/xray/local.key",
		Provider:    "cloudflare",
		Email:       "admin@example.com",
		DNSEnv:      map[string]string{"CF_DNS_API_TOKEN": "local-token"},
		CertContent: "local-cert",
		KeyContent:  "local-key",
	}
	want := *localCert
	want.DNSEnv = map[string]string{"CF_DNS_API_TOKEN": "local-token"}
	controllerConfig := &controller.Config{CertConfig: localCert}

	if err := mergeRuntimePanelCertConfig(controllerConfig, &api.XrayRCertConfig{}); err != nil {
		t.Fatalf("merge runtime panel cert config: %v", err)
	}
	if controllerConfig.CertConfig != localCert {
		t.Fatal("expected existing local cert config pointer to be preserved")
	}
	if !reflect.DeepEqual(&want, controllerConfig.CertConfig) {
		t.Fatalf("expected local cert config to remain unchanged, got %#v", controllerConfig.CertConfig)
	}
}

func TestMergeRuntimePanelCertConfigMaterializesContentCert(t *testing.T) {
	controllerConfig := &controller.Config{}
	panelCert := &api.XrayRCertConfig{
		CertMode:    "content",
		CertDomain:  "example.com",
		CertContent: "-----BEGIN CERTIFICATE-----\ncert\n-----END CERTIFICATE-----\n",
		KeyContent:  "-----BEGIN PRIVATE KEY-----\nkey\n-----END PRIVATE KEY-----\n",
	}

	if err := mergeRuntimePanelCertConfig(controllerConfig, panelCert); err != nil {
		t.Fatalf("merge runtime panel cert config: %v", err)
	}
	certConfig := controllerConfig.CertConfig
	if certConfig == nil {
		t.Fatal("expected panel cert config to be materialized")
	}
	if certConfig.CertMode != "content" || certConfig.CertDomain != panelCert.CertDomain {
		t.Fatalf("unexpected content cert config: %#v", certConfig)
	}
	if certConfig.CertContent != panelCert.CertContent || certConfig.KeyContent != panelCert.KeyContent {
		t.Fatalf("expected inline cert/key content to be preserved, got cert=%q key=%q", certConfig.CertContent, certConfig.KeyContent)
	}
	if certConfig.CertFile != "" || certConfig.KeyFile != "" {
		t.Fatalf("expected content cert not to materialize file paths, got cert=%q key=%q", certConfig.CertFile, certConfig.KeyFile)
	}
}

func TestMergeRuntimePanelCertConfigMaterializesFileAndDNSFields(t *testing.T) {
	controllerConfig := &controller.Config{}
	panelCert := &api.XrayRCertConfig{
		CertMode:   "file",
		CertDomain: "file.example.com",
		CertFile:   "/panel/cert.crt",
		KeyFile:    "/panel/cert.key",
		Provider:   "cloudflare",
		Email:      "admin@example.com",
		DNSEnv:     map[string]string{"CF_DNS_API_TOKEN": "panel-token"},
	}

	if err := mergeRuntimePanelCertConfig(controllerConfig, panelCert); err != nil {
		t.Fatalf("merge runtime panel cert config: %v", err)
	}
	certConfig := controllerConfig.CertConfig
	if certConfig == nil {
		t.Fatal("expected panel cert config to be materialized")
	}
	if certConfig.CertMode != "file" || certConfig.CertDomain != panelCert.CertDomain || certConfig.CertFile != panelCert.CertFile || certConfig.KeyFile != panelCert.KeyFile {
		t.Fatalf("unexpected file cert config: %#v", certConfig)
	}
	if certConfig.Provider != panelCert.Provider || certConfig.Email != panelCert.Email || !reflect.DeepEqual(certConfig.DNSEnv, panelCert.DNSEnv) {
		t.Fatalf("unexpected DNS provider metadata: %#v", certConfig)
	}
}

func TestMergeRuntimePanelCertConfigTreatsLegacyDNSFieldsAsDNSMode(t *testing.T) {
	controllerConfig := &controller.Config{}
	panelCert := &api.XrayRCertConfig{Provider: "cloudflare", DNSEnv: map[string]string{"CF_DNS_API_TOKEN": "panel-token"}}

	if err := mergeRuntimePanelCertConfig(controllerConfig, panelCert); err != nil {
		t.Fatalf("merge runtime panel cert config: %v", err)
	}
	certConfig := controllerConfig.CertConfig
	if certConfig == nil {
		t.Fatal("expected legacy DNS cert config to be materialized")
	}
	if certConfig.CertMode != "dns" || certConfig.Provider != panelCert.Provider || !reflect.DeepEqual(certConfig.DNSEnv, panelCert.DNSEnv) {
		t.Fatalf("expected legacy DNS fields to materialize dns mode, got %#v", certConfig)
	}
}

func TestMaterializeRuntimeCertConfigWarnsAndKeepsLocalOnFetchError(t *testing.T) {
	localCert := &mylego.CertConfig{CertMode: "file", CertFile: "/local.crt", KeyFile: "/local.key"}
	controllerConfig := &controller.Config{CertConfig: localCert}
	client := &runtimeCertConfigAPI{certErr: errors.New("panel unavailable")}

	materializeRuntimeCertConfig(client, controllerConfig, discardTestLogger())

	if client.certCalls != 1 {
		t.Fatalf("expected one panel cert fetch, got %d", client.certCalls)
	}
	if controllerConfig.CertConfig != localCert {
		t.Fatal("expected local cert config to be preserved when panel cert fetch fails")
	}
	if controllerConfig.CertConfig.CertMode != "file" || controllerConfig.CertConfig.CertFile != "/local.crt" || controllerConfig.CertConfig.KeyFile != "/local.key" {
		t.Fatalf("expected local cert config to remain unchanged, got %#v", controllerConfig.CertConfig)
	}
}

func discardTestLogger() *log.Entry {
	logger := log.New()
	logger.SetOutput(io.Discard)
	return log.NewEntry(logger)
}

type runtimeCertConfigAPI struct {
	cert      *api.XrayRCertConfig
	certErr   error
	certCalls int
}

func (a *runtimeCertConfigAPI) GetXrayRCertConfig() (*api.XrayRCertConfig, error) {
	a.certCalls++
	return a.cert, a.certErr
}
