package controller

import (
	"context"
	"errors"
	"reflect"
	"testing"

	"github.com/Mtoly/XrayRP/api"
	"github.com/Mtoly/XrayRP/common/mylego"
)

// localDNSCertConfig is the locally declared certificate basis. Startup merges
// panel snapshots over it, and certificate synchronization must do the same.
func localDNSCertConfig() *mylego.CertConfig {
	return &mylego.CertConfig{
		CertMode: "dns",
		Provider: "cloudflare",
		Email:    "ops@example.com",
		DNSEnv:   map[string]string{"CF_API_TOKEN": "local-token"},
	}
}

func runCertConfigSync(t *testing.T, controller *Controller) {
	t.Helper()
	if err := controller.ExecuteSyncAction(
		context.Background(),
		newSyncAction(syncActionTypeSyncCertConfig, syncActionSourceWS, syncActionMetadata{Trigger: "cert_changed"}),
	); err != nil {
		t.Fatalf("ExecuteSyncAction() error = %v", err)
	}
}

func TestSyncApplyCertKeepsLocalDNSEnvWhenPanelOmitsIt(t *testing.T) {
	fakeAPI := &fakeSyncApplyAPI{certConfig: &api.XrayRCertConfig{
		CertMode:   "dns",
		CertDomain: "node.example.com",
		Provider:   "cloudflare",
		Email:      "ops@example.com",
	}}
	controller, _ := newTestSyncApplyController(fakeAPI)
	controller.config.localCertConfig = localDNSCertConfig()
	controller.config.CertConfig = localDNSCertConfig()

	runCertConfigSync(t, controller)

	got := controller.config.CertConfig
	if got == nil || got.CertDomain != "node.example.com" {
		t.Fatalf("panel certificate domain was not applied: %#v", got)
	}
	if got.DNSEnv["CF_API_TOKEN"] != "local-token" {
		t.Fatalf("local DNS credential was erased by panel snapshot without DNSEnv: %#v", got.DNSEnv)
	}
}

func TestSyncApplyCertDoesNotRetainPreviousPanelCredential(t *testing.T) {
	fakeAPI := &fakeSyncApplyAPI{certConfig: &api.XrayRCertConfig{
		Provider: "cloudflare",
		DNSEnv:   map[string]string{"PANEL_TOKEN": "panel-1"},
	}}
	controller, _ := newTestSyncApplyController(fakeAPI)
	controller.config.localCertConfig = &mylego.CertConfig{
		Provider: "cloudflare",
		DNSEnv:   map[string]string{"LOCAL_TOKEN": "local"},
	}
	controller.config.CertConfig = cloneCertConfig(controller.config.localCertConfig)

	runCertConfigSync(t, controller)
	wantFirst := map[string]string{"LOCAL_TOKEN": "local", "PANEL_TOKEN": "panel-1"}
	if got := controller.config.CertConfig.DNSEnv; !reflect.DeepEqual(got, wantFirst) {
		t.Fatalf("first panel snapshot DNSEnv = %#v, want %#v", got, wantFirst)
	}

	fakeAPI.certConfig = &api.XrayRCertConfig{
		Provider: "cloudflare",
		DNSEnv:   map[string]string{"OTHER_TOKEN": "panel-2"},
	}
	runCertConfigSync(t, controller)
	wantSecond := map[string]string{"LOCAL_TOKEN": "local", "OTHER_TOKEN": "panel-2"}
	if got := controller.config.CertConfig.DNSEnv; !reflect.DeepEqual(got, wantSecond) {
		t.Fatalf("second panel snapshot DNSEnv = %#v, want %#v (previous panel credential must not persist)", got, wantSecond)
	}
}

func TestSyncApplyCertAbsentPanelConfigFallsBackToLocalBasis(t *testing.T) {
	fakeAPI := &fakeSyncApplyAPI{}
	controller, _ := newTestSyncApplyController(fakeAPI)
	controller.config.localCertConfig = localDNSCertConfig()
	controller.config.CertConfig = &mylego.CertConfig{
		CertMode: "file",
		CertFile: "/panel/stale.crt",
		KeyFile:  "/panel/stale.key",
		DNSEnv:   map[string]string{"PANEL_TOKEN": "stale"},
	}

	runCertConfigSync(t, controller)

	if got, want := controller.config.CertConfig, localDNSCertConfig(); !reflect.DeepEqual(got, want) {
		t.Fatalf("absent panel cert config should restore local basis: got %#v, want %#v", got, want)
	}
}

func TestSyncApplyCertModeSwitchKeepsLocalDNSFallback(t *testing.T) {
	fakeAPI := &fakeSyncApplyAPI{certConfig: &api.XrayRCertConfig{
		CertMode:   "file",
		CertDomain: "file.example.com",
		CertFile:   "/panel/node.crt",
		KeyFile:    "/panel/node.key",
	}}
	controller, _ := newTestSyncApplyController(fakeAPI)
	controller.config.localCertConfig = localDNSCertConfig()
	controller.config.CertConfig = localDNSCertConfig()

	runCertConfigSync(t, controller)

	got := controller.config.CertConfig
	if got == nil || got.CertMode != "file" || got.CertFile != "/panel/node.crt" || got.KeyFile != "/panel/node.key" {
		t.Fatalf("panel file mode was not applied: %#v", got)
	}
	if got.DNSEnv["CF_API_TOKEN"] != "local-token" {
		t.Fatalf("local DNS fallback was dropped on mode switch: %#v", got.DNSEnv)
	}
}

func TestSyncApplyCertUnchangedMergedSnapshotIsNotRepublished(t *testing.T) {
	fakeAPI := &fakeSyncApplyAPI{certConfig: &api.XrayRCertConfig{
		Provider: "cloudflare",
		Email:    "ops@example.com",
	}}
	controller, _ := newTestSyncApplyController(fakeAPI)
	controller.config.localCertConfig = localDNSCertConfig()
	controller.config.CertConfig = localDNSCertConfig()
	before := controller.config.CertConfig

	runCertConfigSync(t, controller)

	if controller.config.CertConfig != before {
		t.Fatalf("effective cert config equal to local-merged snapshot was republished: %#v", controller.config.CertConfig)
	}
}

// Guard: content mode is private-key material. A later snapshot that leaves
// content mode must not keep the previous panel key.
func TestSyncApplyCertModeSwitchDoesNotRetainPanelPrivateKey(t *testing.T) {
	fakeAPI := &fakeSyncApplyAPI{certConfig: &api.XrayRCertConfig{
		CertMode:    "content",
		CertDomain:  "content.example.com",
		CertContent: "-----BEGIN CERTIFICATE-----\ncert\n-----END CERTIFICATE-----\n",
		KeyContent:  "panel-private-key",
	}}
	controller, _ := newTestSyncApplyController(fakeAPI)
	controller.config.localCertConfig = &mylego.CertConfig{CertMode: "file", CertFile: "/local.crt", KeyFile: "/local.key"}
	controller.config.CertConfig = cloneCertConfig(controller.config.localCertConfig)

	runCertConfigSync(t, controller)
	if controller.config.CertConfig.KeyContent != "panel-private-key" {
		t.Fatalf("content mode snapshot was not applied: %#v", controller.config.CertConfig)
	}

	fakeAPI.certConfig = &api.XrayRCertConfig{CertMode: "file", CertFile: "/panel/node.crt", KeyFile: "/panel/node.key"}
	runCertConfigSync(t, controller)
	got := controller.config.CertConfig
	if got.KeyContent != "" || got.CertContent != "" || got.CertMode != "file" {
		t.Fatalf("previous panel private key persisted after mode switch: %#v", got)
	}
}

// Renewal reads the effective DNS credential produced by the last successful
// sync. The prepare hook stops before any DNS or ACME work: the fake reports
// no renewal, so the test only observes the configuration handed to renewal.
func TestSyncApplyCertRenewalUsesEffectiveDNSEnv(t *testing.T) {
	cases := []struct {
		name      string
		panelEnv  map[string]string
		wantToken string
	}{
		{name: "omitted panel token keeps local credential", panelEnv: nil, wantToken: "local-token"},
		{name: "panel token replaces local credential", panelEnv: map[string]string{"CF_API_TOKEN": "panel-token"}, wantToken: "panel-token"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			fakeAPI := &fakeSyncApplyAPI{certConfig: &api.XrayRCertConfig{
				CertMode:   "dns",
				CertDomain: "node.example.com",
				Provider:   "cloudflare",
				Email:      "ops@example.com",
				DNSEnv:     tc.panelEnv,
			}}
			controller, _ := newTestSyncApplyController(fakeAPI)
			controller.config.CertConfig = localDNSCertConfig()
			controller.config.CaptureLocalCertConfig()

			runCertConfigSync(t, controller)
			// Renewal only runs for TLS nodes; set the applied node state the
			// certificate monitor would see after sync.
			controller.setNodeState(&api.NodeInfo{EnableTLS: true}, "node-tag")

			var gotMode, gotToken string
			controller.prepareRenewal = func(cert *mylego.CertConfig) (preparedCertificateRenewal, error) {
				gotMode = cert.CertMode
				gotToken = cert.DNSEnv["CF_API_TOKEN"]
				return &fakeControllerPreparedRenewal{}, nil
			}
			if err := controller.renewCertificateIfNeededContext(context.Background()); err != nil {
				t.Fatalf("renewCertificateIfNeededContext() error = %v", err)
			}
			if gotMode != "dns" || gotToken != tc.wantToken {
				t.Fatalf("renewal saw mode=%q token=%q, want dns/%q", gotMode, gotToken, tc.wantToken)
			}
		})
	}
}

// A candidate that fails to build must not change the local basis. A later
// successful snapshot must still merge over the untouched declaration.
func TestSyncApplyCertFailedCandidateDoesNotPolluteLocalBasis(t *testing.T) {
	buildErr := errors.New("candidate runtime build failed")
	fakeAPI := &fakeSyncApplyAPI{certConfig: &api.XrayRCertConfig{
		CertMode:   "dns",
		CertDomain: "candidate.example.com",
		Provider:   "cloudflare",
		DNSEnv:     map[string]string{"CF_API_TOKEN": "panel-token"},
	}}
	controller, recorder := newTestSyncApplyController(fakeAPI)
	currentNode := &api.NodeInfo{NodeType: "V2ray", NodeID: 1, Port: 443, EnableTLS: true}
	controller.setNodeState(currentNode, controller.buildNodeTagFrom(currentNode))
	currentUsers := []api.UserInfo{}
	controller.setUserList(&currentUsers)
	controller.config.CertConfig = localDNSCertConfig()
	controller.config.CaptureLocalCertConfig()
	appliedBefore := controller.config.CertConfig
	recorder.addTagErr = buildErr
	recorder.addTagErrAtCall = 1

	err := controller.ExecuteSyncAction(context.Background(), newSyncAction(syncActionTypeSyncCertConfig, syncActionSourceWS, syncActionMetadata{Trigger: "cert_changed"}))
	if !errors.Is(err, buildErr) {
		t.Fatalf("ExecuteSyncAction() error = %v, want %v", err, buildErr)
	}
	if got := controller.config.localCertConfig; got.CertDomain != "" || got.DNSEnv["CF_API_TOKEN"] != "local-token" {
		t.Fatalf("failed candidate polluted the local basis: %#v", got)
	}
	if controller.config.CertConfig != appliedBefore {
		t.Fatalf("failed candidate published a certificate config: %#v", controller.config.CertConfig)
	}

	recorder.addTagErr = nil
	fakeAPI.certConfig = &api.XrayRCertConfig{CertMode: "dns", Provider: "cloudflare"}
	runCertConfigSync(t, controller)
	if got := controller.config.CertConfig.DNSEnv["CF_API_TOKEN"]; got != "local-token" {
		t.Fatalf("later snapshot did not merge over the untouched basis, DNSEnv = %#v", controller.config.CertConfig.DNSEnv)
	}
}

// Clone must detach the captured basis: mutating a clone cannot reach the
// original, and the captured flag must travel with the copy.
func TestConfigCloneDetachesLocalCertBasis(t *testing.T) {
	config := &Config{CertConfig: localDNSCertConfig()}
	config.CaptureLocalCertConfig()

	cloned := config.Clone()
	cloned.localCertConfig.DNSEnv["CF_API_TOKEN"] = "mutated"
	cloned.localCertConfig.CertDomain = "mutated.example.com"

	if config.localCertConfig.DNSEnv["CF_API_TOKEN"] != "local-token" || config.localCertConfig.CertDomain != "" {
		t.Fatalf("clone aliased the original local basis: %#v", config.localCertConfig)
	}
	if !cloned.localCertCaptured {
		t.Fatal("clone dropped the captured flag, so a later capture would recapture merged values")
	}
}

// MergePanelCertConfig must not alias its inputs on any branch: the merged
// result, the local basis and the panel snapshot stay independent.
func TestMergePanelCertConfigDoesNotAliasInputs(t *testing.T) {
	local := localDNSCertConfig()
	panel := &api.XrayRCertConfig{CertMode: "dns", DNSEnv: map[string]string{"PANEL_TOKEN": "panel"}}

	merged := mergePanelCertConfig(local, panel)
	if merged == local {
		t.Fatal("merged config reuses the local pointer")
	}
	merged.DNSEnv["CF_API_TOKEN"] = "mutated"
	merged.DNSEnv["PANEL_TOKEN"] = "mutated"
	if local.DNSEnv["CF_API_TOKEN"] != "local-token" || len(local.DNSEnv) != 1 {
		t.Fatalf("merged DNSEnv wrote into the local basis: %#v", local.DNSEnv)
	}
	panel.DNSEnv["PANEL_TOKEN"] = "panel-mutated"
	if merged.DNSEnv["PANEL_TOKEN"] != "mutated" {
		t.Fatal("merged DNSEnv aliases the panel snapshot map")
	}

	// Empty panel mode returns a clone of the local basis.
	empty := mergePanelCertConfig(local, &api.XrayRCertConfig{})
	if empty == local {
		t.Fatal("empty-mode merge reuses the local pointer")
	}
	empty.DNSEnv["CF_API_TOKEN"] = "mutated"
	if local.DNSEnv["CF_API_TOKEN"] != "local-token" {
		t.Fatalf("empty-mode merge aliases the local DNSEnv: %#v", local.DNSEnv)
	}

	// A nil panel snapshot also returns a clone.
	none := mergePanelCertConfig(local, nil)
	if none == local {
		t.Fatal("nil-panel merge reuses the local pointer")
	}
	none.DNSEnv["CF_API_TOKEN"] = "mutated"
	if local.DNSEnv["CF_API_TOKEN"] != "local-token" {
		t.Fatalf("nil-panel merge aliases the local DNSEnv: %#v", local.DNSEnv)
	}
}
