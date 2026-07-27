package mylego

import (
	"bytes"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/go-acme/lego/v4/certcrypto"
	"github.com/go-acme/lego/v4/certificate"
	"github.com/sirupsen/logrus"
)

func TestNewRejectsNilCertificateConfig(t *testing.T) {
	lego, err := New(nil)

	if err == nil {
		t.Fatalf("New(nil) = %#v, nil; want error", lego)
	}
	if lego != nil {
		t.Fatalf("New(nil) returned client %#v", lego)
	}
}

func TestCreateDirectoryAllDurableSyncsEveryNewDirectoryAndParent(t *testing.T) {
	base := t.TempDir()
	first := filepath.Join(base, "cert")
	target := filepath.Join(first, "certificates")
	var synced []string

	err := createDirectoryAllDurableWithSync(target, 0o700, func(path string) error {
		synced = append(synced, filepath.Clean(path))
		return nil
	})
	if err != nil {
		t.Fatalf("createDirectoryAllDurableWithSync() error = %v", err)
	}

	want := []string{
		filepath.Clean(first),
		filepath.Clean(base),
		filepath.Clean(target),
		filepath.Clean(first),
	}
	if len(synced) != len(want) {
		t.Fatalf("directory sync order = %#v, want %#v", synced, want)
	}
	for i := range want {
		if synced[i] != want[i] {
			t.Fatalf("directory sync order = %#v, want %#v", synced, want)
		}
	}
}

func TestFileTransactionRemovalRenamesBeforeDurabilitySync(t *testing.T) {
	dir := t.TempDir()
	issuerPath := filepath.Join(dir, "node.example.com.issuer.crt")
	if err := os.WriteFile(issuerPath, []byte("last-known-good-issuer"), filePerm); err != nil {
		t.Fatal(err)
	}

	var events []string
	removalRenamed := false
	renameFile := func(source, target string) error {
		if filepath.Clean(source) == filepath.Clean(issuerPath) {
			removalRenamed = true
			events = append(events, "rename-removal")
		}
		return replaceFile(source, target)
	}
	syncDir := func(string) error {
		if removalRenamed {
			events = append(events, "sync-removal")
		}
		return nil
	}

	err := writeFileTransactionWithOperations(
		[]fileTransactionEntry{{
			path:   issuerPath,
			remove: true,
		}},
		renameFile,
		replaceFile,
		syncDir,
	)
	if err != nil {
		t.Fatalf("writeFileTransactionWithOperations() error = %v", err)
	}
	if len(events) < 2 || events[0] != "rename-removal" || events[1] != "sync-removal" {
		t.Fatalf("removal durability events = %#v, want rename then sync", events)
	}
	if _, err := os.Stat(issuerPath); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("removed issuer still exists: %v", err)
	}
}

func TestFailedFileTransactionSyncsRollbackBeforeRemovingJournal(t *testing.T) {
	dir := t.TempDir()
	journalPath := filepath.Join(dir, fileTransactionJournalName)
	if err := os.WriteFile(journalPath, []byte(`{"entries":[]}`), filePerm); err != nil {
		t.Fatal(err)
	}

	var events []string
	syncDir := func(string) error {
		_, err := os.Stat(journalPath)
		switch {
		case err == nil:
			events = append(events, "sync-rollback")
		case errors.Is(err, os.ErrNotExist):
			events = append(events, "sync-journal-removal")
		default:
			return err
		}
		return nil
	}

	if err := finishFailedFileTransaction(dir, nil, syncDir); err != nil {
		t.Fatalf("finishFailedFileTransaction() error = %v", err)
	}
	want := []string{"sync-rollback", "sync-journal-removal"}
	if len(events) != len(want) {
		t.Fatalf("failed transaction durability events = %#v, want %#v", events, want)
	}
	for i := range want {
		if events[i] != want[i] {
			t.Fatalf("failed transaction durability events = %#v, want %#v", events, want)
		}
	}
}

func TestFileTransactionRejectsReservedTargetPaths(t *testing.T) {
	for _, name := range []string{
		fileTransactionJournalName,
		fileTransactionTempPrefix + "account.key",
	} {
		t.Run(name, func(t *testing.T) {
			target := filepath.Join(t.TempDir(), name)

			err := writeFileTransaction([]fileTransactionEntry{{
				path: target,
				data: []byte("secret"),
				perm: filePerm,
			}}, nil)

			if err == nil {
				t.Fatalf("writeFileTransaction() accepted reserved target %q", name)
			}
			if _, statErr := os.Stat(target); !errors.Is(statErr, os.ErrNotExist) {
				t.Fatalf("reserved transaction target %q was published: %v", name, statErr)
			}
		})
	}
}

func TestDNSCertRestoresConfiguredEnvironment(t *testing.T) {
	configRoot := t.TempDir()
	t.Setenv("XRAY_LOCATION_CONFIG", configRoot)
	t.Setenv("CF_API_TOKEN", "last-known-good")
	const absentKey = "CF_XRAYRP_TEST_TOKEN"
	restoreAbsent := preserveEnvironment(t, absentKey)
	if err := os.Unsetenv(absentKey); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(restoreAbsent)

	lego, err := New(&CertConfig{
		CertMode:   "dns",
		CertDomain: "node.example.com",
		Provider:   "invalid-provider-not-used",
		DNSEnv: map[string]string{
			"CF_API_TOKEN":         "candidate-secret",
			"cf_xrayrp_test_token": "candidate-only",
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	writeCertificatePair(t, lego.path, "node.example.com", "cert", "key")

	if _, _, err := lego.DNSCert(); err != nil {
		t.Fatalf("DNSCert with existing certificate failed: %v", err)
	}
	if got := os.Getenv("CF_API_TOKEN"); got != "last-known-good" {
		t.Fatalf("CF_API_TOKEN after success = %q, want last-known-good", got)
	}
	if value, exists := os.LookupEnv(absentKey); exists {
		t.Fatalf("%s after success = %q, want absent", absentKey, value)
	}
}

func TestDNSCertRestoresEnvironmentAfterFailure(t *testing.T) {
	configRoot := t.TempDir()
	t.Setenv("XRAY_LOCATION_CONFIG", configRoot)
	t.Setenv("CF_API_TOKEN", "last-known-good")

	lego, err := New(&CertConfig{
		CertMode:   "dns",
		CertDomain: "\x00",
		Provider:   "invalid-provider",
		Email:      "ops@example.com",
		DNSEnv:     map[string]string{"CF_API_TOKEN": "candidate-secret"},
	})
	if err != nil {
		t.Fatal(err)
	}

	_, _, certErr := lego.DNSCert()
	if got := os.Getenv("CF_API_TOKEN"); got != "last-known-good" {
		t.Fatalf("CF_API_TOKEN after failure = %q, want last-known-good", got)
	}
	if certErr == nil {
		t.Fatal("DNSCert with invalid certificate path returned nil error")
	}
}

func TestLegoClientUsesItsOwnCertificatePath(t *testing.T) {
	firstRoot := t.TempDir()
	secondRoot := t.TempDir()
	t.Setenv("XRAY_LOCATION_CONFIG", firstRoot)
	first, err := New(&CertConfig{
		CertMode:   "dns",
		CertDomain: "first.example.com",
		Provider:   "invalid-provider-not-used",
	})
	if err != nil {
		t.Fatal(err)
	}
	writeCertificatePair(t, first.path, "first.example.com", "first-cert", "first-key")

	t.Setenv("XRAY_LOCATION_CONFIG", secondRoot)
	second, err := New(&CertConfig{CertMode: "dns", CertDomain: "second.example.com"})
	if err != nil {
		t.Fatal(err)
	}
	writeCertificatePair(t, second.path, "first.example.com", "wrong-cert", "wrong-key")

	certPath, keyPath, err := first.DNSCert()
	if err != nil {
		t.Fatalf("first client used another client's path: %v", err)
	}
	if certPath != filepath.Join(firstRoot, "cert", "certificates", "first.example.com.crt") {
		t.Fatalf("cert path = %q, want first client path", certPath)
	}
	if keyPath != filepath.Join(firstRoot, "cert", "certificates", "first.example.com.key") {
		t.Fatalf("key path = %q, want first client path", keyPath)
	}
}

func TestLegoClientRejectsPathLikeAccountEmail(t *testing.T) {
	for _, email := range []string{
		" ",
		".",
		"..",
		"../escaped-account",
		`..\escaped-account`,
		"account/name@example.com",
		`account\name@example.com`,
	} {
		t.Run(email, func(t *testing.T) {
			t.Setenv("XRAY_LOCATION_CONFIG", t.TempDir())
			lego, err := New(&CertConfig{
				CertMode:   "dns",
				CertDomain: "node.example.com",
				Email:      email,
			})
			if err != nil {
				t.Fatal(err)
			}

			storage := NewAccountsStorage(lego)
			if err := storage.Save(&Account{Email: email}); err == nil {
				t.Fatalf("account storage accepted account email %q", email)
			}
		})
	}
}

func TestAccountsStorageRejectsNTFSAlternateDataStreamEmailBeforePublication(t *testing.T) {
	configRoot := t.TempDir()
	t.Setenv("XRAY_LOCATION_CONFIG", configRoot)
	const email = "user:stream@example.com"

	lego, err := New(&CertConfig{
		CertMode:   "dns",
		CertDomain: "node.example.com",
		Email:      email,
	})
	if err != nil {
		t.Fatal(err)
	}
	storage := NewAccountsStorage(lego)

	err = storage.Save(&Account{Email: email})
	if err == nil || !strings.Contains(err.Error(), "must not contain path syntax") {
		t.Fatalf("Save() error = %v, want account path validation failure", err)
	}
	if _, statErr := os.Stat(storage.GetRootPath()); !errors.Is(statErr, os.ErrNotExist) {
		t.Fatalf("account storage published state before rejecting ADS email: %v", statErr)
	}
}

func TestAccountsStorageAllowsEmptyAccountEmail(t *testing.T) {
	t.Setenv("XRAY_LOCATION_CONFIG", t.TempDir())
	lego, err := New(&CertConfig{
		CertMode:   "dns",
		CertDomain: "node.example.com",
	})
	if err != nil {
		t.Fatal(err)
	}

	storage := NewAccountsStorage(lego)
	if err := storage.Save(&Account{}); err != nil {
		t.Fatalf("Save() with empty account email = %v", err)
	}
	if _, err := os.Stat(filepath.Join(storage.GetRootUserPath(), accountFileName)); err != nil {
		t.Fatalf("empty-email account file: %v", err)
	}
}

func TestLegoClientAllowsExistingCertificateWithoutAccountEmail(t *testing.T) {
	t.Setenv("XRAY_LOCATION_CONFIG", t.TempDir())
	lego, err := New(&CertConfig{
		CertMode:   "dns",
		CertDomain: "node.example.com",
	})
	if err != nil {
		t.Fatal(err)
	}
	writeCertificatePair(t, lego.path, "node.example.com", "cert", "key")

	certPath, keyPath, err := lego.DNSCert()
	if err != nil {
		t.Fatalf("DNSCert() with existing certificate and no account email: %v", err)
	}
	if certPath == "" || keyPath == "" {
		t.Fatalf("existing certificate paths = %q/%q", certPath, keyPath)
	}
}

func TestLegoClientPreservesNormalAccountEmailDirectory(t *testing.T) {
	t.Setenv("XRAY_LOCATION_CONFIG", t.TempDir())
	const email = "ops+node@example.com"
	lego, err := New(&CertConfig{
		CertMode:   "dns",
		CertDomain: "node.example.com",
		Email:      email,
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := lego.validate(); err != nil {
		t.Fatalf("validate normal account email: %v", err)
	}

	storage := NewAccountsStorage(lego)
	if got := filepath.Base(storage.GetRootUserPath()); got != email {
		t.Fatalf("account directory = %q, want %q", got, email)
	}
}

func TestAccountsStorageRejectsSymlinkedAccountDirectory(t *testing.T) {
	configRoot := t.TempDir()
	outsideRoot := t.TempDir()
	t.Setenv("XRAY_LOCATION_CONFIG", configRoot)
	lego, err := New(&CertConfig{
		CertMode:   "dns",
		CertDomain: "node.example.com",
		Email:      "ops@example.com",
	})
	if err != nil {
		t.Fatal(err)
	}
	storage := NewAccountsStorage(lego)
	if err := os.MkdirAll(filepath.Dir(storage.GetRootUserPath()), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(outsideRoot, storage.GetRootUserPath()); err != nil {
		t.Skipf("symbolic links are unavailable: %v", err)
	}

	if err := storage.Save(&Account{Email: "ops@example.com"}); err == nil {
		t.Fatal("account storage accepted a symlinked account directory")
	}
	if _, err := os.Stat(filepath.Join(outsideRoot, accountFileName)); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("outside account path was modified: %v", err)
	}
}

func TestContentCertRollsBackCertificateWhenKeyWriteFails(t *testing.T) {
	configRoot := t.TempDir()
	t.Setenv("XRAY_LOCATION_CONFIG", configRoot)
	certDir := filepath.Join(configRoot, "cert", "panel")
	if err := os.MkdirAll(certDir, 0o700); err != nil {
		t.Fatal(err)
	}
	certPath := filepath.Join(certDir, "node.example.com.crt")
	keyPath := filepath.Join(certDir, "node.example.com.key")
	if err := os.WriteFile(certPath, []byte("last-known-good-cert"), filePerm); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(keyPath, 0o700); err != nil {
		t.Fatal(err)
	}

	_, _, err := ContentCert(&CertConfig{
		CertDomain:  "node.example.com",
		CertContent: "candidate-cert",
		KeyContent:  "candidate-key",
	})

	if err == nil {
		t.Fatal("ContentCert returned nil error with an unwritable key target")
	}
	assertFileContent(t, certPath, "last-known-good-cert")
}

func TestContentCertRejectsSymlinkedCertificateDirectory(t *testing.T) {
	configRoot := t.TempDir()
	outsideRoot := t.TempDir()
	t.Setenv("XRAY_LOCATION_CONFIG", configRoot)

	certRoot := filepath.Join(configRoot, "cert")
	if err := os.Symlink(outsideRoot, certRoot); err != nil {
		t.Skipf("symbolic links are unavailable: %v", err)
	}

	_, _, err := ContentCert(&CertConfig{
		CertDomain:  "node.example.com",
		CertContent: "candidate-cert",
		KeyContent:  "candidate-key",
	})

	if err == nil {
		t.Fatal("ContentCert accepted a symlinked certificate directory")
	}
	outsideCert := filepath.Join(outsideRoot, "panel", "node.example.com.crt")
	if _, statErr := os.Stat(outsideCert); !errors.Is(statErr, os.ErrNotExist) {
		t.Fatalf("outside certificate path was modified: %v", statErr)
	}
	if _, statErr := os.Stat(filepath.Join(outsideRoot, "panel")); !errors.Is(statErr, os.ErrNotExist) {
		t.Fatalf("outside certificate directory was modified: %v", statErr)
	}
}

func TestCheckCertFileRejectsNonRegularCertificatePaths(t *testing.T) {
	root := t.TempDir()
	certificatesRoot := filepath.Join(root, "certificates")
	if err := os.MkdirAll(certificatesRoot, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(filepath.Join(certificatesRoot, "node.example.com.crt"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(certificatesRoot, "node.example.com.key"), []byte("key"), filePerm); err != nil {
		t.Fatal(err)
	}

	if certPath, keyPath, err := checkCertFile(root, "node.example.com"); err == nil {
		t.Fatalf("checkCertFile accepted non-regular paths: cert=%q key=%q", certPath, keyPath)
	}
}

func TestCertificateOperationSerializesAndConvertsPanic(t *testing.T) {
	entered := make(chan struct{})
	release := make(chan struct{})
	done := make(chan error, 1)
	go func() {
		done <- executeCertificateOperation(nil, func() error {
			close(entered)
			<-release
			return nil
		})
	}()
	<-entered

	if certificateOperationMu.TryLock() {
		certificateOperationMu.Unlock()
		t.Fatal("certificate operation did not hold the serialization lock")
	}
	close(release)
	if err := <-done; err != nil {
		t.Fatalf("serialized operation failed: %v", err)
	}

	panicErr := errors.New("certificate panic")
	err := executeCertificateOperation(nil, func() error {
		panic(panicErr)
	})
	if !errors.Is(err, panicErr) {
		t.Fatalf("panic error = %v, want %v", err, panicErr)
	}
}

func TestRunAndRenewConvertPanicsToErrors(t *testing.T) {
	t.Run("run", func(t *testing.T) {
		lego := &LegoCMD{}
		if err := lego.Run(); err == nil {
			t.Fatal("Run returned nil error for invalid state")
		}
	})
	t.Run("renew", func(t *testing.T) {
		lego := &LegoCMD{}
		if renewed, err := lego.Renew(); err == nil {
			t.Fatalf("Renew = %v, nil; want error", renewed)
		}
	})
}

func TestCertificateStoragePanicsWithoutLoggingSensitiveError(t *testing.T) {
	logger := logrus.StandardLogger()
	originalOutput := logger.Out
	buffer := &bytes.Buffer{}
	logger.SetOutput(buffer)
	t.Cleanup(func() {
		logger.SetOutput(originalOutput)
	})

	const secret = "token=acme-sensitive-value"
	storage := NewCertificatesStorage(t.TempDir())
	storage.ops.renameFile = func(string, string) error {
		return errors.New(secret)
	}

	var recovered any
	func() {
		defer func() {
			recovered = recover()
		}()
		storage.SaveResource(&certificate.Resource{
			Domain:      "node.example.com",
			Certificate: []byte("candidate-cert"),
			PrivateKey:  []byte("candidate-key"),
		})
	}()

	if recovered == nil {
		t.Fatal("SaveResource() did not preserve its panic contract")
	}
	if strings.Contains(buffer.String(), secret) {
		t.Fatalf("certificate storage logged sensitive error before recovery: %q", buffer.String())
	}
}

func TestCertificatesStorageRejectsPathLikeExtension(t *testing.T) {
	root := t.TempDir()
	storage := NewCertificatesStorage(root)
	outsidePath := filepath.Join(root, "escaped-certificate")

	err := storage.WriteFile("node.example.com", `/../../escaped-certificate`, []byte("secret"))

	if err == nil {
		t.Fatal("WriteFile() accepted a path-like extension")
	}
	if _, statErr := os.Stat(outsidePath); !errors.Is(statErr, os.ErrNotExist) {
		t.Fatalf("extension escaped certificate storage: %v", statErr)
	}
}

func TestCertificatesStorageRejectsPathLikeDomainWithoutAliasing(t *testing.T) {
	root := t.TempDir()
	writeCertificatePair(
		t,
		root,
		"node.example.com",
		"last-known-good-cert",
		"last-known-good-key",
	)
	storage := NewCertificatesStorage(root)

	if _, err := storage.ReadFile("../node.example.com", ".crt"); err == nil {
		t.Fatal("ReadFile() aliased a path-like domain to another certificate")
	}
	if certPath, keyPath, err := checkCertFile(root, "../node.example.com"); err == nil {
		t.Fatalf(
			"checkCertFile() aliased a path-like domain: cert=%q key=%q",
			certPath,
			keyPath,
		)
	}
}

func TestCertificatesStorageRejectsTransactionReservedDomain(t *testing.T) {
	root := t.TempDir()
	storage := NewCertificatesStorage(root)
	const domain = ".xrayrp-certificate-transaction"

	err := storage.StoreResource(&certificate.Resource{
		Domain:      domain,
		Certificate: []byte("candidate-cert"),
		PrivateKey:  []byte("candidate-key"),
	})

	if err == nil {
		t.Fatal("StoreResource() accepted the certificate transaction reserved domain")
	}
	for _, extension := range []string{".crt", ".key", ".json"} {
		path := filepath.Join(storage.rootPath, domain+extension)
		if _, statErr := os.Stat(path); !errors.Is(statErr, os.ErrNotExist) {
			t.Fatalf("reserved certificate path %s was published: %v", path, statErr)
		}
	}
}

func TestCertificatesStorageRejectsNTFSAlternateDataStreamExtension(t *testing.T) {
	storage := NewCertificatesStorage(t.TempDir())

	err := storage.WriteFile("node.example.com", ":stream", []byte("secret"))

	if err == nil {
		t.Fatal("WriteFile() accepted an NTFS alternate-data-stream extension")
	}
}

func TestCertificatesStoragePreservesWildcardFileNameMapping(t *testing.T) {
	storage := NewCertificatesStorage(t.TempDir())

	path, err := storage.fileName("*.example.com", ".crt")
	if err != nil {
		t.Fatalf("fileName() wildcard domain error = %v", err)
	}
	if got, want := filepath.Base(path), "_.example.com.crt"; got != want {
		t.Fatalf("fileName() wildcard base = %q, want %q", got, want)
	}
}

func TestCertificatesStorageRollsBackOnMetadataPublishFailure(t *testing.T) {
	root := t.TempDir()
	storage := NewCertificatesStorage(root)
	if err := os.MkdirAll(storage.rootPath, 0o700); err != nil {
		t.Fatal(err)
	}
	domain := "node.example.com"
	oldFiles := map[string]string{
		".crt":  "last-known-good-cert",
		".key":  "last-known-good-key",
		".json": `{"domain":"last-known-good"}`,
	}
	for extension, content := range oldFiles {
		if err := os.WriteFile(storage.GetFileName(domain, extension), []byte(content), filePerm); err != nil {
			t.Fatal(err)
		}
	}

	metadataErr := errors.New("metadata publish failed")
	storage.ops.renameFile = func(oldPath, newPath string) error {
		if strings.HasSuffix(newPath, ".json") {
			return metadataErr
		}
		return replaceFile(oldPath, newPath)
	}

	err := storage.StoreResource(&certificate.Resource{
		Domain:      domain,
		Certificate: []byte("candidate-cert"),
		PrivateKey:  []byte("candidate-key"),
	})

	if !errors.Is(err, metadataErr) {
		t.Fatalf("StoreResource error = %v, want %v", err, metadataErr)
	}
	for extension, want := range oldFiles {
		assertFileContent(t, storage.GetFileName(domain, extension), want)
	}
}

func TestCertificatesStorageJoinsPublishAndRollbackFailures(t *testing.T) {
	root := t.TempDir()
	storage := NewCertificatesStorage(root)
	if err := os.MkdirAll(storage.rootPath, 0o700); err != nil {
		t.Fatal(err)
	}
	domain := "node.example.com"
	for extension, content := range map[string]string{
		".crt":  "last-known-good-cert",
		".key":  "last-known-good-key",
		".json": `{"domain":"last-known-good"}`,
	} {
		if err := os.WriteFile(storage.GetFileName(domain, extension), []byte(content), filePerm); err != nil {
			t.Fatal(err)
		}
	}

	publishErr := errors.New("metadata publish failed")
	rollbackErr := errors.New("private key rollback failed")
	targetCalls := make(map[string]int)
	storage.ops.renameFile = func(oldPath, newPath string) error {
		targetCalls[newPath]++
		switch {
		case strings.HasSuffix(newPath, ".json"):
			return publishErr
		case strings.HasSuffix(newPath, ".key") && targetCalls[newPath] == 2:
			return rollbackErr
		default:
			return replaceFile(oldPath, newPath)
		}
	}

	err := storage.StoreResource(&certificate.Resource{
		Domain:      domain,
		Certificate: []byte("candidate-cert"),
		PrivateKey:  []byte("candidate-key"),
	})

	if !errors.Is(err, publishErr) || !errors.Is(err, rollbackErr) {
		t.Fatalf("StoreResource error = %v, want publish %v and rollback %v", err, publishErr, rollbackErr)
	}
}

func TestFileTransactionCommitSyncFailureKeepsRecoverySnapshotsWhenRollbackFails(t *testing.T) {
	dir := t.TempDir()
	certPath := filepath.Join(dir, "node.example.com.crt")
	keyPath := filepath.Join(dir, "node.example.com.key")
	for path, content := range map[string]string{
		certPath: "last-known-good-cert",
		keyPath:  "last-known-good-key",
	} {
		if err := os.WriteFile(path, []byte(content), filePerm); err != nil {
			t.Fatal(err)
		}
	}

	commitSyncErr := errors.New("commit journal directory sync failed")
	rollbackErr := errors.New("private key rollback failed")
	syncCalls := 0
	syncDir := func(string) error {
		syncCalls++
		if syncCalls >= 4 {
			return commitSyncErr
		}
		return nil
	}
	targetCalls := make(map[string]int)
	renameFile := func(source, target string) error {
		targetCalls[target]++
		if target == keyPath && targetCalls[target] == 2 {
			return rollbackErr
		}
		return replaceFile(source, target)
	}

	err := writeFileTransactionWithSync(
		[]fileTransactionEntry{
			{path: certPath, data: []byte("candidate-cert"), perm: filePerm},
			{path: keyPath, data: []byte("candidate-key"), perm: filePerm},
		},
		renameFile,
		syncDir,
	)

	if !errors.Is(err, commitSyncErr) || !errors.Is(err, rollbackErr) {
		t.Fatalf("writeFileTransactionWithSync() error = %v, want sync %v and rollback %v", err, commitSyncErr, rollbackErr)
	}
	if err := recoverFileTransaction(dir); err != nil {
		t.Fatalf("recoverFileTransaction() error = %v", err)
	}
	assertFileContent(t, certPath, "last-known-good-cert")
	assertFileContent(t, keyPath, "last-known-good-key")
}

func TestFileTransactionCommitFailureRecoversAfterJournalRestoreAndFileRollbackFail(t *testing.T) {
	dir := t.TempDir()
	certPath := filepath.Join(dir, "node.example.com.crt")
	keyPath := filepath.Join(dir, "node.example.com.key")
	for path, content := range map[string]string{
		certPath: "last-known-good-cert",
		keyPath:  "last-known-good-key",
	} {
		if err := os.WriteFile(path, []byte(content), filePerm); err != nil {
			t.Fatal(err)
		}
	}

	commitSyncErr := errors.New("commit journal directory sync failed")
	journalRestoreErr := errors.New("recoverable journal restore failed")
	rollbackErr := errors.New("private key rollback failed")
	syncCalls := 0
	syncDir := func(string) error {
		syncCalls++
		if syncCalls == 4 {
			return commitSyncErr
		}
		return nil
	}
	journalReplaces := 0
	replaceJournal := func(source, target string) error {
		journalReplaces++
		if journalReplaces == 3 {
			return journalRestoreErr
		}
		return replaceFile(source, target)
	}
	targetCalls := make(map[string]int)
	renameFile := func(source, target string) error {
		targetCalls[target]++
		if target == keyPath && targetCalls[target] == 2 {
			return rollbackErr
		}
		return replaceFile(source, target)
	}

	err := writeFileTransactionWithOperations(
		[]fileTransactionEntry{
			{path: certPath, data: []byte("candidate-cert"), perm: filePerm},
			{path: keyPath, data: []byte("candidate-key"), perm: filePerm},
		},
		renameFile,
		replaceJournal,
		syncDir,
	)

	if !errors.Is(err, commitSyncErr) ||
		!errors.Is(err, journalRestoreErr) ||
		!errors.Is(err, rollbackErr) {
		t.Fatalf(
			"writeFileTransactionWithOperations() error = %v, want sync %v, journal restore %v, and rollback %v",
			err,
			commitSyncErr,
			journalRestoreErr,
			rollbackErr,
		)
	}
	if err := recoverFileTransaction(dir); err != nil {
		t.Fatalf("recoverFileTransaction() error = %v", err)
	}
	assertFileContent(t, certPath, "last-known-good-cert")
	assertFileContent(t, keyPath, "last-known-good-key")
}

func TestFileTransactionRecoveryRollsBackMixedCommittedStateWithSnapshots(t *testing.T) {
	dir := t.TempDir()
	certPath := filepath.Join(dir, "node.example.com.crt")
	keyPath := filepath.Join(dir, "node.example.com.key")
	if err := os.WriteFile(certPath, []byte("candidate-cert"), filePerm); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(keyPath, []byte("last-known-good-key"), filePerm); err != nil {
		t.Fatal(err)
	}

	journal := fileTransactionJournal{
		Committed: true,
		Entries: []fileTransactionJournalEntry{
			{
				Name:    filepath.Base(certPath),
				Existed: true,
				Data:    []byte("last-known-good-cert"),
				Perm:    filePerm,
			},
			{
				Name:    filepath.Base(keyPath),
				Existed: true,
				Data:    []byte("last-known-good-key"),
				Perm:    filePerm,
			},
		},
	}
	journalData, err := json.Marshal(journal)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(
		filepath.Join(dir, fileTransactionJournalName),
		journalData,
		filePerm,
	); err != nil {
		t.Fatal(err)
	}

	if err := recoverFileTransaction(dir); err != nil {
		t.Fatalf("recoverFileTransaction() error = %v", err)
	}

	assertFileContent(t, certPath, "last-known-good-cert")
	assertFileContent(t, keyPath, "last-known-good-key")
}

func TestFileTransactionRecoveryRemovesOrphanedStagedSecret(t *testing.T) {
	dir := t.TempDir()
	tempPath, err := stageFile(fileTransactionEntry{
		path: filepath.Join(dir, "node.example.com.key"),
		data: []byte("orphaned-candidate-private-key"),
		perm: filePerm,
	})
	if err != nil {
		t.Fatal(err)
	}

	if err := recoverFileTransaction(dir); err != nil {
		t.Fatalf("recoverFileTransaction() error = %v", err)
	}

	if _, err := os.Stat(tempPath); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("orphaned staged private key still exists after recovery: %v", err)
	}
}

func TestCertificatesStorageRecoversInterruptedPublicationBeforeRead(t *testing.T) {
	root := t.TempDir()
	storage := NewCertificatesStorage(root)
	if err := os.MkdirAll(storage.rootPath, 0o700); err != nil {
		t.Fatal(err)
	}
	domain := "node.example.com"
	oldFiles := map[string]string{
		".crt":  "last-known-good-cert",
		".key":  "last-known-good-key",
		".json": `{"domain":"last-known-good"}`,
	}
	for extension, content := range oldFiles {
		if err := os.WriteFile(storage.GetFileName(domain, extension), []byte(content), filePerm); err != nil {
			t.Fatal(err)
		}
	}

	publishes := 0
	storage.ops.renameFile = func(source, target string) error {
		publishes++
		if publishes == 2 {
			panic("simulated process interruption")
		}
		return replaceFile(source, target)
	}
	err := storage.StoreResource(&certificate.Resource{
		Domain:      domain,
		Certificate: []byte("candidate-cert"),
		PrivateKey:  []byte("candidate-key"),
	})
	if err == nil {
		t.Fatal("StoreResource() returned nil after simulated interruption")
	}

	storage.ops.renameFile = replaceFile
	for extension, want := range oldFiles {
		got, readErr := storage.ReadFile(domain, extension)
		if readErr != nil {
			t.Fatalf("ReadFile(%q) after interrupted publication: %v", extension, readErr)
		}
		if string(got) != want {
			t.Fatalf("ReadFile(%q) after recovery = %q, want %q", extension, got, want)
		}
	}
}

func TestCertificatesStorageHoldsRecoveryLockDuringPublication(t *testing.T) {
	storage := NewCertificatesStorage(t.TempDir())
	entered := make(chan struct{})
	release := make(chan struct{})
	storage.ops.renameFile = func(source, target string) error {
		if strings.HasSuffix(target, ".crt") {
			close(entered)
			<-release
		}
		return replaceFile(source, target)
	}

	done := make(chan error, 1)
	go func() {
		done <- storage.StoreResource(&certificate.Resource{
			Domain:      "node.example.com",
			Certificate: []byte("candidate-cert"),
			PrivateKey:  []byte("candidate-key"),
		})
	}()
	<-entered

	if fileTransactionMu.TryLock() {
		fileTransactionMu.Unlock()
		close(release)
		<-done
		t.Fatal("certificate publication did not exclude concurrent recovery")
	}
	close(release)
	if err := <-done; err != nil {
		t.Fatalf("StoreResource() error = %v", err)
	}
}

func TestAccountPrivateKeyRecoversInterruptedPublication(t *testing.T) {
	dir := t.TempDir()
	keyPath := filepath.Join(dir, "account.key")
	var recovered any
	func() {
		defer func() { recovered = recover() }()
		_, _ = generatePrivateKeyWithRename(keyPath, certcrypto.EC256, func(string, string) error {
			panic("simulated process interruption")
		})
	}()
	if recovered == nil {
		t.Fatal("private-key publication did not reach the injected interruption")
	}

	if err := recoverFileTransaction(dir); err != nil {
		t.Fatalf("recoverFileTransaction() error = %v", err)
	}
	if _, err := os.Stat(keyPath); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("interrupted account key remains after recovery: %v", err)
	}
	if _, err := os.Stat(filepath.Join(dir, fileTransactionJournalName)); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("account key transaction journal remains after recovery: %v", err)
	}
}

func TestAccountsStorageRecoversInterruptedPrivateKeyBeforeRead(t *testing.T) {
	t.Setenv("XRAY_LOCATION_CONFIG", t.TempDir())
	lego, err := New(&CertConfig{
		CertMode:   "dns",
		CertDomain: "node.example.com",
		Email:      "ops@example.com",
	})
	if err != nil {
		t.Fatal(err)
	}
	storage := NewAccountsStorage(lego)
	if err := os.MkdirAll(storage.keysPath, 0o700); err != nil {
		t.Fatal(err)
	}
	keyPath := filepath.Join(storage.keysPath, storage.userID+".key")

	var interrupted any
	func() {
		defer func() { interrupted = recover() }()
		_, _ = generatePrivateKeyWithRename(keyPath, certcrypto.EC256, func(source, target string) error {
			if err := replaceFile(source, target); err != nil {
				return err
			}
			panic("simulated interruption after private-key publication")
		})
	}()
	if interrupted == nil {
		t.Fatal("private-key publication did not reach the injected interruption")
	}

	if key := storage.GetPrivateKey(certcrypto.EC256); key == nil {
		t.Fatal("GetPrivateKey() returned nil after recovering interrupted publication")
	}
	if _, err := os.Stat(filepath.Join(storage.keysPath, fileTransactionJournalName)); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("production private-key read left transaction journal behind: %v", err)
	}
}

func TestCertificatesStorageRemovesStaleOptionalFilesTransactionally(t *testing.T) {
	root := t.TempDir()
	storage := NewCertificatesStorage(root)
	storage.pem = true
	if err := os.MkdirAll(storage.rootPath, 0o700); err != nil {
		t.Fatal(err)
	}
	domain := "node.example.com"
	for extension, content := range map[string]string{
		".crt":        "last-known-good-cert",
		".key":        "last-known-good-key",
		".issuer.crt": "stale-issuer",
		".pem":        "stale-combined-pem",
		".json":       `{"domain":"last-known-good"}`,
	} {
		if err := os.WriteFile(storage.GetFileName(domain, extension), []byte(content), filePerm); err != nil {
			t.Fatal(err)
		}
	}

	storage.pem = false
	err := storage.StoreResource(&certificate.Resource{
		Domain:      domain,
		Certificate: []byte("candidate-cert"),
		PrivateKey:  []byte("candidate-key"),
	})
	if err != nil {
		t.Fatalf("StoreResource() error = %v", err)
	}

	for _, extension := range []string{".issuer.crt", ".pem"} {
		if _, statErr := os.Stat(storage.GetFileName(domain, extension)); !errors.Is(statErr, os.ErrNotExist) {
			t.Fatalf("stale optional file %s remains: %v", extension, statErr)
		}
	}
}

func TestCertificatesStoragePreservesExistingPrivateKeyForCSRResource(t *testing.T) {
	root := t.TempDir()
	storage := NewCertificatesStorage(root)
	if err := os.MkdirAll(storage.rootPath, 0o700); err != nil {
		t.Fatal(err)
	}
	const domain = "node.example.com"
	keyPath := storage.GetFileName(domain, ".key")
	if err := os.WriteFile(keyPath, []byte("last-known-good-key"), filePerm); err != nil {
		t.Fatal(err)
	}

	err := storage.StoreResource(&certificate.Resource{
		Domain:      domain,
		Certificate: []byte("csr-certificate"),
	})

	if err != nil {
		t.Fatalf("StoreResource() CSR resource error = %v", err)
	}
	assertFileContent(t, keyPath, "last-known-good-key")
}

func TestPreparedRenewalKeepsCandidatePrivateUntilCommit(t *testing.T) {
	root := t.TempDir()
	storage := NewCertificatesStorage(root)
	if err := os.MkdirAll(storage.rootPath, 0o700); err != nil {
		t.Fatal(err)
	}
	domain := "node.example.com"
	oldFiles := map[string]string{
		".crt":  "last-known-good-cert",
		".key":  "last-known-good-key",
		".json": `{"domain":"last-known-good"}`,
	}
	for extension, content := range oldFiles {
		if err := os.WriteFile(storage.GetFileName(domain, extension), []byte(content), filePerm); err != nil {
			t.Fatal(err)
		}
	}

	prepared := newPreparedRenewal(storage, &certificate.Resource{
		Domain:      domain,
		Certificate: []byte("candidate-cert"),
		PrivateKey:  []byte("candidate-key"),
	}, true, false)

	if got := string(prepared.CertificatePEM()); got != "candidate-cert" {
		t.Fatalf("candidate certificate = %q", got)
	}
	for extension, want := range oldFiles {
		assertFileContent(t, storage.GetFileName(domain, extension), want)
	}

	if err := prepared.Commit(); err != nil {
		t.Fatalf("Commit() error = %v", err)
	}
	assertFileContent(t, storage.GetFileName(domain, ".crt"), "candidate-cert")
	assertFileContent(t, storage.GetFileName(domain, ".key"), "candidate-key")
}

func TestPreparedRenewalRollbackPreservesLastKnownGoodFiles(t *testing.T) {
	root := t.TempDir()
	storage := NewCertificatesStorage(root)
	if err := os.MkdirAll(storage.rootPath, 0o700); err != nil {
		t.Fatal(err)
	}
	domain := "node.example.com"
	certPath := storage.GetFileName(domain, ".crt")
	keyPath := storage.GetFileName(domain, ".key")
	if err := os.WriteFile(certPath, []byte("last-known-good-cert"), filePerm); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(keyPath, []byte("last-known-good-key"), filePerm); err != nil {
		t.Fatal(err)
	}

	prepared := newPreparedRenewal(storage, &certificate.Resource{
		Domain:      domain,
		Certificate: []byte("candidate-cert"),
		PrivateKey:  []byte("candidate-key"),
	}, true, false)

	if err := prepared.Rollback(); err != nil {
		t.Fatalf("Rollback() error = %v", err)
	}
	assertFileContent(t, certPath, "last-known-good-cert")
	assertFileContent(t, keyPath, "last-known-good-key")
}

func writeCertificatePair(t *testing.T, root, domain, cert, key string) {
	t.Helper()
	storage := NewCertificatesStorage(root)
	if err := os.MkdirAll(storage.rootPath, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(storage.GetFileName(domain, ".crt"), []byte(cert), filePerm); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(storage.GetFileName(domain, ".key"), []byte(key), filePerm); err != nil {
		t.Fatal(err)
	}
}

func preserveEnvironment(t *testing.T, key string) func() {
	t.Helper()
	value, exists := os.LookupEnv(key)
	return func() {
		if exists {
			_ = os.Setenv(key, value)
			return
		}
		_ = os.Unsetenv(key)
	}
}
