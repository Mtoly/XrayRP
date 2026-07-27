//go:build windows

package mylego

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
)

func TestReplaceFileReplacesExistingTargetWithoutSensitiveBackup(t *testing.T) {
	dir := t.TempDir()
	source := filepath.Join(dir, "candidate.tmp")
	target := filepath.Join(dir, "node.key")
	if err := os.WriteFile(source, []byte("candidate-private-key"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(target, []byte("last-known-good-private-key"), 0o600); err != nil {
		t.Fatal(err)
	}

	if err := replaceFile(source, target); err != nil {
		t.Fatalf("replaceFile() error = %v", err)
	}
	content, err := os.ReadFile(target)
	if err != nil {
		t.Fatal(err)
	}
	if string(content) != "candidate-private-key" {
		t.Fatalf("replacement content = %q", content)
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	for _, entry := range entries {
		if strings.Contains(entry.Name(), "backup") {
			t.Fatalf("sensitive replacement backup remains: %s", entry.Name())
		}
	}
}

func TestSyncDirectoryFlushesDirectoryHandle(t *testing.T) {
	if err := syncDirectory(t.TempDir()); err != nil {
		t.Fatalf("syncDirectory() error = %v", err)
	}
}

func TestCommittedJournalCleanupFailureDoesNotHidePublishedCertificate(t *testing.T) {
	storage := NewCertificatesStorage(t.TempDir())
	if err := os.MkdirAll(storage.rootPath, 0o700); err != nil {
		t.Fatal(err)
	}
	certPath := storage.GetFileName("node.example.com", ".crt")
	if err := os.WriteFile(certPath, []byte("committed-certificate"), filePerm); err != nil {
		t.Fatal(err)
	}
	journalData, err := json.Marshal(fileTransactionJournal{
		Committed: true,
		Entries: []fileTransactionJournalEntry{{
			Name: filepath.Base(certPath),
		}},
	})
	if err != nil {
		t.Fatal(err)
	}
	journalPath := filepath.Join(storage.rootPath, fileTransactionJournalName)
	if err := os.WriteFile(journalPath, journalData, 0o600); err != nil {
		t.Fatal(err)
	}
	journalPathUTF16, err := syscall.UTF16PtrFromString(journalPath)
	if err != nil {
		t.Fatal(err)
	}
	handle, err := syscall.CreateFile(
		journalPathUTF16,
		syscall.GENERIC_READ,
		syscall.FILE_SHARE_READ|syscall.FILE_SHARE_WRITE,
		nil,
		syscall.OPEN_EXISTING,
		syscall.FILE_ATTRIBUTE_NORMAL,
		0,
	)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = syscall.CloseHandle(handle) })

	content, err := storage.ReadFile("node.example.com", ".crt")
	if err != nil {
		t.Fatalf("ReadFile() rejected committed state after cleanup failure: %v", err)
	}
	if string(content) != "committed-certificate" {
		t.Fatalf("ReadFile() content = %q", content)
	}
}
