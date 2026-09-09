package mylego

import (
	"crypto"
	"encoding/pem"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestLoadPrivateKeyRejectsMalformedPEMWithoutPanic(t *testing.T) {
	keyPath := filepath.Join(t.TempDir(), "account.key")
	if err := os.WriteFile(keyPath, []byte("not PEM"), 0o600); err != nil {
		t.Fatal(err)
	}

	var (
		key crypto.PrivateKey
		err error
	)
	func() {
		defer func() {
			if recovered := recover(); recovered != nil {
				t.Fatalf("loadPrivateKey panicked: %v", recovered)
			}
		}()
		key, err = loadPrivateKey(keyPath)
	}()
	if key != nil {
		t.Fatalf("loadPrivateKey returned key for malformed PEM: %T", key)
	}
	if err == nil || !strings.Contains(err.Error(), "block not found") {
		t.Fatalf("loadPrivateKey error = %v, want PEM block error", err)
	}
}

func TestLoadPrivateKeyRejectsTrailingPEMData(t *testing.T) {
	keyPath := filepath.Join(t.TempDir(), "account.key")
	if err := os.WriteFile(keyPath, append(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: []byte("invalid")}), []byte("extra")...), 0o600); err != nil {
		t.Fatal(err)
	}

	key, err := loadPrivateKey(keyPath)
	if key != nil {
		t.Fatalf("loadPrivateKey returned key for trailing data: %T", key)
	}
	if err == nil || !strings.Contains(err.Error(), "trailing data") {
		t.Fatalf("loadPrivateKey error = %v, want trailing-data error", err)
	}
}

func TestLoadPrivateKeyRejectsUnsupportedPEMType(t *testing.T) {
	keyPath := filepath.Join(t.TempDir(), "account.key")
	if err := os.WriteFile(keyPath, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: []byte("invalid")}), 0o600); err != nil {
		t.Fatal(err)
	}

	key, err := loadPrivateKey(keyPath)
	if key != nil {
		t.Fatalf("loadPrivateKey returned key for unsupported PEM type: %T", key)
	}
	if err == nil || !strings.Contains(err.Error(), "unknown account private key type") {
		t.Fatalf("loadPrivateKey error = %v, want unsupported-type error", err)
	}
}
