package mylego

import (
	"bytes"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/go-acme/lego/v4/certcrypto"
	"github.com/go-acme/lego/v4/certificate"
	"golang.org/x/net/idna"
)

const (
	baseCertificatesFolderName = "certificates"
)

// CertificatesStorage a certificates' storage.
//
// rootPath:
//
//	./.lego/certificates/
//	     │      └── root certificates directory
//	     └── "path" option
//
// archivePath:
//
//	./.lego/archives/
//	     │      └── archived certificates directory
//	     └── "path" option
type CertificatesStorage struct {
	rootPath string
	pem      bool
	ops      *fileTransactionOps
}

type fileTransactionOps struct {
	renameFile func(string, string) error
}

// NewCertificatesStorage create a new certificates storage.
func NewCertificatesStorage(path string) *CertificatesStorage {
	return &CertificatesStorage{
		rootPath: filepath.Join(path, baseCertificatesFolderName),
		ops:      &fileTransactionOps{renameFile: replaceFile},
	}
}

func (s *CertificatesStorage) CreateRootFolder() {
	if err := s.createRootFolder(); err != nil {
		panic(fmt.Errorf("check or create certificate path: %w", err))
	}
}

func (s *CertificatesStorage) createRootFolder() error {
	if err := rejectSymlinkPathComponents(filepath.Join(s.rootPath, ".certificate-root")); err != nil {
		return err
	}
	return createNonExistingFolder(s.rootPath)
}

func (s *CertificatesStorage) GetRootPath() string {
	return s.rootPath
}

func (s *CertificatesStorage) SaveResource(certRes *certificate.Resource) {
	if err := s.StoreResource(certRes); err != nil {
		panic(err)
	}
}

// StoreResource persists the certificate, private key, issuer, and metadata as
// one recoverable transaction.
func (s *CertificatesStorage) StoreResource(certRes *certificate.Resource) error {
	return executeCertificateOperation(nil, func() error {
		return s.storeResource(certRes)
	})
}

func (s *CertificatesStorage) storeResource(certRes *certificate.Resource) error {
	if certRes == nil {
		return errors.New("certificate resource is nil")
	}
	if err := s.createRootFolder(); err != nil {
		return err
	}

	domain := certRes.Domain
	safeDomain, err := sanitizeDomain(domain)
	if err != nil {
		return err
	}
	filePath := func(extension string) string {
		return filepath.Join(s.rootPath, safeDomain+extension)
	}

	entries := []fileTransactionEntry{
		{path: filePath(".crt"), data: certRes.Certificate, perm: filePerm},
	}
	if certRes.IssuerCertificate != nil {
		entries = append(entries, fileTransactionEntry{
			path: filePath(".issuer.crt"),
			data: certRes.IssuerCertificate,
			perm: filePerm,
		})
	} else {
		entries = append(entries, fileTransactionEntry{
			path:   filePath(".issuer.crt"),
			remove: true,
		})
	}
	if certRes.PrivateKey != nil {
		entries = append(entries, fileTransactionEntry{
			path: filePath(".key"),
			data: certRes.PrivateKey,
			perm: filePerm,
		})
		if s.pem {
			entries = append(entries, fileTransactionEntry{
				path: filePath(".pem"),
				data: bytes.Join([][]byte{certRes.Certificate, certRes.PrivateKey}, nil),
				perm: filePerm,
			})
		}
	} else if s.pem {
		return fmt.Errorf("unable to save pem without private key for domain %s; are you using a CSR?", domain)
	}
	if !s.pem {
		entries = append(entries, fileTransactionEntry{
			path:   filePath(".pem"),
			remove: true,
		})
	}

	jsonBytes, err := json.MarshalIndent(certRes, "", "\t")
	if err != nil {
		return fmt.Errorf("marshal certificate metadata for domain %s: %w", domain, err)
	}
	entries = append(entries, fileTransactionEntry{
		path: filePath(".json"),
		data: jsonBytes,
		perm: filePerm,
	})
	return writeFileTransaction(entries, s.rename())
}

func (s *CertificatesStorage) ReadResource(domain string) certificate.Resource {
	raw, err := s.ReadFile(domain, ".json")
	if err != nil {
		panic(fmt.Errorf("load certificate metadata for domain %s: %w", domain, err))
	}

	var resource certificate.Resource
	if err = json.Unmarshal(raw, &resource); err != nil {
		panic(fmt.Errorf("parse certificate metadata for domain %s: %w", domain, err))
	}

	return resource
}

func (s *CertificatesStorage) ExistsFile(domain, extension string) bool {
	filePath, err := s.fileName(domain, extension)
	if err != nil {
		panic(err)
	}
	if err := recoverFileTransaction(filepath.Dir(filePath)); err != nil {
		panic(err)
	}

	if err := validateExistingRegularFile(filePath); errors.Is(err, os.ErrNotExist) {
		return false
	} else if err != nil {
		panic(err)
	}
	return true
}

func (s *CertificatesStorage) ReadFile(domain, extension string) ([]byte, error) {
	filePath, err := s.fileName(domain, extension)
	if err != nil {
		return nil, err
	}
	if err := recoverFileTransaction(filepath.Dir(filePath)); err != nil {
		return nil, err
	}
	if err := validateExistingRegularFile(filePath); err != nil {
		return nil, err
	}
	return os.ReadFile(filePath)
}

func (s *CertificatesStorage) GetFileName(domain, extension string) string {
	filename, err := s.fileName(domain, extension)
	if err != nil {
		panic(err)
	}
	return filename
}

func (s *CertificatesStorage) ReadCertificate(domain, extension string) ([]*x509.Certificate, error) {
	content, err := s.ReadFile(domain, extension)
	if err != nil {
		return nil, err
	}

	// The input may be a bundle or a single certificate.
	return certcrypto.ParsePEMBundle(content)
}

func (s *CertificatesStorage) WriteFile(domain, extension string, data []byte) error {
	filePath, err := s.fileName(domain, extension)
	if err != nil {
		return err
	}

	return executeCertificateOperation(nil, func() error {
		return writeFileTransaction([]fileTransactionEntry{{
			path: filePath,
			data: data,
			perm: filePerm,
		}}, s.rename())
	})
}

func (s *CertificatesStorage) rename() func(string, string) error {
	if s == nil || s.ops == nil || s.ops.renameFile == nil {
		return replaceFile
	}
	return s.ops.renameFile
}

func (s *CertificatesStorage) fileName(domain, extension string) (string, error) {
	if s == nil || strings.TrimSpace(s.rootPath) == "" {
		return "", errors.New("certificate storage path is empty")
	}
	if err := validateCertificateExtension(extension); err != nil {
		return "", err
	}
	baseFileName, err := sanitizeDomain(domain)
	if err != nil {
		return "", err
	}
	return filepath.Join(s.rootPath, baseFileName+extension), nil
}

func validateCertificateExtension(extension string) error {
	if extension == "" || strings.TrimSpace(extension) != extension {
		return errors.New("certificate extension is empty or contains surrounding whitespace")
	}
	if strings.Contains(extension, "..") ||
		strings.ContainsAny(extension, `/\:`) ||
		strings.ContainsRune(extension, '\x00') ||
		filepath.IsAbs(extension) ||
		filepath.VolumeName(extension) != "" {
		return errors.New("certificate extension must not contain path syntax")
	}
	return nil
}

// sanitizedDomain Make sure no funny chars are in the cert names (like wildcards ;)).
func sanitizedDomain(domain string) string {
	safe, err := sanitizeDomain(domain)
	if err != nil {
		panic(err)
	}
	return safe
}

func sanitizeDomain(domain string) (string, error) {
	if domain == "" || strings.TrimSpace(domain) != domain {
		return "", errors.New("certificate domain is empty or contains surrounding whitespace")
	}
	wildcard := strings.HasPrefix(domain, "*.")
	lookupDomain := domain
	if wildcard {
		lookupDomain = strings.TrimPrefix(domain, "*.")
	}
	if lookupDomain == "" ||
		strings.ContainsRune(lookupDomain, '*') ||
		strings.Contains(lookupDomain, "..") ||
		strings.ContainsAny(lookupDomain, `/\:`) ||
		strings.ContainsRune(lookupDomain, '\x00') ||
		filepath.IsAbs(lookupDomain) ||
		filepath.VolumeName(lookupDomain) != "" {
		return "", errors.New("certificate domain must not contain path syntax")
	}
	if _, err := idna.Lookup.ToASCII(lookupDomain); err != nil {
		return "", fmt.Errorf("validate certificate domain: %w", err)
	}

	// Preserve the historical Punycode file mapping after validating the
	// input with the stricter DNS lookup profile.
	safe, err := idna.ToASCII(lookupDomain)
	if err != nil {
		return "", err
	}
	if wildcard {
		safe = "_." + safe
	}
	if safe == "" ||
		strings.ContainsAny(safe, `/\:`) ||
		strings.ContainsRune(safe, '\x00') {
		return "", errors.New("certificate domain maps to an invalid file name")
	}
	reservedPrefix := strings.TrimSuffix(fileTransactionJournalName, ".json")
	if strings.HasPrefix(strings.ToLower(safe), strings.ToLower(reservedPrefix)) {
		return "", errors.New("certificate domain uses the reserved transaction namespace")
	}
	return safe, nil
}
