package mylego

import (
	"errors"
	"fmt"
	"path/filepath"
	"strings"

	"golang.org/x/net/idna"
)

// sanitizedDomain preserves the historical panic-based helper for ACME storage.
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
