package mylego

import (
	"strings"
	"testing"
)

func TestFullDNSRegistryPreservesExactProviderNameSemantics(t *testing.T) {
	provider, err := newFullDNSChallengeProvider("manual")
	if err != nil {
		t.Fatalf("manual provider returned error: %v", err)
	}
	if provider == nil {
		t.Fatal("manual provider is nil")
	}

	for _, name := range []string{"Manual", " manual", "manual "} {
		t.Run(name, func(t *testing.T) {
			provider, err := newFullDNSChallengeProvider(name)
			if err == nil {
				t.Fatalf("provider %q unexpectedly accepted as %#v", name, provider)
			}
			if provider != nil {
				t.Fatalf("provider %q returned partial value %#v with error %v", name, provider, err)
			}
			if got, want := err.Error(), "unrecognized DNS provider: "+name; got != want {
				t.Fatalf("error = %q, want %q", got, want)
			}
		})
	}
}

func TestFullDNSRegistryPreservesGeneratedAliases(t *testing.T) {
	t.Setenv("ACME_DNS_API_BASE", "https://acme-dns.invalid")

	aliases := []string{
		"acme-dns", "acmedns",
		"domeneshop", "domainnameshop",
		"edgedns", "fastdns",
		"linode", "linodev4",
		"rfc2136", "dnsupdate",
		"webnames", "webnamesru",
	}
	for _, name := range aliases {
		t.Run(name, func(t *testing.T) {
			_, err := newFullDNSChallengeProvider(name)
			if err != nil && strings.HasPrefix(err.Error(), "unrecognized DNS provider:") {
				t.Fatalf("generated alias %q was not recognized: %v", name, err)
			}
		})
	}
}
