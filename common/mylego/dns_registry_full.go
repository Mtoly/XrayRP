package mylego

import (
	"github.com/go-acme/lego/v4/challenge"
	"github.com/go-acme/lego/v4/providers/dns"
)

// newFullDNSChallengeProvider preserves lego's complete generated registry.
// Provider names are passed through unchanged; narrowing or normalization is a
// configuration compatibility change and requires a separately approved batch.
func newFullDNSChallengeProvider(name string) (challenge.Provider, error) {
	return dns.NewDNSChallengeProviderByName(name)
}
