//go:build !with_quic

package singboxregistry

import "github.com/sagernet/sing-box/adapter/inbound"

// Without QUIC, sing-box's TUIC stub stays registered.
func registerQUICUserInbounds(*inbound.Registry) {}
