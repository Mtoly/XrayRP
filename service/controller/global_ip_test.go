package controller

import (
	"context"
	"testing"

	xraynet "github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/protocol"
	"github.com/xtls/xray-core/common/session"
	"github.com/xtls/xray-core/transport"
)

func TestDataPathWrapperRejectsNonIPSource(t *testing.T) {
	for _, address := range []xraynet.Address{nil, xraynet.DomainAddress("source.example")} {
		base := &fakeOutboundHandler{tag: "node"}
		wrapper := &dataPathWrapper{Handler: base, tag: "node"}
		ctx := session.ContextWithInbound(context.Background(), &session.Inbound{
			Tag: "node", Source: xraynet.Destination{Address: address},
			User: &protocol.MemoryUser{Email: "node|17"},
		})
		wrapper.Dispatch(ctx, &transport.Link{})
		if base.dispatched {
			t.Fatal("non-IP source reached outbound handler")
		}
	}
}
