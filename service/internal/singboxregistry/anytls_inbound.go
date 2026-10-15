package singboxregistry

import (
	"context"
	"net"
	"strings"
	"sync/atomic"

	anytls "github.com/anytls/sing-anytls"
	"github.com/anytls/sing-anytls/padding"
	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/adapter/inbound"
	"github.com/sagernet/sing-box/common/listener"
	"github.com/sagernet/sing-box/common/tls"
	"github.com/sagernet/sing-box/common/uot"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing/common"
	"github.com/sagernet/sing/common/auth"
	E "github.com/sagernet/sing/common/exceptions"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
)

// AnyTLSInbound is derived from sing-box v1.14.2 protocol/anytls/inbound.go
// (GPL-3.0). It adds UpdateUsers so panel user snapshots reach the running
// inbound; review it against upstream on every sing-box upgrade.
type AnyTLSInbound struct {
	inbound.Adapter
	tlsConfig     tls.ServerConfig
	router        adapter.ConnectionRouterEx
	logger        log.ContextLogger
	listener      *listener.Listener
	paddingScheme []byte
	service       atomic.Pointer[anytls.Service]
}

func registerAnyTLSInbound(registry *inbound.Registry) {
	inbound.Register[option.AnyTLSInboundOptions](registry, C.TypeAnyTLS, newAnyTLSInbound)
}

func newAnyTLSInbound(ctx context.Context, router adapter.Router, logger log.ContextLogger, tag string, options option.AnyTLSInboundOptions) (adapter.Inbound, error) {
	inbound := &AnyTLSInbound{
		Adapter:       inbound.NewAdapter(C.TypeAnyTLS, tag),
		router:        uot.NewRouter(router, logger),
		logger:        logger,
		paddingScheme: padding.DefaultPaddingScheme,
	}

	if options.TLS != nil && options.TLS.Enabled {
		tlsConfig, err := tls.NewServer(ctx, logger, common.PtrValueOrDefault(options.TLS))
		if err != nil {
			return nil, err
		}
		inbound.tlsConfig = tlsConfig
	}

	if len(options.PaddingScheme) > 0 {
		inbound.paddingScheme = []byte(strings.Join(options.PaddingScheme, "\n"))
	}
	if err := inbound.UpdateUsers(options.Users); err != nil {
		return nil, err
	}
	inbound.listener = listener.New(listener.Options{
		Context:           ctx,
		Logger:            logger,
		Network:           []string{N.NetworkTCP},
		Listen:            options.ListenOptions,
		ConnectionHandler: inbound,
	})
	return inbound, nil
}

// UpdateUsers replaces the user table for new connections. An AnyTLS service
// holds no per-connection state, so established connections keep the service
// that accepted them.
func (h *AnyTLSInbound) UpdateUsers(users []option.AnyTLSUser) error {
	service, err := anytls.NewService(anytls.ServiceConfig{
		Users: common.Map(users, func(it option.AnyTLSUser) anytls.User {
			return anytls.User(it)
		}),
		PaddingScheme: h.paddingScheme,
		Handler:       (*anyTLSInboundHandler)(h),
		Logger:        h.logger,
	})
	if err != nil {
		return err
	}
	h.service.Store(service)
	return nil
}

func (h *AnyTLSInbound) Start(stage adapter.StartStage) error {
	if stage != adapter.StartStateStart {
		return nil
	}
	if h.tlsConfig != nil {
		err := h.tlsConfig.Start()
		if err != nil {
			return err
		}
	}
	return h.listener.Start()
}

func (h *AnyTLSInbound) Close() error {
	return common.Close(h.listener, h.tlsConfig)
}

func (h *AnyTLSInbound) NewConnection(ctx context.Context, conn net.Conn, metadata adapter.InboundContext, onClose N.CloseHandlerFunc) {
	if h.tlsConfig != nil {
		tlsConn, err := tls.ServerHandshake(ctx, conn, h.tlsConfig)
		if err != nil {
			N.CloseOnHandshakeFailure(conn, onClose, err)
			h.logger.ErrorContext(ctx, E.Cause(err, "process connection from ", metadata.Source, ": TLS handshake"))
			return
		}
		conn = tlsConn
	}
	err := h.service.Load().NewConnection(adapter.WithContext(ctx, &metadata), conn, metadata.Source, onClose)
	if err != nil {
		N.CloseOnHandshakeFailure(conn, onClose, err)
		h.logger.ErrorContext(ctx, E.Cause(err, "process connection from ", metadata.Source))
	}
}

type anyTLSInboundHandler AnyTLSInbound

func (h *anyTLSInboundHandler) NewConnectionEx(ctx context.Context, conn net.Conn, source M.Socksaddr, destination M.Socksaddr, onClose N.CloseHandlerFunc) {
	var metadata adapter.InboundContext
	metadata.Inbound = h.Tag()
	metadata.InboundType = h.Type()
	//nolint:staticcheck
	metadata.InboundDetour = h.listener.ListenOptions().Detour
	//nolint:staticcheck
	metadata.Source = source
	metadata.Destination = destination.Unwrap()
	if userName, _ := auth.UserFromContext[string](ctx); userName != "" {
		metadata.User = userName
		h.logger.InfoContext(ctx, "[", userName, "] inbound connection to ", metadata.Destination)
	} else {
		h.logger.InfoContext(ctx, "inbound connection to ", metadata.Destination)
	}
	h.router.RouteConnectionEx(ctx, conn, metadata, onClose)
}
