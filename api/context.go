package api

import "context"

type ContextPanelClient interface {
	GetNodeInfoContext(context.Context) (*NodeInfo, error)
	GetUserListContext(context.Context) (*[]UserInfo, error)
	GetNodeRuleContext(context.Context) (*[]DetectRule, error)
	ReportNodeStatusContext(context.Context, *NodeStatus) error
	ReportNodeOnlineUsersContext(context.Context, *[]OnlineUser) error
	ReportUserTrafficContext(context.Context, *[]UserTraffic) error
	ReportIllegalContext(context.Context, *[]DetectResult) error
}

type ContextCertConfigProvider interface {
	GetXrayRCertConfigContext(context.Context) (*XrayRCertConfig, error)
}

type ContextAliveListProvider interface {
	GetAliveListContext(context.Context) (map[int][]string, error)
}

type ContextWSEndpointDiscoverer interface {
	DiscoverWSEndpointContext(context.Context) (string, error)
}

func contextOrBackground(ctx context.Context) context.Context {
	if ctx == nil {
		return context.Background()
	}
	return ctx
}

func finishContextCall(ctx context.Context, err error) error {
	if err != nil {
		return err
	}
	return contextOrBackground(ctx).Err()
}

func GetNodeInfoContext(ctx context.Context, client interface{ GetNodeInfo() (*NodeInfo, error) }) (*NodeInfo, error) {
	ctx = contextOrBackground(ctx)
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if contextual, ok := client.(interface {
		GetNodeInfoContext(context.Context) (*NodeInfo, error)
	}); ok {
		return contextual.GetNodeInfoContext(ctx)
	}
	value, err := client.GetNodeInfo()
	return value, finishContextCall(ctx, err)
}

func GetUserListContext(ctx context.Context, client interface{ GetUserList() (*[]UserInfo, error) }) (*[]UserInfo, error) {
	ctx = contextOrBackground(ctx)
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if contextual, ok := client.(interface {
		GetUserListContext(context.Context) (*[]UserInfo, error)
	}); ok {
		return contextual.GetUserListContext(ctx)
	}
	value, err := client.GetUserList()
	return value, finishContextCall(ctx, err)
}

func GetNodeRuleContext(ctx context.Context, client interface{ GetNodeRule() (*[]DetectRule, error) }) (*[]DetectRule, error) {
	ctx = contextOrBackground(ctx)
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if contextual, ok := client.(interface {
		GetNodeRuleContext(context.Context) (*[]DetectRule, error)
	}); ok {
		return contextual.GetNodeRuleContext(ctx)
	}
	value, err := client.GetNodeRule()
	return value, finishContextCall(ctx, err)
}

func ReportNodeStatusContext(ctx context.Context, client interface{ ReportNodeStatus(*NodeStatus) error }, status *NodeStatus) error {
	ctx = contextOrBackground(ctx)
	if err := ctx.Err(); err != nil {
		return err
	}
	if contextual, ok := client.(interface {
		ReportNodeStatusContext(context.Context, *NodeStatus) error
	}); ok {
		return contextual.ReportNodeStatusContext(ctx, status)
	}
	return finishContextCall(ctx, client.ReportNodeStatus(status))
}

func ReportNodeOnlineUsersContext(ctx context.Context, client interface{ ReportNodeOnlineUsers(*[]OnlineUser) error }, users *[]OnlineUser) error {
	ctx = contextOrBackground(ctx)
	if err := ctx.Err(); err != nil {
		return err
	}
	if contextual, ok := client.(interface {
		ReportNodeOnlineUsersContext(context.Context, *[]OnlineUser) error
	}); ok {
		return contextual.ReportNodeOnlineUsersContext(ctx, users)
	}
	return finishContextCall(ctx, client.ReportNodeOnlineUsers(users))
}

func ReportUserTrafficContext(ctx context.Context, client interface{ ReportUserTraffic(*[]UserTraffic) error }, traffic *[]UserTraffic) error {
	ctx = contextOrBackground(ctx)
	if err := ctx.Err(); err != nil {
		return err
	}
	if contextual, ok := client.(interface {
		ReportUserTrafficContext(context.Context, *[]UserTraffic) error
	}); ok {
		return contextual.ReportUserTrafficContext(ctx, traffic)
	}
	return finishContextCall(ctx, client.ReportUserTraffic(traffic))
}

func ReportIllegalContext(ctx context.Context, client interface{ ReportIllegal(*[]DetectResult) error }, results *[]DetectResult) error {
	ctx = contextOrBackground(ctx)
	if err := ctx.Err(); err != nil {
		return err
	}
	if contextual, ok := client.(interface {
		ReportIllegalContext(context.Context, *[]DetectResult) error
	}); ok {
		return contextual.ReportIllegalContext(ctx, results)
	}
	return finishContextCall(ctx, client.ReportIllegal(results))
}

func GetXrayRCertConfigContext(ctx context.Context, provider CertConfigProvider) (*XrayRCertConfig, error) {
	ctx = contextOrBackground(ctx)
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if contextual, ok := provider.(ContextCertConfigProvider); ok {
		return contextual.GetXrayRCertConfigContext(ctx)
	}
	value, err := provider.GetXrayRCertConfig()
	return value, finishContextCall(ctx, err)
}

func GetAliveListContext(ctx context.Context, provider AliveListProvider) (map[int][]string, error) {
	ctx = contextOrBackground(ctx)
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if contextual, ok := provider.(ContextAliveListProvider); ok {
		return contextual.GetAliveListContext(ctx)
	}
	value, err := provider.GetAliveList()
	return value, finishContextCall(ctx, err)
}

func DiscoverWSEndpointContext(ctx context.Context, provider WSEndpointDiscoverer) (string, error) {
	ctx = contextOrBackground(ctx)
	if err := ctx.Err(); err != nil {
		return "", err
	}
	if contextual, ok := provider.(ContextWSEndpointDiscoverer); ok {
		return contextual.DiscoverWSEndpointContext(ctx)
	}
	value, err := provider.DiscoverWSEndpoint()
	return value, finishContextCall(ctx, err)
}
