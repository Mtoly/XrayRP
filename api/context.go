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

type ContextNodeSnapshotProvider interface {
	GetNodeSnapshotContext(context.Context) (*NodeSnapshot, error)
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
		value, err := contextual.GetNodeInfoContext(ctx)
		return value, finishContextCall(ctx, err)
	}
	value, err := client.GetNodeInfo()
	return value, finishContextCall(ctx, err)
}

// GetNodeSnapshotContext prefers the normalized adapter capability and falls
// back to the compatibility NodeInfo contract for older adapters and fakes.
func GetNodeSnapshotContext(ctx context.Context, client interface{ GetNodeInfo() (*NodeInfo, error) }) (*NodeSnapshot, error) {
	ctx = contextOrBackground(ctx)
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if contextual, ok := client.(ContextNodeSnapshotProvider); ok {
		value, err := contextual.GetNodeSnapshotContext(ctx)
		if err = finishContextCall(ctx, err); err != nil {
			return nil, err
		}
		return value.Clone(), nil
	}
	if provider, ok := client.(NodeSnapshotProvider); ok {
		value, err := provider.GetNodeSnapshot()
		if err = finishContextCall(ctx, err); err != nil {
			return nil, err
		}
		return value.Clone(), nil
	}
	nodeInfo, err := GetNodeInfoContext(ctx, client)
	if err != nil {
		return nil, err
	}
	return NormalizeNodeInfo(nodeInfo), nil
}

func GetUserListContext(ctx context.Context, client interface{ GetUserList() (*[]UserInfo, error) }) (*[]UserInfo, error) {
	ctx = contextOrBackground(ctx)
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if contextual, ok := client.(interface {
		GetUserListContext(context.Context) (*[]UserInfo, error)
	}); ok {
		value, err := contextual.GetUserListContext(ctx)
		return value, finishContextCall(ctx, err)
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
		value, err := contextual.GetNodeRuleContext(ctx)
		return value, finishContextCall(ctx, err)
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
		return finishContextCall(ctx, contextual.ReportNodeStatusContext(ctx, status))
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
		return finishContextCall(ctx, contextual.ReportNodeOnlineUsersContext(ctx, users))
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
		return finishContextCall(ctx, contextual.ReportUserTrafficContext(ctx, traffic))
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
		return finishContextCall(ctx, contextual.ReportIllegalContext(ctx, results))
	}
	return finishContextCall(ctx, client.ReportIllegal(results))
}

func GetXrayRCertConfigContext(ctx context.Context, provider CertConfigProvider) (*XrayRCertConfig, error) {
	ctx = contextOrBackground(ctx)
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if contextual, ok := provider.(ContextCertConfigProvider); ok {
		value, err := contextual.GetXrayRCertConfigContext(ctx)
		return value, finishContextCall(ctx, err)
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
		value, err := contextual.GetAliveListContext(ctx)
		return value, finishContextCall(ctx, err)
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
		value, err := contextual.DiscoverWSEndpointContext(ctx)
		return value, finishContextCall(ctx, err)
	}
	value, err := provider.DiscoverWSEndpoint()
	return value, finishContextCall(ctx, err)
}
