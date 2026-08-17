package controller

import (
	"context"
	"fmt"

	"github.com/xtls/xray-core/common/protocol"

	"github.com/Mtoly/XrayRP/api"
)

func (c *Controller) removeOldTag(oldTag string) (err error) {
	err = c.removeInbound(oldTag)
	if err != nil {
		return err
	}
	err = c.removeOutbound(oldTag)
	if err != nil {
		return err
	}
	return nil
}

func (c *Controller) addNewTag(newNodeInfo *api.NodeInfo, tag string) (err error) {
	return c.addNewTagWithConfig(newNodeInfo, tag, c.config)
}

func (c *Controller) addNewTagWithConfig(newNodeInfo *api.NodeInfo, tag string, config *Config) error {
	return c.addNewTagWithConfigContext(context.Background(), newNodeInfo, tag, config)
}

func (c *Controller) addNewTagWithConfigContext(ctx context.Context, newNodeInfo *api.NodeInfo, tag string, config *Config) error {
	return c.addNewTagWithSnapshotConfigContext(ctx, api.NormalizeNodeInfo(newNodeInfo), tag, config)
}

func (c *Controller) addNewTagWithSnapshotConfigContext(ctx context.Context, snapshot *api.NodeSnapshot, tag string, config *Config) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	node := normalizeNodeSnapshot(snapshot)
	inbound := node.inboundView()
	outbound := node.outboundView()
	routePolicy := node.routingPolicy()
	nodeType := inbound.listener.nodeType

	// Socks/HTTP inbounds are built with users embedded (no UserManager support).
	// Skip here; addNewUserWithConfigContext creates the inbound with its users.
	if nodeType == "Socks" || nodeType == "HTTP" {
		outBoundConfig, err := buildOutbound(config, outbound, tag)
		if err != nil {
			return err
		}
		return c.addOutboundContext(ctx, outBoundConfig, tag, routePolicy)
	}

	if nodeType == "Shadowsocks-Plugin" {
		return c.addInboundForSSPluginContext(ctx, node, tag, config)
	}

	inboundConfig, err := buildInbound(config, inbound, tag)
	if err != nil {
		return err
	}
	if err := c.addInboundContext(ctx, inboundConfig); err != nil {
		return err
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	outBoundConfig, err := buildOutbound(config, outbound, tag)
	if err != nil {
		return err
	}
	return c.addOutboundContext(ctx, outBoundConfig, tag, routePolicy)
}

func (c *Controller) addInboundForSSPlugin(node nodeValue, tag string, config *Config) error {
	return c.addInboundForSSPluginContext(context.Background(), node, tag, config)
}

func (c *Controller) addInboundForSSPluginContext(ctx context.Context, node nodeValue, tag string, config *Config) error {
	views := node.shadowsocksPluginViews()
	inboundConfig, err := buildInbound(config, views.regularInbound, tag)
	if err != nil {
		return err
	}
	if err := c.addInboundContext(ctx, inboundConfig); err != nil {
		return err
	}
	outBoundConfig, err := buildOutbound(config, views.regularOutbound, tag)
	if err != nil {
		return err
	}
	if err := c.addOutboundContext(ctx, outBoundConfig, tag, views.routing); err != nil {
		return err
	}
	if err := ctx.Err(); err != nil {
		return err
	}

	dokodemoTag := fmt.Sprintf("dokodemo-door_%s+1", tag)
	inboundConfig, err = buildInbound(config, views.bridgeInbound, dokodemoTag)
	if err != nil {
		return err
	}
	if err := c.addInboundContext(ctx, inboundConfig); err != nil {
		return err
	}
	outBoundConfig, err = buildOutbound(config, views.bridgeOutbound, dokodemoTag)
	if err != nil {
		return err
	}
	return c.addOutboundContext(ctx, outBoundConfig, dokodemoTag, views.routing)
}

// rebuildInboundWithUsers rebuilds the socks/http inbound with all users embedded.
// This is needed because socks/http inbounds don't support proxy.UserManager.
func (c *Controller) rebuildInboundWithUsers(userInfo *[]api.UserInfo, nodeInfo *api.NodeInfo, tag string) error {
	return c.rebuildInboundWithUsersWithConfig(userInfo, nodeInfo, tag, c.config)
}

func (c *Controller) rebuildInboundWithUsersWithConfig(userInfo *[]api.UserInfo, nodeInfo *api.NodeInfo, tag string, config *Config) error {
	return c.rebuildInboundWithUsersWithConfigContext(context.Background(), userInfo, nodeInfo, tag, config)
}

func (c *Controller) rebuildInboundWithUsersWithConfigContext(ctx context.Context, userInfo *[]api.UserInfo, nodeInfo *api.NodeInfo, tag string, config *Config) error {
	return c.rebuildInboundWithUsersWithSnapshotConfigContext(ctx, userInfo, api.NormalizeNodeInfo(nodeInfo), tag, config)
}

func (c *Controller) rebuildInboundWithUsersWithSnapshotConfigContext(ctx context.Context, userInfo *[]api.UserInfo, snapshot *api.NodeSnapshot, tag string, config *Config) error {
	// Remove existing inbound if present (ignore errors for first-time setup).
	_ = c.removeInboundContext(ctx, tag)
	if err := ctx.Err(); err != nil {
		return err
	}
	inboundConfig, err := buildInboundWithUsers(config, inboundViewFromSnapshot(snapshot).listener, tag, userInfo)
	if err != nil {
		return err
	}
	if err := c.addInboundContext(ctx, inboundConfig); err != nil {
		return err
	}

	c.logger.Printf("Rebuilt %s inbound with %d users", snapshot.NodeType, len(*userInfo))
	return nil
}

func (c *Controller) addNewUser(userInfo *[]api.UserInfo, nodeInfo *api.NodeInfo, tag string) (err error) {
	return c.addNewUserWithConfig(userInfo, nodeInfo, tag, c.config)
}

func (c *Controller) addNewUserWithConfig(userInfo *[]api.UserInfo, nodeInfo *api.NodeInfo, tag string, config *Config) error {
	return c.addNewUserWithConfigContext(context.Background(), userInfo, nodeInfo, tag, config)
}

func (c *Controller) addNewUserWithConfigContext(ctx context.Context, userInfo *[]api.UserInfo, nodeInfo *api.NodeInfo, tag string, config *Config) error {
	return c.addNewUserWithSnapshotConfigContext(ctx, userInfo, api.NormalizeNodeInfo(nodeInfo), tag, config)
}

func (c *Controller) addNewUserWithSnapshotConfigContext(ctx context.Context, userInfo *[]api.UserInfo, snapshot *api.NodeSnapshot, tag string, config *Config) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	node := userViewFromSnapshot(snapshot)

	// Socks/HTTP don't support proxy.UserManager; rebuild the inbound with users embedded.
	if node.nodeType == "Socks" || node.nodeType == "HTTP" {
		return c.rebuildInboundWithUsersWithSnapshotConfigContext(ctx, userInfo, snapshot, tag, config)
	}

	users := make([]*protocol.User, 0)
	switch node.nodeType {
	case "V2ray", "Vmess", "Vless":
		if node.enableVless || (node.nodeType == "Vless" && node.nodeType != "Vmess") {
			users = c.buildVlessUser(userInfo, node.vless, tag)
		} else {
			users = c.buildVmessUser(userInfo, tag)
		}
	case "Trojan":
		users = c.buildTrojanUser(userInfo, tag)
	case "Shadowsocks":
		users = c.buildSSUser(userInfo, node.cypherMethod, tag)
	case "Shadowsocks-Plugin":
		users = c.buildSSPluginUser(userInfo, tag)
	default:
		return fmt.Errorf("unsupported node type: %s", node.nodeType)
	}

	if err := c.addUsersContext(ctx, users, tag); err != nil {
		return err
	}
	c.logger.Printf("Added %d new users", len(*userInfo))
	return nil
}
