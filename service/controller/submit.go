package controller

import (
	"context"

	"github.com/Mtoly/XrayRP/service"
)

type syncActionSubmitter interface {
	Submit(syncAction)
}

func (c *Controller) submitSyncAction(action syncAction) error {
	ctx, cancel := service.WithDefaultTimeout(context.Background(), service.DefaultSyncTimeout)
	defer cancel()
	return c.submitSyncActionContext(ctx, action)
}

func (c *Controller) submitSyncActionContext(ctx context.Context, action syncAction) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if c.syncCoordinator != nil {
		c.syncCoordinator.Submit(action)
		return ctx.Err()
	}
	return c.ExecuteSyncAction(ctx, action)
}
