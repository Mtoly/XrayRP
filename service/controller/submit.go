package controller

import "context"

type syncActionSubmitter interface {
	Submit(syncAction)
}

func (c *Controller) submitSyncAction(action syncAction) error {
	if c.syncCoordinator != nil {
		c.syncCoordinator.Submit(action)
		return nil
	}
	return c.ExecuteSyncAction(context.Background(), action)
}
