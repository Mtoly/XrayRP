package controller

import "context"

func (c *Controller) SyncPortForTest(ctx context.Context) error {
	return c.ExecuteSyncAction(ctx, newSyncAction(syncActionTypeSyncNodeConfig, syncActionSourcePolling, syncActionMetadata{}))
}
