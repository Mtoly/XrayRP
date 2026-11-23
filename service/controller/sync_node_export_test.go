package controller

import "context"

// SyncNodeConfigForTest drives one node-configuration sync through the same
// action pipeline used by polling and websocket events.
func (c *Controller) SyncNodeConfigForTest(ctx context.Context) error {
	return c.ExecuteSyncAction(ctx, newSyncAction(syncActionTypeSyncNodeConfig, syncActionSourcePolling, syncActionMetadata{}))
}
