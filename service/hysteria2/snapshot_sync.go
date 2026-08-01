package hysteria2

import (
	"context"
	"errors"
	"fmt"
	"reflect"

	"github.com/Mtoly/XrayRP/api"
	"github.com/Mtoly/XrayRP/service"
	"github.com/Mtoly/XrayRP/service/internal/specialruntime"
)

var _ service.SnapshotSyncSubmitter = (*Hysteria2Service)(nil)

func (h *Hysteria2Service) initializeSnapshotSyncCoordinator() {
	if h.syncCoordinator != nil {
		return
	}
	h.syncCoordinator = specialruntime.NewSnapshotSyncCoordinator(specialruntime.SnapshotSyncCoordinatorConfig{
		Execute:  h.syncSnapshotsContext,
		OnResult: h.recordSnapshotSyncResult,
	})
}

func (h *Hysteria2Service) SubmitSnapshotSync(trigger service.SnapshotSyncTrigger) {
	if h == nil || h.syncCoordinator == nil {
		return
	}
	h.syncCoordinator.SubmitSnapshotSync(trigger)
}

func (h *Hysteria2Service) syncSnapshotsContext(ctx context.Context, scope service.SnapshotSyncScope) error {
	var errs []error
	if scope.Includes(service.SnapshotSyncUsers) {
		errs = append(errs, h.syncUserSnapshotContext(ctx))
	}
	if scope.Includes(service.SnapshotSyncRules) {
		errs = append(errs, h.syncRuleSnapshotContext(ctx))
	}
	if scope.Includes(service.SnapshotSyncNode) {
		errs = append(errs, h.syncNodeSnapshotContext(ctx))
	}
	return errors.Join(errs...)
}

func (h *Hysteria2Service) syncUserSnapshotContext(ctx context.Context) error {
	users, err := api.GetUserListContext(ctx, h.apiClient)
	if errors.Is(err, api.ErrUserNotModified) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("refresh Hysteria2 users: %w", err)
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	h.syncUsers(users)
	service.RecordSnapshotSyncApplied(h.apiClient, service.SnapshotSyncUsers)
	return nil
}

func (h *Hysteria2Service) syncRuleSnapshotContext(ctx context.Context) error {
	if h.config == nil || h.config.DisableGetRule || h.rules == nil {
		return nil
	}
	rules, err := api.GetNodeRuleContext(ctx, h.apiClient)
	if errors.Is(err, api.ErrRuleNotModified) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("refresh Hysteria2 rules: %w", err)
	}
	if rules == nil {
		return nil
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if err := h.rules.UpdateRule(h.appliedTag(), *rules); err != nil {
		return err
	}
	service.RecordSnapshotSyncApplied(h.apiClient, service.SnapshotSyncRules)
	return nil
}

func (h *Hysteria2Service) syncNodeSnapshotContext(ctx context.Context) error {
	currentNode, _, _ := h.appliedStateSnapshot()
	nodeInfo, err := api.GetNodeInfoContext(ctx, h.apiClient)
	if errors.Is(err, api.ErrNodeNotModified) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("refresh Hysteria2 node: %w", err)
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if nodeInfo == nil || nodeInfo.NodeType != "Hysteria2" {
		return errors.New("refresh Hysteria2 node returned unexpected node type")
	}
	if currentNode != nil && reflect.DeepEqual(currentNode, nodeInfo) {
		service.RecordSnapshotSyncApplied(h.apiClient, service.SnapshotSyncNode)
		return nil
	}
	if err := h.reloadNodeContext(ctx, nodeInfo); err != nil {
		return err
	}
	service.RecordSnapshotSyncApplied(h.apiClient, service.SnapshotSyncNode)
	return nil
}

func (h *Hysteria2Service) recordSnapshotSyncResult(result specialruntime.SnapshotSyncResult) {
	if result.Err == nil {
		h.health.RecordSuccessfulSync(result.FinishedAt)
		return
	}
	h.health.RecordFailure(service.FailureStageSync, result.FinishedAt)
	if h.logger != nil {
		h.logger.Warn("Hysteria2 snapshot sync failed; polling will retry")
	}
}
