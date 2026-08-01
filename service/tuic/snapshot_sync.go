package tuic

import (
	"context"
	"errors"
	"fmt"
	"reflect"

	"github.com/Mtoly/XrayRP/api"
	"github.com/Mtoly/XrayRP/service"
	"github.com/Mtoly/XrayRP/service/internal/specialruntime"
)

var _ service.SnapshotSyncSubmitter = (*TuicService)(nil)

func (s *TuicService) initializeSnapshotSyncCoordinator() {
	if s.syncCoordinator != nil {
		return
	}
	s.syncCoordinator = specialruntime.NewSnapshotSyncCoordinator(specialruntime.SnapshotSyncCoordinatorConfig{
		Execute:  s.syncSnapshotsContext,
		OnResult: s.recordSnapshotSyncResult,
	})
}

func (s *TuicService) SubmitSnapshotSync(trigger service.SnapshotSyncTrigger) {
	if s == nil || s.syncCoordinator == nil {
		return
	}
	s.syncCoordinator.SubmitSnapshotSync(trigger)
}

func (s *TuicService) syncSnapshotsContext(ctx context.Context, scope service.SnapshotSyncScope) error {
	var errs []error
	if scope.Includes(service.SnapshotSyncUsers) {
		errs = append(errs, s.syncUserSnapshotContext(ctx))
	}
	if scope.Includes(service.SnapshotSyncRules) {
		errs = append(errs, s.syncRuleSnapshotContext(ctx))
	}
	if scope.Includes(service.SnapshotSyncNode) {
		errs = append(errs, s.syncNodeSnapshotContext(ctx))
	}
	return errors.Join(errs...)
}

func (s *TuicService) syncUserSnapshotContext(ctx context.Context) error {
	users, err := api.GetUserListContext(ctx, s.apiClient)
	if errors.Is(err, api.ErrUserNotModified) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("refresh TUIC users: %w", err)
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	s.syncUsers(users)
	service.RecordSnapshotSyncApplied(s.apiClient, service.SnapshotSyncUsers)
	return nil
}

func (s *TuicService) syncRuleSnapshotContext(ctx context.Context) error {
	if s.config == nil || s.config.DisableGetRule || s.rules == nil {
		return nil
	}
	rules, err := api.GetNodeRuleContext(ctx, s.apiClient)
	if errors.Is(err, api.ErrRuleNotModified) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("refresh TUIC rules: %w", err)
	}
	if rules == nil {
		return nil
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if err := s.rules.UpdateRule(s.appliedTag(), *rules); err != nil {
		return err
	}
	service.RecordSnapshotSyncApplied(s.apiClient, service.SnapshotSyncRules)
	return nil
}

func (s *TuicService) syncNodeSnapshotContext(ctx context.Context) error {
	currentNode, _, _ := s.appliedStateSnapshot()
	nodeInfo, err := api.GetNodeInfoContext(ctx, s.apiClient)
	if errors.Is(err, api.ErrNodeNotModified) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("refresh TUIC node: %w", err)
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if nodeInfo == nil || nodeInfo.NodeType != "Tuic" {
		return errors.New("refresh TUIC node returned unexpected node type")
	}
	if currentNode != nil && reflect.DeepEqual(currentNode, nodeInfo) {
		service.RecordSnapshotSyncApplied(s.apiClient, service.SnapshotSyncNode)
		return nil
	}
	if err := s.reloadNodeContext(ctx, nodeInfo); err != nil {
		return err
	}
	service.RecordSnapshotSyncApplied(s.apiClient, service.SnapshotSyncNode)
	return nil
}

func (s *TuicService) recordSnapshotSyncResult(result specialruntime.SnapshotSyncResult) {
	if result.Err == nil {
		s.health.RecordSuccessfulSync(result.FinishedAt)
		return
	}
	s.health.RecordFailure(service.FailureStageSync, result.FinishedAt)
	if s.logger != nil {
		s.logger.Warn("TUIC snapshot sync failed; polling will retry")
	}
}
