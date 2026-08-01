package machine

import (
	"context"
	"errors"

	"github.com/Mtoly/XrayRP/service"
)

type RuntimeService struct {
	supervisor *Supervisor
	sharedWS   *SharedWSRuntime
}

func NewRuntimeService(supervisor *Supervisor, sharedWS *SharedWSRuntime) *RuntimeService {
	if supervisor != nil && sharedWS != nil {
		sharedWS.SetRediscoverContext(supervisor.ReconcileNowContext)
	}
	return &RuntimeService{
		supervisor: supervisor,
		sharedWS:   sharedWS,
	}
}

func (s *RuntimeService) Start() error {
	ctx, cancel := service.WithDefaultTimeout(context.Background(), service.DefaultStartTimeout)
	defer cancel()
	return s.StartContext(ctx)
}

func (s *RuntimeService) StartContext(parent context.Context) error {
	ctx, cancel := service.WithDefaultTimeout(parent, service.DefaultStartTimeout)
	defer cancel()
	if s == nil || s.supervisor == nil {
		return nil
	}
	if err := s.supervisor.StartContext(ctx); err != nil {
		return err
	}
	if s.sharedWS == nil {
		return nil
	}
	if err := s.sharedWS.StartContext(ctx); err != nil {
		cleanupCtx, cleanupCancel := service.CleanupContext(ctx)
		cleanupErr := s.supervisor.CloseContext(cleanupCtx)
		cleanupCancel()
		return errors.Join(err, cleanupErr)
	}
	return nil
}

func (s *RuntimeService) Close() error {
	ctx, cancel := service.WithDefaultTimeout(context.Background(), service.DefaultCloseTimeout)
	defer cancel()
	return s.CloseContext(ctx)
}

func (s *RuntimeService) CloseContext(parent context.Context) error {
	ctx, cancel := service.WithDefaultTimeout(parent, service.DefaultCloseTimeout)
	defer cancel()
	if s == nil {
		return nil
	}

	var errs []error
	if s.sharedWS != nil {
		if err := s.sharedWS.CloseContext(ctx); err != nil {
			errs = append(errs, err)
		}
	}
	if s.supervisor != nil {
		if err := s.supervisor.CloseContext(ctx); err != nil {
			errs = append(errs, err)
		}
	}
	return errors.Join(errs...)
}
