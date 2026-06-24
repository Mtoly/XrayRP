package machine

import "errors"

type RuntimeService struct {
	supervisor *Supervisor
	sharedWS   *SharedWSRuntime
}

func NewRuntimeService(supervisor *Supervisor, sharedWS *SharedWSRuntime) *RuntimeService {
	if supervisor != nil && sharedWS != nil {
		sharedWS.SetRediscover(supervisor.ReconcileNow)
	}
	return &RuntimeService{
		supervisor: supervisor,
		sharedWS:   sharedWS,
	}
}

func (s *RuntimeService) Start() error {
	if s == nil || s.supervisor == nil {
		return nil
	}
	if err := s.supervisor.Start(); err != nil {
		return err
	}
	if s.sharedWS == nil {
		return nil
	}
	if err := s.sharedWS.Start(); err != nil {
		_ = s.supervisor.Close()
		return err
	}
	return nil
}

func (s *RuntimeService) Close() error {
	if s == nil {
		return nil
	}

	var errs []error
	if s.sharedWS != nil {
		if err := s.sharedWS.Close(); err != nil {
			errs = append(errs, err)
		}
	}
	if s.supervisor != nil {
		if err := s.supervisor.Close(); err != nil {
			errs = append(errs, err)
		}
	}
	return errors.Join(errs...)
}
