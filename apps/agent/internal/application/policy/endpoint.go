package policy

import (
	"context"
	"fmt"
)

type EndpointCandidate interface {
	PolicyID() string
	PolicyVersion() uint64
	PolicySource() Source
}

type EndpointReport struct {
	Status          string
	Message         string
	Warnings        []string
	RequiresRestart bool
}

type EndpointRepository interface {
	PrepareEndpoint(context.Context, string, Source) (EndpointCandidate, error)
	PersistEndpoint(context.Context, EndpointCandidate) error
	SaveDesiredManaged(context.Context, EndpointCandidate) error
	ActivateManagedDurable(context.Context, EndpointCandidate) error
	PromoteManaged(context.Context, EndpointCandidate) error
	PendingManaged(context.Context) (EndpointCandidate, bool, error)
	LoadStandalone(context.Context) (EndpointCandidate, bool, error)
}

type EndpointRuntime interface {
	ApplyEndpoint(context.Context, EndpointCandidate) (EndpointReport, error)
	RollbackEndpoint(context.Context, EndpointCandidate) error
	ActivateEndpoint(EndpointCandidate, EndpointReport)
}

type EndpointService struct {
	repository EndpointRepository
	runtime    EndpointRuntime
}

func NewEndpointService(repository EndpointRepository, runtime EndpointRuntime) *EndpointService {
	return &EndpointService{repository: repository, runtime: runtime}
}

func (s *EndpointService) Validate(ctx context.Context, document string, source Source) (EndpointCandidate, error) {
	if err := s.initialized(); err != nil {
		return nil, err
	}
	return s.repository.PrepareEndpoint(ctx, document, source)
}

func (s *EndpointService) ActivateStandalone(ctx context.Context, document string) (EndpointReport, error) {
	candidate, err := s.Validate(ctx, document, SourceStandalone)
	if err != nil {
		return EndpointReport{}, err
	}
	report, err := s.runtime.ApplyEndpoint(ctx, candidate)
	if err != nil {
		return EndpointReport{}, fmt.Errorf("apply endpoint policy: %w", err)
	}
	if err := s.repository.PersistEndpoint(ctx, candidate); err != nil {
		return EndpointReport{}, s.rollback(ctx, candidate, fmt.Errorf("persist endpoint policy: %w", err))
	}
	s.runtime.ActivateEndpoint(candidate, report)
	return report, nil
}

func (s *EndpointService) ActivateManaged(ctx context.Context, document string) (EndpointReport, bool, error) {
	candidate, err := s.Validate(ctx, document, SourceManaged)
	if err != nil {
		return EndpointReport{}, false, err
	}
	if err := s.repository.SaveDesiredManaged(ctx, candidate); err != nil {
		return EndpointReport{}, false, fmt.Errorf("save desired managed endpoint policy: %w", err)
	}
	report, err := s.runtime.ApplyEndpoint(ctx, candidate)
	if err != nil {
		return pendingEndpointReport("endpoint policy persisted; waiting for sensor recovery"), true, nil
	}
	return s.completeManaged(ctx, candidate, report)
}

func (s *EndpointService) ResumeManaged(ctx context.Context) (bool, error) {
	if err := s.initialized(); err != nil {
		return false, err
	}
	candidate, ok, err := s.repository.PendingManaged(ctx)
	if err != nil || !ok {
		return false, err
	}
	_, pending, err := s.completeManaged(ctx, candidate, EndpointReport{Status: "applied"})
	return !pending, err
}

func (s *EndpointService) RestoreStandalone(ctx context.Context, activate func(context.Context) error) error {
	if err := s.initialized(); err != nil {
		return err
	}
	candidate, ok, err := s.repository.LoadStandalone(ctx)
	if err != nil {
		return fmt.Errorf("load standalone endpoint policy: %w", err)
	}
	if !ok {
		return fmt.Errorf("standalone endpoint policy is not initialized")
	}
	report, err := s.runtime.ApplyEndpoint(ctx, candidate)
	if err != nil {
		return fmt.Errorf("apply standalone endpoint policy: %w", err)
	}
	if err := activate(ctx); err != nil {
		return s.rollback(ctx, candidate, fmt.Errorf("activate standalone endpoint policy: %w", err))
	}
	s.runtime.ActivateEndpoint(candidate, report)
	return nil
}

func (s *EndpointService) completeManaged(ctx context.Context, candidate EndpointCandidate, report EndpointReport) (EndpointReport, bool, error) {
	if err := s.repository.ActivateManagedDurable(ctx, candidate); err != nil {
		return pendingEndpointReport("endpoint policy persisted; waiting for durable activation"), true, nil
	}
	if err := s.repository.PromoteManaged(ctx, candidate); err != nil {
		return pendingEndpointReport("endpoint policy persisted; waiting for authority promotion"), true, nil
	}
	s.runtime.ActivateEndpoint(candidate, report)
	return report, false, nil
}

func (s *EndpointService) rollback(ctx context.Context, candidate EndpointCandidate, cause error) error {
	if err := s.runtime.RollbackEndpoint(ctx, candidate); err != nil {
		return fmt.Errorf("%w; rollback endpoint runtime: %v", cause, err)
	}
	return cause
}

func (s *EndpointService) initialized() error {
	if s == nil || s.repository == nil || s.runtime == nil {
		return fmt.Errorf("endpoint policy service is not initialized")
	}
	return nil
}

func pendingEndpointReport(message string) EndpointReport {
	return EndpointReport{Status: "pending", Message: message}
}
