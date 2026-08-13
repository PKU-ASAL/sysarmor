package policy

import (
	"context"
	"fmt"
)

type EndpointCandidate struct {
	ID      string
	Version uint64
	Raw     string
	Source  Source
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
}

type EndpointRuntime interface {
	ApplyEndpoint(context.Context, EndpointCandidate) (EndpointReport, error)
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
	if s == nil || s.repository == nil {
		return EndpointCandidate{}, fmt.Errorf("endpoint policy service is not initialized")
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
		return EndpointReport{}, err
	}
	if err := s.repository.PersistEndpoint(ctx, candidate); err != nil {
		return EndpointReport{}, err
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
		return EndpointReport{}, false, err
	}
	report, err := s.runtime.ApplyEndpoint(ctx, candidate)
	if err != nil {
		return EndpointReport{Status: "pending", Message: "endpoint policy persisted; waiting for sensor recovery"}, true, nil
	}
	if err := s.repository.ActivateManagedDurable(ctx, candidate); err != nil {
		return EndpointReport{Status: "pending", Message: "endpoint policy persisted; waiting for durable activation"}, true, nil
	}
	if err := s.repository.PromoteManaged(ctx, candidate); err != nil {
		return EndpointReport{Status: "pending", Message: "endpoint policy persisted; waiting for authority promotion"}, true, nil
	}
	s.runtime.ActivateEndpoint(candidate, report)
	return report, false, nil
}
