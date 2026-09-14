package policy

import (
	"context"
	"fmt"
)

type TelemetryInput struct {
	MaxBatchItems uint32
	MaxBatchBytes uint32
	FlushInterval string
}

type TelemetryCandidate interface {
	ReportJSON() string
}

type TelemetryRepository interface {
	PrepareTelemetry(context.Context, string, *TelemetryInput) (TelemetryCandidate, error)
	PersistTelemetry(context.Context, TelemetryCandidate) error
}

type TelemetryRuntime interface {
	PublishTelemetry(TelemetryCandidate)
}

type TelemetryService struct {
	repository TelemetryRepository
	runtime    TelemetryRuntime
}

func NewTelemetryService(repository TelemetryRepository, runtime TelemetryRuntime) *TelemetryService {
	return &TelemetryService{repository: repository, runtime: runtime}
}

func (s *TelemetryService) Validate(ctx context.Context, document string, input *TelemetryInput) (TelemetryCandidate, error) {
	if err := s.initialized(); err != nil {
		return nil, err
	}
	return s.repository.PrepareTelemetry(ctx, document, input)
}

func (s *TelemetryService) Activate(ctx context.Context, document string, input *TelemetryInput) (TelemetryCandidate, error) {
	candidate, err := s.Validate(ctx, document, input)
	if err != nil {
		return nil, err
	}
	if err := s.repository.PersistTelemetry(ctx, candidate); err != nil {
		return nil, fmt.Errorf("persist telemetry policy: %w", err)
	}
	s.runtime.PublishTelemetry(candidate)
	return candidate, nil
}

func (s *TelemetryService) initialized() error {
	if s == nil || s.repository == nil || s.runtime == nil {
		return fmt.Errorf("telemetry policy service is not initialized")
	}
	return nil
}
