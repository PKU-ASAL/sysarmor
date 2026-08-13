package policy

import (
	"context"
	"fmt"
)

type DetectionReport struct {
	Status     string
	Message    string
	Details    []string
	Warnings   []string
	ReportJSON string
}

type DetectionCandidate interface {
	PolicyID() string
	PolicyVersion() uint64
	BuildReport() DetectionReport
}

type DetectionResult struct {
	Candidate DetectionCandidate
	Report    DetectionReport
}

type DetectionRepository interface {
	PrepareDetection(context.Context, string) (DetectionCandidate, error)
	PersistDetection(context.Context, DetectionCandidate) error
}

type DetectionRuntime interface {
	RecordRejectedDetection(DetectionCandidate)
	PublishDetection(DetectionCandidate)
}

type DetectionService struct {
	repository DetectionRepository
	runtime    DetectionRuntime
}

func NewDetectionService(repository DetectionRepository, runtime DetectionRuntime) *DetectionService {
	return &DetectionService{repository: repository, runtime: runtime}
}

func (s *DetectionService) Validate(ctx context.Context, document string) (DetectionCandidate, error) {
	if err := s.initialized(); err != nil {
		return nil, err
	}
	return s.repository.PrepareDetection(ctx, document)
}

func (s *DetectionService) Activate(ctx context.Context, document string) (DetectionResult, error) {
	candidate, err := s.Validate(ctx, document)
	if err != nil {
		return DetectionResult{}, err
	}
	report := candidate.BuildReport()
	if report.Status == "rejected" {
		s.runtime.RecordRejectedDetection(candidate)
		return DetectionResult{Candidate: candidate, Report: report}, nil
	}
	if err := s.repository.PersistDetection(ctx, candidate); err != nil {
		return DetectionResult{}, fmt.Errorf("persist detection policy: %w", err)
	}
	s.runtime.PublishDetection(candidate)
	return DetectionResult{Candidate: candidate, Report: report}, nil
}

func (s *DetectionService) initialized() error {
	if s == nil || s.repository == nil || s.runtime == nil {
		return fmt.Errorf("detection policy service is not initialized")
	}
	return nil
}
