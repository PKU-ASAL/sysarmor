package policy

import (
	"context"
	"fmt"
)

type CollectionScope struct {
	Type     string
	Selector string
}

type CollectionReport struct {
	Status     string
	Message    string
	Warnings   []string
	ReportJSON string
}

type CollectionCandidate interface {
	PolicyID() string
	PolicyVersion() uint64
	ValidationReport() CollectionReport
}

type CollectionResult struct {
	Candidate CollectionCandidate
	Report    CollectionReport
}

type CollectionRepository interface {
	PrepareCollection(context.Context, string, CollectionScope) (CollectionCandidate, error)
	PersistCollection(context.Context, CollectionCandidate) error
}

type CollectionRuntime interface {
	ApplyCollection(context.Context, CollectionCandidate) error
	RollbackCollection(context.Context, CollectionCandidate) error
	PublishCollection(CollectionCandidate)
}

type CollectionService struct {
	repository CollectionRepository
	runtime    CollectionRuntime
}

func NewCollectionService(repository CollectionRepository, runtime CollectionRuntime) *CollectionService {
	return &CollectionService{repository: repository, runtime: runtime}
}

func (s *CollectionService) Validate(ctx context.Context, document string, scope CollectionScope) (CollectionCandidate, error) {
	if err := s.initialized(); err != nil {
		return nil, err
	}
	return s.repository.PrepareCollection(ctx, document, scope)
}

func (s *CollectionService) Activate(ctx context.Context, document string, scope CollectionScope) (CollectionResult, error) {
	candidate, err := s.Validate(ctx, document, scope)
	if err != nil {
		return CollectionResult{}, err
	}
	if err := s.runtime.ApplyCollection(ctx, candidate); err != nil {
		return CollectionResult{}, fmt.Errorf("apply collection policy: %w", err)
	}
	if err := s.repository.PersistCollection(ctx, candidate); err != nil {
		cause := fmt.Errorf("persist collection policy: %w", err)
		if rollbackErr := s.runtime.RollbackCollection(ctx, candidate); rollbackErr != nil {
			cause = fmt.Errorf("%w; rollback collection runtime: %v", cause, rollbackErr)
		}
		return CollectionResult{}, cause
	}
	s.runtime.PublishCollection(candidate)
	return CollectionResult{Candidate: candidate, Report: candidate.ValidationReport()}, nil
}

func (s *CollectionService) initialized() error {
	if s == nil || s.repository == nil || s.runtime == nil {
		return fmt.Errorf("collection policy service is not initialized")
	}
	return nil
}
