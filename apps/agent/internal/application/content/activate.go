package content

import (
	"context"
	"fmt"

	domaincontent "github.com/sysarmor/sysarmor-next-project/apps/agent/internal/domain/content"
	"github.com/sysarmor/sysarmor-next-project/apps/agent/internal/ports"
)

type Service struct {
	repository ports.ContentRepository
	runtime    ports.ContentRuntime
	mutation   ports.ContentMutation
}

func NewService(repository ports.ContentRepository, runtime ports.ContentRuntime, mutation ports.ContentMutation) *Service {
	return &Service{repository: repository, runtime: runtime, mutation: mutation}
}

func (s *Service) Validate(_ context.Context, document string, allowUnsigned bool) (domaincontent.Record, error) {
	if s == nil || s.repository == nil {
		return domaincontent.Record{}, fmt.Errorf("content service is not initialized")
	}
	return s.repository.Validate(document, allowUnsigned)
}

func (s *Service) Activate(ctx context.Context, document string, allowUnsigned bool) (domaincontent.Record, error) {
	if s == nil || s.repository == nil || s.runtime == nil || s.mutation == nil {
		return domaincontent.Record{}, fmt.Errorf("content service is not initialized")
	}
	release, err := s.mutation.Begin(ctx, true)
	if err != nil {
		return domaincontent.Record{}, err
	}
	defer release()
	record, snapshot, err := s.repository.Prepare(document, allowUnsigned)
	if err != nil {
		return domaincontent.Record{}, err
	}
	built, err := s.runtime.BuildDetection(snapshot)
	if err != nil {
		return domaincontent.Record{}, fmt.Errorf("build detection: %w", err)
	}
	if err := s.repository.Commit(record); err != nil {
		return domaincontent.Record{}, err
	}
	s.runtime.ActivateDetection(snapshot, built)
	return record, nil
}
