package policy

import (
	"context"
	"fmt"
)

type Source string

const (
	SourceStandalone Source = "standalone"
	SourceManaged    Source = "managed"
)

type Candidate struct {
	ID      string
	Version uint64
	Source  Source
	Raw     string
}

type Report struct {
	Status   string
	Message  string
	Details  []string
	Warnings []string
}

type Result struct {
	Candidate Candidate
	Report    Report
}

type Repository interface {
	Prepare(context.Context, string, Source) (Candidate, error)
	Commit(context.Context, Candidate) error
}

type Runtime interface {
	Apply(context.Context, Candidate) (Report, error)
	Activate(Candidate, Report)
}

type Authority interface {
	Begin(context.Context, Source, bool) (func(), error)
}

type Service struct {
	repository Repository
	runtime    Runtime
	authority  Authority
}

func NewService(repository Repository, runtime Runtime, authority Authority) *Service {
	return &Service{repository: repository, runtime: runtime, authority: authority}
}

func (s *Service) Activate(ctx context.Context, document string, source Source) (Result, error) {
	if s == nil || s.repository == nil || s.runtime == nil || s.authority == nil {
		return Result{}, fmt.Errorf("policy service is not initialized")
	}
	release, err := s.authority.Begin(ctx, source, true)
	if err != nil {
		return Result{}, err
	}
	defer release()
	candidate, err := s.repository.Prepare(ctx, document, source)
	if err != nil {
		return Result{}, err
	}
	report, err := s.runtime.Apply(ctx, candidate)
	if err != nil {
		return Result{}, fmt.Errorf("apply policy: %w", err)
	}
	if report.Status == "rejected" {
		return Result{Candidate: candidate, Report: report}, fmt.Errorf("policy rejected: %s", report.Message)
	}
	if err := s.repository.Commit(ctx, candidate); err != nil {
		return Result{}, err
	}
	s.runtime.Activate(candidate, report)
	return Result{Candidate: candidate, Report: report}, nil
}
