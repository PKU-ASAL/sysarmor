package policy

import (
	"context"
	"errors"
	"testing"
)

type repositoryFake struct {
	candidate             Candidate
	prepared, committed   bool
	prepareErr, commitErr error
}

func (f *repositoryFake) Prepare(context.Context, string, Source) (Candidate, error) {
	f.prepared = true
	return f.candidate, f.prepareErr
}
func (f *repositoryFake) Commit(context.Context, Candidate) error {
	f.committed = true
	return f.commitErr
}

type runtimeFake struct {
	report             Report
	applied, activated bool
	applyErr           error
}

func (f *runtimeFake) Apply(context.Context, Candidate) (Report, error) {
	f.applied = true
	return f.report, f.applyErr
}
func (f *runtimeFake) Activate(Candidate, Report) { f.activated = true }

type authorityFake struct{ begun bool }

func (f *authorityFake) Begin(context.Context, Source, bool) (func(), error) {
	f.begun = true
	return func() {}, nil
}

type pendingFake struct {
	saved, activated, promoted       bool
	saveErr, activateErr, promoteErr error
}

func (f *pendingFake) SaveDesired(context.Context, Candidate) error { f.saved = true; return f.saveErr }
func (f *pendingFake) ActivateDesired(context.Context, Candidate) error {
	f.activated = true
	return f.activateErr
}
func (f *pendingFake) Promote(context.Context, Candidate) error {
	f.promoted = true
	return f.promoteErr
}

func TestActivateCommitsBeforeRuntimeActivation(t *testing.T) {
	repo := &repositoryFake{candidate: Candidate{ID: "p1", Version: 2}}
	runtime := &runtimeFake{report: Report{Status: "applied"}}
	service := NewService(repo, runtime, &authorityFake{})
	if _, err := service.Activate(context.Background(), "{}", SourceStandalone); err != nil {
		t.Fatal(err)
	}
	if !repo.prepared || !runtime.applied || !repo.committed || !runtime.activated {
		t.Fatalf("state repo=%+v runtime=%+v", repo, runtime)
	}
}

func TestActivateDoesNotCommitWhenRuntimeRejects(t *testing.T) {
	repo := &repositoryFake{candidate: Candidate{ID: "p1"}}
	runtime := &runtimeFake{report: Report{Status: "rejected", Message: "missing published policy"}}
	service := NewService(repo, runtime, &authorityFake{})
	if _, err := service.Activate(context.Background(), "{}", SourceManaged); err == nil {
		t.Fatal("expected rejection")
	}
	if repo.committed || runtime.activated {
		t.Fatalf("unexpected state repo=%+v runtime=%+v", repo, runtime)
	}
}

func TestActivatePropagatesPrepareFailure(t *testing.T) {
	repo := &repositoryFake{prepareErr: errors.New("invalid policy")}
	service := NewService(repo, &runtimeFake{}, &authorityFake{})
	if _, err := service.Activate(context.Background(), "{}", SourceStandalone); err == nil {
		t.Fatal("expected prepare error")
	}
	if repo.committed {
		t.Fatal("committed after prepare failure")
	}
}

func TestValidateDoesNotCommitOrActivate(t *testing.T) {
	repo := &repositoryFake{candidate: Candidate{ID: "p1"}}
	runtime := &runtimeFake{}
	service := NewService(repo, runtime, &authorityFake{})
	if _, err := service.Validate(context.Background(), "{}", SourceManaged); err != nil {
		t.Fatal(err)
	}
	if repo.committed || runtime.applied || runtime.activated {
		t.Fatalf("validation mutated state repo=%+v runtime=%+v", repo, runtime)
	}
}

func TestActivateManagedPersistsPendingWhenSensorUnavailable(t *testing.T) {
	repo := &repositoryFake{candidate: Candidate{ID: "p1"}}
	runtime := &runtimeFake{applyErr: errors.New("sensor unavailable")}
	pending := &pendingFake{}
	service := NewService(repo, runtime, &authorityFake{})
	result, err := service.ActivateManaged(context.Background(), "{}", pending, SourceManaged)
	if err != nil {
		t.Fatal(err)
	}
	if !result.Pending || !pending.saved || pending.activated || pending.promoted || runtime.activated {
		t.Fatalf("result=%+v pending=%+v runtime=%+v", result, pending, runtime)
	}
}
