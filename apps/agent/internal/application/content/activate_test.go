package content

import (
	"context"
	"errors"
	"testing"

	domaincontent "github.com/sysarmor/sysarmor-next-project/apps/agent/internal/domain/content"
)

type repositoryFake struct {
	record              domaincontent.Record
	snapshot            domaincontent.Snapshot
	committed, prepared bool
	commitErr           error
}

func (f *repositoryFake) Validate(string, bool) (domaincontent.Record, error) { return f.record, nil }
func (f *repositoryFake) Prepare(string, bool) (domaincontent.Record, domaincontent.Snapshot, error) {
	f.prepared = true
	return f.record, f.snapshot, nil
}
func (f *repositoryFake) Commit(domaincontent.Record) error  { f.committed = true; return f.commitErr }
func (f *repositoryFake) List(string) []domaincontent.Record { return nil }
func (f *repositoryFake) Get(string) (domaincontent.Record, bool) {
	return domaincontent.Record{}, false
}

type runtimeFake struct {
	built, activated bool
	buildErr         error
}

func (f *runtimeFake) BuildDetection(domaincontent.Snapshot) (any, error) {
	f.built = true
	return struct{}{}, f.buildErr
}
func (f *runtimeFake) ActivateDetection(domaincontent.Snapshot, any) { f.activated = true }

type mutationFake struct{ released bool }

func (f *mutationFake) Begin(context.Context, bool) (func(), error) {
	return func() { f.released = true }, nil
}

func TestActivateCommitsBeforeRuntimeSwap(t *testing.T) {
	repo := &repositoryFake{record: domaincontent.Record{Ref: "rulepack:r1"}}
	runtime := &runtimeFake{}
	service := NewService(repo, runtime, &mutationFake{})
	if _, err := service.Activate(context.Background(), "{}", false); err != nil {
		t.Fatal(err)
	}
	if !repo.prepared || !repo.committed || !runtime.built || !runtime.activated {
		t.Fatalf("activation state: %+v %+v", repo, runtime)
	}
}

func TestActivateDoesNotCommitWhenDetectionBuildFails(t *testing.T) {
	repo := &repositoryFake{record: domaincontent.Record{Ref: "rulepack:r1"}}
	runtime := &runtimeFake{buildErr: errors.New("invalid rule")}
	service := NewService(repo, runtime, &mutationFake{})
	if _, err := service.Activate(context.Background(), "{}", false); err == nil {
		t.Fatal("expected build failure")
	}
	if repo.committed || runtime.activated {
		t.Fatalf("unexpected commit/swap: %+v %+v", repo, runtime)
	}
}
