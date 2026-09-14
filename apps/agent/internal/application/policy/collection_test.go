package policy

import (
	"context"
	"errors"
	"testing"
)

type collectionCandidateFake struct {
	id      string
	version uint64
	report  CollectionReport
}

func (c collectionCandidateFake) PolicyID() string                   { return c.id }
func (c collectionCandidateFake) PolicyVersion() uint64              { return c.version }
func (c collectionCandidateFake) ValidationReport() CollectionReport { return c.report }

type collectionRepositoryFake struct {
	candidate              CollectionCandidate
	prepareErr, persistErr error
	events                 *[]string
}

func (f *collectionRepositoryFake) PrepareCollection(context.Context, string, CollectionScope) (CollectionCandidate, error) {
	return f.candidate, f.prepareErr
}
func (f *collectionRepositoryFake) PersistCollection(context.Context, CollectionCandidate) error {
	*f.events = append(*f.events, "persist")
	return f.persistErr
}

type collectionRuntimeFake struct {
	events      *[]string
	applyErr    error
	rollbackErr error
}

func (f *collectionRuntimeFake) ApplyCollection(context.Context, CollectionCandidate) error {
	*f.events = append(*f.events, "apply")
	return f.applyErr
}
func (f *collectionRuntimeFake) RollbackCollection(context.Context, CollectionCandidate) error {
	*f.events = append(*f.events, "rollback")
	return f.rollbackErr
}
func (f *collectionRuntimeFake) PublishCollection(CollectionCandidate) {
	*f.events = append(*f.events, "activate")
}

func TestCollectionActivationPersistsAfterSensorBeforePublish(t *testing.T) {
	events := []string{}
	candidate := collectionCandidateFake{id: "collection-a", version: 2, report: CollectionReport{Status: "applied"}}
	service := NewCollectionService(&collectionRepositoryFake{candidate: candidate, events: &events}, &collectionRuntimeFake{events: &events})
	result, err := service.Activate(t.Context(), "{}", CollectionScope{Type: "host"})
	if err != nil || result.Candidate.PolicyID() != "collection-a" || len(events) != 3 || events[0] != "apply" || events[1] != "persist" || events[2] != "activate" {
		t.Fatalf("result=%+v events=%v err=%v", result, events, err)
	}
}

func TestCollectionPersistenceFailureRollsBackSensor(t *testing.T) {
	events := []string{}
	repository := &collectionRepositoryFake{candidate: collectionCandidateFake{id: "collection-a"}, events: &events, persistErr: errors.New("disk full")}
	service := NewCollectionService(repository, &collectionRuntimeFake{events: &events})
	if _, err := service.Activate(t.Context(), "{}", CollectionScope{}); err == nil {
		t.Fatal("expected persistence failure")
	}
	if len(events) != 3 || events[2] != "rollback" {
		t.Fatalf("events=%v", events)
	}
}

func TestCollectionSensorFailureDoesNotPersist(t *testing.T) {
	events := []string{}
	repository := &collectionRepositoryFake{candidate: collectionCandidateFake{id: "collection-a"}, events: &events}
	service := NewCollectionService(repository, &collectionRuntimeFake{events: &events, applyErr: errors.New("sensor unavailable")})
	if _, err := service.Activate(t.Context(), "{}", CollectionScope{}); err == nil {
		t.Fatal("expected sensor failure")
	}
	if len(events) != 1 || events[0] != "apply" {
		t.Fatalf("events=%v", events)
	}
}

func TestCollectionValidationHasNoSideEffects(t *testing.T) {
	events := []string{}
	repository := &collectionRepositoryFake{candidate: collectionCandidateFake{id: "collection-a"}, events: &events}
	service := NewCollectionService(repository, &collectionRuntimeFake{events: &events})
	if _, err := service.Validate(t.Context(), "{}", CollectionScope{Type: "container", Selector: "a"}); err != nil {
		t.Fatal(err)
	}
	if len(events) != 0 {
		t.Fatalf("events=%v", events)
	}
}
