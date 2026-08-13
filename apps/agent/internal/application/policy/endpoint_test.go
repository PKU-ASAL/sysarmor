package policy

import (
	"context"
	"errors"
	"testing"
)

type endpointRepoFake struct {
	candidate                             EndpointCandidate
	persisted, desired, durable, promoted bool
	persistErr                            error
}

func (f *endpointRepoFake) PrepareEndpoint(context.Context, string, Source) (EndpointCandidate, error) {
	return f.candidate, nil
}
func (f *endpointRepoFake) PersistEndpoint(context.Context, EndpointCandidate) error {
	f.persisted = true
	return f.persistErr
}
func (f *endpointRepoFake) SaveDesiredManaged(context.Context, EndpointCandidate) error {
	f.desired = true
	return nil
}
func (f *endpointRepoFake) ActivateManagedDurable(context.Context, EndpointCandidate) error {
	f.durable = true
	return nil
}
func (f *endpointRepoFake) PromoteManaged(context.Context, EndpointCandidate) error {
	f.promoted = true
	return nil
}

type endpointRuntimeFake struct {
	report             EndpointReport
	applyErr           error
	applied, activated bool
}

func (f *endpointRuntimeFake) ApplyEndpoint(context.Context, EndpointCandidate) (EndpointReport, error) {
	f.applied = true
	return f.report, f.applyErr
}
func (f *endpointRuntimeFake) ActivateEndpoint(EndpointCandidate, EndpointReport) { f.activated = true }

func TestEndpointManagedSensorFailureStaysPending(t *testing.T) {
	repo := &endpointRepoFake{candidate: EndpointCandidate{ID: "p1"}}
	runtime := &endpointRuntimeFake{applyErr: errors.New("sensor unavailable")}
	service := NewEndpointService(repo, runtime)
	report, pending, err := service.ActivateManaged(context.Background(), "{}")
	if err != nil || !pending || report.Status != "pending" || !repo.desired || repo.durable || repo.promoted || runtime.activated {
		t.Fatalf("report=%+v pending=%v repo=%+v runtime=%+v err=%v", report, pending, repo, runtime, err)
	}
}

func TestEndpointStandalonePersistsBeforeActivation(t *testing.T) {
	repo := &endpointRepoFake{candidate: EndpointCandidate{ID: "p1"}}
	runtime := &endpointRuntimeFake{report: EndpointReport{Status: "applied"}}
	service := NewEndpointService(repo, runtime)
	if _, err := service.ActivateStandalone(context.Background(), "{}"); err != nil {
		t.Fatal(err)
	}
	if !repo.persisted || !runtime.activated {
		t.Fatalf("repo=%+v runtime=%+v", repo, runtime)
	}
}
