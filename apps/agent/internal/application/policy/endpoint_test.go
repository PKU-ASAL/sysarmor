package policy

import (
	"context"
	"errors"
	"strings"
	"testing"
)

type endpointCandidateFake struct {
	id      string
	version uint64
	source  Source
}

func (f endpointCandidateFake) PolicyID() string      { return f.id }
func (f endpointCandidateFake) PolicyVersion() uint64 { return f.version }
func (f endpointCandidateFake) PolicySource() Source  { return f.source }

type endpointRepoFake struct {
	candidate                                      EndpointCandidate
	persisted, desired, durable, promoted          bool
	pending                                        EndpointCandidate
	standalone                                     EndpointCandidate
	persistErr, desiredErr, durableErr, promoteErr error
	pendingErr, standaloneErr                      error
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
	return f.desiredErr
}
func (f *endpointRepoFake) ActivateManagedDurable(context.Context, EndpointCandidate) error {
	f.durable = true
	return f.durableErr
}
func (f *endpointRepoFake) PromoteManaged(context.Context, EndpointCandidate) error {
	f.promoted = true
	return f.promoteErr
}
func (f *endpointRepoFake) PendingManaged(context.Context) (EndpointCandidate, bool, error) {
	return f.pending, f.pending != nil, f.pendingErr
}
func (f *endpointRepoFake) LoadStandalone(context.Context) (EndpointCandidate, bool, error) {
	return f.standalone, f.standalone != nil, f.standaloneErr
}

type endpointRuntimeFake struct {
	report                         EndpointReport
	applyErr, rollbackErr          error
	applied, rolledBack, activated bool
}

func (f *endpointRuntimeFake) ApplyEndpoint(context.Context, EndpointCandidate) (EndpointReport, error) {
	f.applied = true
	return f.report, f.applyErr
}
func (f *endpointRuntimeFake) RollbackEndpoint(context.Context, EndpointCandidate) error {
	f.rolledBack = true
	return f.rollbackErr
}
func (f *endpointRuntimeFake) ActivateEndpoint(EndpointCandidate, EndpointReport) { f.activated = true }

func TestEndpointCandidateExposesOnlyApplicationIdentity(t *testing.T) {
	candidate := endpointCandidateFake{id: "p1", version: 2, source: SourceManaged}
	var contract EndpointCandidate = candidate
	if contract.PolicyID() != "p1" || contract.PolicyVersion() != 2 || contract.PolicySource() != SourceManaged {
		t.Fatalf("candidate identity is incorrect: %+v", candidate)
	}
}

func TestEndpointStandalonePersistenceFailureRollsBackRuntime(t *testing.T) {
	candidate := endpointCandidateFake{id: "p1", source: SourceStandalone}
	repo := &endpointRepoFake{candidate: candidate, persistErr: errors.New("disk full")}
	runtime := &endpointRuntimeFake{report: EndpointReport{Status: "applied"}}
	service := NewEndpointService(repo, runtime)

	_, err := service.ActivateStandalone(t.Context(), "{}")

	if err == nil || !strings.Contains(err.Error(), "persist endpoint policy") {
		t.Fatalf("ActivateStandalone() error = %v", err)
	}
	if !runtime.rolledBack || runtime.activated {
		t.Fatalf("runtime=%+v", runtime)
	}
}

func TestEndpointStandaloneReportsRollbackFailure(t *testing.T) {
	candidate := endpointCandidateFake{id: "p1", source: SourceStandalone}
	repo := &endpointRepoFake{candidate: candidate, persistErr: errors.New("disk full")}
	runtime := &endpointRuntimeFake{rollbackErr: errors.New("sensor rollback failed")}
	service := NewEndpointService(repo, runtime)

	_, err := service.ActivateStandalone(t.Context(), "{}")

	if err == nil || !strings.Contains(err.Error(), "disk full") || !strings.Contains(err.Error(), "sensor rollback failed") {
		t.Fatalf("ActivateStandalone() error = %v", err)
	}
}

func TestEndpointManagedSensorFailureStaysPending(t *testing.T) {
	repo := &endpointRepoFake{candidate: endpointCandidateFake{id: "p1"}}
	runtime := &endpointRuntimeFake{applyErr: errors.New("sensor unavailable")}
	service := NewEndpointService(repo, runtime)

	report, pending, err := service.ActivateManaged(t.Context(), "{}")

	if err != nil || !pending || report.Status != "pending" || !repo.desired || repo.durable || repo.promoted || runtime.activated {
		t.Fatalf("report=%+v pending=%v repo=%+v runtime=%+v err=%v", report, pending, repo, runtime, err)
	}
}

func TestEndpointManagedDurableFailureStaysPending(t *testing.T) {
	repo := &endpointRepoFake{candidate: endpointCandidateFake{id: "p1"}, durableErr: errors.New("disk full")}
	runtime := &endpointRuntimeFake{report: EndpointReport{Status: "applied"}}
	service := NewEndpointService(repo, runtime)

	report, pending, err := service.ActivateManaged(t.Context(), "{}")

	if err != nil || !pending || report.Status != "pending" || !repo.durable || repo.promoted || runtime.activated {
		t.Fatalf("report=%+v pending=%v repo=%+v runtime=%+v err=%v", report, pending, repo, runtime, err)
	}
}

func TestEndpointManagedPromotionFailureStaysPending(t *testing.T) {
	repo := &endpointRepoFake{candidate: endpointCandidateFake{id: "p1"}, promoteErr: errors.New("authority unavailable")}
	runtime := &endpointRuntimeFake{report: EndpointReport{Status: "applied"}}
	service := NewEndpointService(repo, runtime)

	report, pending, err := service.ActivateManaged(t.Context(), "{}")

	if err != nil || !pending || report.Status != "pending" || !repo.promoted || runtime.activated {
		t.Fatalf("report=%+v pending=%v repo=%+v runtime=%+v err=%v", report, pending, repo, runtime, err)
	}
}

func TestEndpointResumeManagedCompletesPendingWithoutReapplyingSensor(t *testing.T) {
	candidate := endpointCandidateFake{id: "p1", source: SourceManaged}
	repo := &endpointRepoFake{pending: candidate}
	runtime := &endpointRuntimeFake{}
	service := NewEndpointService(repo, runtime)

	ok, err := service.ResumeManaged(t.Context())

	if err != nil || !ok || !repo.durable || !repo.promoted || runtime.applied || !runtime.activated {
		t.Fatalf("ok=%v repo=%+v runtime=%+v err=%v", ok, repo, runtime, err)
	}
}

func TestEndpointRestoreStandaloneRollsBackWhenDurableSwitchFails(t *testing.T) {
	candidate := endpointCandidateFake{id: "local", source: SourceStandalone}
	repo := &endpointRepoFake{standalone: candidate}
	runtime := &endpointRuntimeFake{report: EndpointReport{Status: "applied"}}
	service := NewEndpointService(repo, runtime)

	err := service.RestoreStandalone(t.Context(), func(context.Context) error {
		return errors.New("credential cleanup failed")
	})

	if err == nil || !runtime.rolledBack || runtime.activated {
		t.Fatalf("runtime=%+v err=%v", runtime, err)
	}
}

func TestEndpointValidateHasNoSideEffects(t *testing.T) {
	repo := &endpointRepoFake{candidate: endpointCandidateFake{id: "p1"}}
	runtime := &endpointRuntimeFake{}
	service := NewEndpointService(repo, runtime)

	if _, err := service.Validate(t.Context(), "{}", SourceManaged); err != nil {
		t.Fatal(err)
	}
	if repo.persisted || repo.desired || repo.durable || repo.promoted || runtime.applied || runtime.activated {
		t.Fatalf("repo=%+v runtime=%+v", repo, runtime)
	}
}
