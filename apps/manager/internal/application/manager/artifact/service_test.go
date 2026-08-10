package artifact

import (
	"context"
	"errors"
	"testing"
	"time"

	managerapp "github.com/sysarmor/sysarmor-next-project/apps/manager/internal/application/manager"
	domainartifact "github.com/sysarmor/sysarmor-next-project/apps/manager/internal/domain/artifact"
	"github.com/sysarmor/sysarmor-next-project/apps/manager/internal/domain/failure"
	"github.com/sysarmor/sysarmor-next-project/apps/manager/internal/domain/tenant"
	"github.com/sysarmor/sysarmor-next-project/apps/manager/internal/ports"
)

func TestSetChannelRejectsInactiveArtifactWithoutWriting(t *testing.T) {
	artifacts := &artifactRepositoryStub{current: domainartifact.Artifact{
		ID: "agent-a", TenantID: "tenant-a", Status: domainartifact.StatusRevoked,
	}}
	channels := &channelRepositoryStub{}
	service := NewService(&artifactUnitOfWorkStub{tx: artifactTransactionStub{
		artifacts: artifacts, channels: channels,
	}}, artifactClockStub{now: time.Unix(200, 0).UTC()})

	_, err := service.SetChannel(context.Background(), artifactOperatorRequest(t), SetChannelCommand{
		Name: "stable", ArtifactID: "agent-a",
	})
	if failure.KindOf(err) != failure.FailedPrecondition || channels.puts != 0 {
		t.Fatalf("kind=%v error=%v puts=%d", failure.KindOf(err), err, channels.puts)
	}
}

func TestSetChannelMapsMissingArtifactToFailedPrecondition(t *testing.T) {
	artifacts := &artifactRepositoryStub{getErr: failure.New(failure.NotFound, "artifact not found")}
	channels := &channelRepositoryStub{}
	service := NewService(&artifactUnitOfWorkStub{tx: artifactTransactionStub{
		artifacts: artifacts, channels: channels,
	}}, artifactClockStub{now: time.Unix(200, 0).UTC()})

	_, err := service.SetChannel(context.Background(), artifactOperatorRequest(t), SetChannelCommand{
		Name: "stable", ArtifactID: "missing",
	})
	if failure.KindOf(err) != failure.FailedPrecondition || channels.puts != 0 {
		t.Fatalf("kind=%v error=%v puts=%d", failure.KindOf(err), err, channels.puts)
	}
}

func TestSetChannelPreservesRepositoryFailure(t *testing.T) {
	wantErr := errors.New("database unavailable")
	service := NewService(&artifactUnitOfWorkStub{tx: artifactTransactionStub{
		artifacts: &artifactRepositoryStub{getErr: wantErr}, channels: &channelRepositoryStub{},
	}}, artifactClockStub{now: time.Unix(200, 0).UTC()})

	_, err := service.SetChannel(context.Background(), artifactOperatorRequest(t), SetChannelCommand{
		Name: "stable", ArtifactID: "artifact-a",
	})
	if !errors.Is(err, wantErr) {
		t.Fatalf("error=%v", err)
	}
}

func TestRegisterUsesAuthenticatedTenantAndActor(t *testing.T) {
	repository := &artifactRepositoryStub{}
	service := NewService(&artifactUnitOfWorkStub{tx: artifactTransactionStub{
		artifacts: repository, channels: &channelRepositoryStub{},
	}}, artifactClockStub{now: time.Unix(200, 0).UTC()})

	result, err := service.Register(context.Background(), artifactOperatorRequest(t), RegisterCommand{Value: domainartifact.Artifact{
		ID: "agent-a", TenantID: "tenant-b", Name: "sysarmor-agent", Kind: "agent", Version: "1.0.0", SHA256: "sha256-a",
	}})
	if err != nil {
		t.Fatal(err)
	}
	if result.TenantID != "tenant-a" || result.CreatedBy != "operator-a" || result.Status != domainartifact.StatusDraft || repository.puts != 1 {
		t.Fatalf("result=%+v puts=%d", result, repository.puts)
	}
}

func TestChangeStatusPersistsArtifact(t *testing.T) {
	repository := &artifactRepositoryStub{current: domainartifact.Artifact{
		ID: "agent-a", TenantID: "tenant-a", Status: domainartifact.StatusDraft,
	}}
	service := NewService(&artifactUnitOfWorkStub{tx: artifactTransactionStub{
		artifacts: repository, channels: &channelRepositoryStub{},
	}}, artifactClockStub{now: time.Unix(200, 0).UTC()})

	result, err := service.ChangeStatus(context.Background(), artifactOperatorRequest(t), ChangeStatusCommand{
		ArtifactID: "agent-a", Status: domainartifact.StatusActive,
	})
	if err != nil {
		t.Fatal(err)
	}
	if result.Status != domainartifact.StatusActive || repository.puts != 1 {
		t.Fatalf("result=%+v puts=%d", result, repository.puts)
	}
}

func TestListArtifactsUsesAuthenticatedTenant(t *testing.T) {
	repository := &artifactRepositoryStub{listed: []domainartifact.Artifact{{ID: "agent-a"}}}
	service := NewService(&artifactUnitOfWorkStub{tx: artifactTransactionStub{
		artifacts: repository, channels: &channelRepositoryStub{},
	}}, artifactClockStub{now: time.Unix(200, 0).UTC()})

	result, err := service.ListArtifacts(context.Background(), artifactOperatorRequest(t), ArtifactQuery{
		Kind: "agent", Status: domainartifact.StatusActive,
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(result) != 1 || repository.listTenant != "tenant-a" || repository.filter.Kind != "agent" {
		t.Fatalf("result=%+v tenant=%q filter=%+v", result, repository.listTenant, repository.filter)
	}
}

type artifactUnitOfWorkStub struct{ tx ports.ArtifactTransaction }

func (stub *artifactUnitOfWorkStub) Execute(ctx context.Context, fn func(context.Context, ports.ArtifactTransaction) error) error {
	return fn(ctx, stub.tx)
}

type artifactTransactionStub struct {
	artifacts ports.ArtifactRepository
	channels  ports.ArtifactChannelRepository
}

func (stub artifactTransactionStub) Artifacts() ports.ArtifactRepository       { return stub.artifacts }
func (stub artifactTransactionStub) Channels() ports.ArtifactChannelRepository { return stub.channels }

type artifactRepositoryStub struct {
	current    domainartifact.Artifact
	listed     []domainartifact.Artifact
	listTenant tenant.ID
	filter     ports.ArtifactFilter
	getErr     error
	puts       int
}

func (stub *artifactRepositoryStub) Get(context.Context, tenant.ID, string) (domainartifact.Artifact, error) {
	return stub.current, stub.getErr
}

func (stub *artifactRepositoryStub) List(_ context.Context, tenantID tenant.ID, filter ports.ArtifactFilter) ([]domainartifact.Artifact, error) {
	stub.listTenant, stub.filter = tenantID, filter
	return stub.listed, nil
}

func (stub *artifactRepositoryStub) Put(_ context.Context, value domainartifact.Artifact) (domainartifact.Artifact, error) {
	stub.puts++
	stub.current = value
	return value, nil
}

type channelRepositoryStub struct{ puts int }

func (stub *channelRepositoryStub) Get(context.Context, tenant.ID, string) (domainartifact.Channel, error) {
	return domainartifact.Channel{}, nil
}

func (stub *channelRepositoryStub) List(context.Context, tenant.ID) ([]domainartifact.Channel, error) {
	return nil, nil
}

func (stub *channelRepositoryStub) Put(_ context.Context, value domainartifact.Channel) (domainartifact.Channel, error) {
	stub.puts++
	return value, nil
}

type artifactClockStub struct{ now time.Time }

func (stub artifactClockStub) Now() time.Time { return stub.now }

func artifactOperatorRequest(t *testing.T) managerapp.RequestContext {
	t.Helper()
	tenantID, err := tenant.NewID("tenant-a")
	if err != nil {
		t.Fatal(err)
	}
	return managerapp.RequestContext{Actor: tenant.Actor{
		Subject: "operator-a", TenantID: tenantID, Roles: tenant.NewRoleSet(tenant.RoleOperator),
	}}
}
