package feed

import (
	"context"
	"strings"
	"testing"

	managerapp "github.com/sysarmor/sysarmor-next-project/apps/manager/internal/application/manager"
	artifactapp "github.com/sysarmor/sysarmor-next-project/apps/manager/internal/application/manager/artifact"
	domainartifact "github.com/sysarmor/sysarmor-next-project/apps/manager/internal/domain/artifact"
)

func TestArtifactSeederRegistersArtifactAndChannelThroughApplication(t *testing.T) {
	service := &artifactFeedServiceStub{}
	seeder := NewArtifactSeeder(service, nil)
	err := seeder.SeedData(context.Background(), []byte(`{
		"schema_version":"sysarmor.artifact.feed/v1",
		"artifacts":[{
			"artifact_id":"agent-linux-amd64-dev","tenant_id":"tenant-a","name":"sysarmor-agent",
			"kind":"agent","version":"dev","os":"linux","arch":"amd64","sha256":"sha256-a",
			"size_bytes":1234,"status":"active","download_url":"https://artifacts.example/agent.tar.gz",
			"channels":["stable"]
		}]
	}`))
	if err != nil {
		t.Fatal(err)
	}
	if service.registerRequest.Actor.TenantID != "tenant-a" || service.registerRequest.Actor.Subject != packageIndexSource {
		t.Fatalf("request=%+v", service.registerRequest)
	}
	if service.register.Value.Metadata[artifactDownloadURLMetadataKey] != "https://artifacts.example/agent.tar.gz" ||
		service.register.Value.Metadata["source"] != packageIndexSource {
		t.Fatalf("artifact=%+v", service.register.Value)
	}
	if service.channel.Name != "stable" || service.channel.ArtifactID != "agent-linux-amd64-dev" {
		t.Fatalf("channel=%+v", service.channel)
	}
}

func TestArtifactSeederRejectsBlankTenant(t *testing.T) {
	seeder := NewArtifactSeeder(&artifactFeedServiceStub{}, nil)
	err := seeder.SeedData(context.Background(), []byte(`{
		"schema_version":"sysarmor.artifact.feed/v1",
		"artifacts":[{"name":"agent","kind":"agent","version":"dev","sha256":"sha256-a",
		"download_url":"https://artifacts.example/agent.tar.gz"}]
	}`))
	if err == nil || !strings.Contains(err.Error(), "tenant_id") {
		t.Fatalf("error=%v", err)
	}
}

type artifactFeedServiceStub struct {
	registerRequest managerapp.RequestContext
	register        artifactapp.RegisterCommand
	channel         artifactapp.SetChannelCommand
}

func (stub *artifactFeedServiceStub) Register(_ context.Context, request managerapp.RequestContext, command artifactapp.RegisterCommand) (domainartifact.Artifact, error) {
	stub.registerRequest, stub.register = request, command
	return command.Value, nil
}

func (stub *artifactFeedServiceStub) SetChannel(_ context.Context, _ managerapp.RequestContext, command artifactapp.SetChannelCommand) (domainartifact.Channel, error) {
	stub.channel = command
	return domainartifact.Channel{Name: command.Name, ArtifactID: command.ArtifactID}, nil
}
