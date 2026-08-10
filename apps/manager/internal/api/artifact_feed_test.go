package managerapi

import (
	"testing"

	"github.com/sysarmor/sysarmor-next-project/apps/manager/internal/store"
)

func TestArtifactFeedSeedsExternalArtifactAndChannel(t *testing.T) {
	state := &store.Store{}
	server := NewServer(state)
	err := server.SeedArtifactFeedData([]byte(`{
		"schema_version":"sysarmor.artifact.feed/v1",
		"artifacts":[{
			"artifact_id":"agent-linux-amd64-dev",
			"tenant_id":"default",
			"name":"sysarmor-agent",
			"kind":"agent",
			"version":"dev",
			"os":"linux",
			"arch":"amd64",
			"sha256":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
			"size_bytes":1234,
			"status":"active",
			"download_url":"https://artifacts.example/sysarmor-agent.tar.gz",
			"channels":["linux-container-dev"]
		}]
	}`))
	if err != nil {
		t.Fatal(err)
	}
	channel, ok := state.GetChannel("default", "linux-container-dev")
	if !ok || channel.ArtifactID != "agent-linux-amd64-dev" {
		t.Fatalf("channel=%#v found=%t", channel, ok)
	}
	artifact, ok := state.GetArtifact("default", channel.ArtifactID)
	if !ok || artifact.Metadata[artifactDownloadURLMetadataKey] != "https://artifacts.example/sysarmor-agent.tar.gz" {
		t.Fatalf("artifact=%#v found=%t", artifact, ok)
	}
}
