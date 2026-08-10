package artifact

import (
	"testing"
	"time"

	"github.com/sysarmor/sysarmor-next-project/apps/manager/internal/domain/failure"
)

var artifactTestTime = time.Date(2026, 8, 10, 12, 0, 0, 0, time.UTC)

func TestChannelRejectsInactiveArtifact(t *testing.T) {
	value, err := New(Artifact{
		ID: "agent-a", TenantID: "tenant-a", Name: "sysarmor-agent", Kind: "agent",
		Version: "1.0.0", SHA256: "sha256-a", Status: StatusDraft,
	}, artifactTestTime)
	if err != nil {
		t.Fatal(err)
	}

	_, err = NewChannel(Channel{Name: "stable", TenantID: "tenant-a"}, value, "operator-a", artifactTestTime)
	if failure.KindOf(err) != failure.FailedPrecondition {
		t.Fatalf("kind=%v error=%v", failure.KindOf(err), err)
	}
}

func TestChannelUsesActiveArtifactIdentity(t *testing.T) {
	value, err := New(Artifact{
		ID: "agent-a", TenantID: "tenant-a", Name: "sysarmor-agent", Kind: "agent",
		Version: "1.0.0", SHA256: "sha256-a", Status: StatusActive,
	}, artifactTestTime)
	if err != nil {
		t.Fatal(err)
	}

	channel, err := NewChannel(Channel{Name: "stable", TenantID: "tenant-a"}, value, "operator-a", artifactTestTime)
	if err != nil {
		t.Fatal(err)
	}
	if channel.ArtifactID != "agent-a" || channel.CreatedBy != "operator-a" || channel.CreatedAt != artifactTestTime {
		t.Fatalf("channel=%+v", channel)
	}
}

func TestArtifactCanBeActivatedAndRevoked(t *testing.T) {
	value, err := New(Artifact{
		ID: "agent-a", TenantID: "tenant-a", Name: "sysarmor-agent", Kind: "agent",
		Version: "1.0.0", SHA256: "sha256-a",
	}, artifactTestTime)
	if err != nil {
		t.Fatal(err)
	}
	active, err := value.ChangeStatus(StatusActive, artifactTestTime.Add(time.Minute))
	if err != nil {
		t.Fatal(err)
	}
	revoked, err := active.ChangeStatus(StatusRevoked, artifactTestTime.Add(2*time.Minute))
	if err != nil {
		t.Fatal(err)
	}
	if active.Status != StatusActive || revoked.Status != StatusRevoked || revoked.UpdatedAt != artifactTestTime.Add(2*time.Minute) {
		t.Fatalf("active=%+v revoked=%+v", active, revoked)
	}
}
