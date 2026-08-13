package artifact

import (
	"strings"
	"time"

	"github.com/sysarmor/sysarmor-next-project/apps/manager/internal/domain/failure"
	"github.com/sysarmor/sysarmor-next-project/apps/manager/internal/domain/tenant"
)

type Status string

const (
	StatusDraft   Status = "draft"
	StatusActive  Status = "active"
	StatusRevoked Status = "revoked"
)

type Artifact struct {
	ID          string
	TenantID    tenant.ID
	Name        string
	Kind        string
	Version     string
	OS          string
	Arch        string
	SHA256      string
	SizeBytes   int64
	Status      Status
	StoragePath string
	CreatedAt   time.Time
	UpdatedAt   time.Time
	CreatedBy   string
	Metadata    map[string]string
}

type Channel struct {
	TenantID   tenant.ID
	Name       string
	ArtifactID string
	CreatedAt  time.Time
	UpdatedAt  time.Time
	CreatedBy  string
}

func New(value Artifact, now time.Time) (Artifact, error) {
	value.ID = strings.TrimSpace(value.ID)
	value.Name = strings.TrimSpace(value.Name)
	value.Kind = strings.TrimSpace(value.Kind)
	value.Version = strings.TrimSpace(value.Version)
	value.SHA256 = strings.TrimSpace(value.SHA256)
	if value.TenantID.IsZero() || value.ID == "" || value.Name == "" || value.Kind == "" || value.Version == "" || value.SHA256 == "" {
		return Artifact{}, failure.New(failure.InvalidArgument, "artifact identity and digest are required")
	}
	if value.SizeBytes < 0 {
		return Artifact{}, failure.New(failure.InvalidArgument, "artifact size must not be negative")
	}
	if value.Status == "" {
		value.Status = StatusDraft
	}
	if !validStatus(value.Status) {
		return Artifact{}, failure.New(failure.InvalidArgument, "artifact status is invalid")
	}
	value.Metadata = cloneMetadata(value.Metadata)
	value.CreatedAt, value.UpdatedAt = now.UTC(), now.UTC()
	return value, nil
}

func (artifact Artifact) ChangeStatus(status Status, now time.Time) (Artifact, error) {
	if status != StatusActive && status != StatusRevoked {
		return Artifact{}, failure.New(failure.InvalidArgument, "artifact status transition is invalid")
	}
	artifact.Status = status
	artifact.UpdatedAt = now.UTC()
	artifact.Metadata = cloneMetadata(artifact.Metadata)
	return artifact, nil
}

func NewChannel(value Channel, artifact Artifact, actor string, now time.Time) (Channel, error) {
	value.Name = strings.TrimSpace(value.Name)
	if value.TenantID.IsZero() || value.Name == "" {
		return Channel{}, failure.New(failure.InvalidArgument, "artifact channel identity is required")
	}
	if artifact.TenantID != value.TenantID {
		return Channel{}, failure.New(failure.NotFound, "active artifact not found")
	}
	if artifact.Status != StatusActive {
		return Channel{}, failure.New(failure.FailedPrecondition, "active artifact not found")
	}
	value.ArtifactID = artifact.ID
	value.CreatedBy = strings.TrimSpace(actor)
	value.CreatedAt, value.UpdatedAt = now.UTC(), now.UTC()
	return value, nil
}

func validStatus(status Status) bool {
	switch status {
	case StatusDraft, StatusActive, StatusRevoked:
		return true
	default:
		return false
	}
}

func cloneMetadata(values map[string]string) map[string]string {
	if len(values) == 0 {
		return nil
	}
	result := make(map[string]string, len(values))
	for key, value := range values {
		result[key] = value
	}
	return result
}
