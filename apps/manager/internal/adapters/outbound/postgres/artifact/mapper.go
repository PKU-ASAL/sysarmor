package artifact

import (
	"encoding/json"
	"fmt"
	"strings"
	"time"

	domainartifact "github.com/sysarmor/sysarmor-next-project/apps/manager/internal/domain/artifact"
	"github.com/sysarmor/sysarmor-next-project/apps/manager/internal/domain/failure"
	"github.com/sysarmor/sysarmor-next-project/apps/manager/internal/domain/tenant"
)

type artifactRecord struct {
	ID          string                `json:"artifact_id"`
	TenantID    string                `json:"tenant_id"`
	Name        string                `json:"name"`
	Kind        string                `json:"kind"`
	Version     string                `json:"version"`
	OS          string                `json:"os,omitempty"`
	Arch        string                `json:"arch,omitempty"`
	SHA256      string                `json:"sha256"`
	SizeBytes   int64                 `json:"size_bytes"`
	Status      domainartifact.Status `json:"status"`
	StoragePath string                `json:"storage_path,omitempty"`
	CreatedAt   time.Time             `json:"created_at"`
	UpdatedAt   time.Time             `json:"updated_at"`
	CreatedBy   string                `json:"created_by,omitempty"`
	Metadata    map[string]string     `json:"metadata,omitempty"`
}

type channelRecord struct {
	TenantID   string    `json:"tenant_id"`
	Name       string    `json:"channel"`
	ArtifactID string    `json:"artifact_id"`
	CreatedAt  time.Time `json:"created_at"`
	UpdatedAt  time.Time `json:"updated_at"`
	CreatedBy  string    `json:"created_by,omitempty"`
}

func encodeArtifact(value domainartifact.Artifact) ([]byte, error) {
	record := artifactRecord{ID: value.ID, TenantID: value.TenantID.String(), Name: value.Name,
		Kind: value.Kind, Version: value.Version, OS: value.OS, Arch: value.Arch, SHA256: value.SHA256,
		SizeBytes: value.SizeBytes, Status: value.Status, StoragePath: value.StoragePath,
		CreatedAt: value.CreatedAt, UpdatedAt: value.UpdatedAt, CreatedBy: value.CreatedBy, Metadata: value.Metadata}
	return json.Marshal(record)
}

func decodeArtifact(raw []byte) (domainartifact.Artifact, error) {
	var record artifactRecord
	if err := json.Unmarshal(raw, &record); err != nil {
		return domainartifact.Artifact{}, fmt.Errorf("decode artifact record: %w", err)
	}
	tenantID, err := tenant.NewID(record.TenantID)
	if err != nil {
		return domainartifact.Artifact{}, err
	}
	value, err := domainartifact.New(domainartifact.Artifact{ID: record.ID, TenantID: tenantID,
		Name: record.Name, Kind: record.Kind, Version: record.Version, OS: record.OS, Arch: record.Arch,
		SHA256: record.SHA256, SizeBytes: record.SizeBytes, Status: record.Status, StoragePath: record.StoragePath,
		CreatedBy: record.CreatedBy, Metadata: record.Metadata}, record.CreatedAt)
	if err != nil {
		return domainartifact.Artifact{}, err
	}
	value.UpdatedAt = record.UpdatedAt.UTC()
	return value, nil
}

func encodeChannel(value domainartifact.Channel) ([]byte, error) {
	record := channelRecord{TenantID: value.TenantID.String(), Name: value.Name, ArtifactID: value.ArtifactID,
		CreatedAt: value.CreatedAt, UpdatedAt: value.UpdatedAt, CreatedBy: value.CreatedBy}
	return json.Marshal(record)
}

func decodeChannel(raw []byte) (domainartifact.Channel, error) {
	var record channelRecord
	if err := json.Unmarshal(raw, &record); err != nil {
		return domainartifact.Channel{}, fmt.Errorf("decode artifact channel record: %w", err)
	}
	tenantID, err := tenant.NewID(record.TenantID)
	if err != nil {
		return domainartifact.Channel{}, err
	}
	if strings.TrimSpace(record.Name) == "" || strings.TrimSpace(record.ArtifactID) == "" {
		return domainartifact.Channel{}, failure.New(failure.InvalidArgument, "artifact channel record is invalid")
	}
	return domainartifact.Channel{TenantID: tenantID, Name: record.Name, ArtifactID: record.ArtifactID,
		CreatedAt: record.CreatedAt, UpdatedAt: record.UpdatedAt, CreatedBy: record.CreatedBy}, nil
}
