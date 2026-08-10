package artifact

import "time"

type artifactDTO struct {
	ID          string            `json:"artifact_id"`
	TenantID    string            `json:"tenant_id"`
	Name        string            `json:"name"`
	Kind        string            `json:"kind"`
	Version     string            `json:"version"`
	OS          string            `json:"os,omitempty"`
	Arch        string            `json:"arch,omitempty"`
	SHA256      string            `json:"sha256"`
	SizeBytes   int64             `json:"size_bytes"`
	Status      string            `json:"status"`
	StoragePath string            `json:"storage_path,omitempty"`
	CreatedAt   time.Time         `json:"created_at"`
	UpdatedAt   time.Time         `json:"updated_at"`
	CreatedBy   string            `json:"created_by,omitempty"`
	Metadata    map[string]string `json:"metadata,omitempty"`
}

type channelDTO struct {
	TenantID   string    `json:"tenant_id"`
	Name       string    `json:"channel"`
	ArtifactID string    `json:"artifact_id"`
	CreatedAt  time.Time `json:"created_at"`
	UpdatedAt  time.Time `json:"updated_at"`
	CreatedBy  string    `json:"created_by,omitempty"`
}

type channelRequest struct {
	TenantID   string `json:"tenant_id,omitempty"`
	Name       string `json:"channel"`
	ArtifactID string `json:"artifact_id"`
	Actor      string `json:"actor,omitempty"`
}
