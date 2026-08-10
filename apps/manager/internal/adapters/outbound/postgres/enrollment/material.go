package enrollment

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	domainenrollment "github.com/sysarmor/sysarmor-next-project/apps/manager/internal/domain/enrollment"
	"github.com/sysarmor/sysarmor-next-project/apps/manager/internal/domain/failure"
	"github.com/sysarmor/sysarmor-next-project/apps/manager/internal/domain/tenant"
)

type installMaterialRepository struct{ executor sqlExecutor }

func (repository installMaterialRepository) ListArtifacts(ctx context.Context, tenantID tenant.ID) ([]domainenrollment.DeploymentArtifact, error) {
	if tenantID.IsZero() {
		return nil, failure.New(failure.InvalidArgument, "tenant is required")
	}
	rows, err := repository.executor.QueryContext(ctx, `SELECT data FROM artifacts
WHERE tenant_id=$1 AND artifact_kind='agent' ORDER BY created_at,artifact_id`, tenantID.String())
	if err != nil {
		return nil, fmt.Errorf("list deployment artifacts: %w", err)
	}
	defer rows.Close()
	artifacts := []domainenrollment.DeploymentArtifact{}
	for rows.Next() {
		var raw []byte
		if err := rows.Scan(&raw); err != nil {
			return nil, fmt.Errorf("scan deployment artifact: %w", err)
		}
		artifact, err := decodeDeploymentArtifact(raw)
		if err != nil {
			return nil, err
		}
		artifacts = append(artifacts, artifact)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate deployment artifacts: %w", err)
	}
	return artifacts, nil
}

func (repository installMaterialRepository) Resolve(ctx context.Context, tenantID tenant.ID, channel, artifactID string) (domainenrollment.InstallMaterial, error) {
	if tenantID.IsZero() {
		return domainenrollment.InstallMaterial{}, failure.New(failure.InvalidArgument, "tenant is required")
	}
	channel, artifactID = strings.TrimSpace(channel), strings.TrimSpace(artifactID)
	if channel != "" {
		resolved, err := repository.artifactForChannel(ctx, tenantID, channel)
		if err != nil {
			return domainenrollment.InstallMaterial{}, err
		}
		artifactID = resolved
	}
	var sha256, status string
	var raw []byte
	err := repository.executor.QueryRowContext(ctx,
		`SELECT sha256,status,data FROM artifacts WHERE tenant_id=$1 AND artifact_id=$2`, tenantID.String(), artifactID).
		Scan(&sha256, &status, &raw)
	if err == sql.ErrNoRows {
		return domainenrollment.InstallMaterial{}, failure.New(failure.InvalidArgument, "active artifact not found")
	}
	if err != nil {
		return domainenrollment.InstallMaterial{}, fmt.Errorf("query install artifact: %w", err)
	}
	if status != "active" {
		return domainenrollment.InstallMaterial{}, failure.New(failure.InvalidArgument, "active artifact not found")
	}
	downloadURL, err := artifactDownloadURL(raw)
	if err != nil {
		return domainenrollment.InstallMaterial{}, err
	}
	return domainenrollment.InstallMaterial{Channel: channel, ArtifactID: artifactID,
		ArtifactSHA256: sha256, ArtifactURL: downloadURL}, nil
}

func (repository installMaterialRepository) GetArtifact(ctx context.Context, tenantID tenant.ID, artifactID string) (domainenrollment.InstallArtifact, error) {
	if tenantID.IsZero() || strings.TrimSpace(artifactID) == "" {
		return domainenrollment.InstallArtifact{}, failure.New(failure.NotFound, "install artifact not found")
	}
	var sha256, status, storagePath string
	var raw []byte
	err := repository.executor.QueryRowContext(ctx, `SELECT sha256,status,storage_path,data
FROM artifacts WHERE tenant_id=$1 AND artifact_id=$2`, tenantID.String(), artifactID).
		Scan(&sha256, &status, &storagePath, &raw)
	if err == sql.ErrNoRows {
		return domainenrollment.InstallArtifact{}, failure.New(failure.NotFound, "install artifact not found")
	}
	if err != nil {
		return domainenrollment.InstallArtifact{}, fmt.Errorf("query install artifact: %w", err)
	}
	if status != "active" {
		return domainenrollment.InstallArtifact{}, failure.New(failure.NotFound, "install artifact not found")
	}
	downloadURL, err := artifactDownloadURL(raw)
	if err != nil {
		return domainenrollment.InstallArtifact{}, err
	}
	return domainenrollment.InstallArtifact{ID: artifactID, SHA256: sha256, Status: status,
		StoragePath: storagePath, DownloadURL: downloadURL}, nil
}

func artifactDownloadURL(raw []byte) (string, error) {
	var document struct {
		Metadata map[string]string `json:"metadata"`
	}
	if err := json.Unmarshal(raw, &document); err != nil {
		return "", fmt.Errorf("decode install artifact: %w", err)
	}
	return strings.TrimSpace(document.Metadata["download_url"]), nil
}

func decodeDeploymentArtifact(raw []byte) (domainenrollment.DeploymentArtifact, error) {
	var document struct {
		ID        string            `json:"artifact_id"`
		Version   string            `json:"version"`
		OS        string            `json:"os"`
		Arch      string            `json:"arch"`
		SHA256    string            `json:"sha256"`
		Status    string            `json:"status"`
		CreatedAt time.Time         `json:"created_at"`
		Metadata  map[string]string `json:"metadata"`
	}
	if err := json.Unmarshal(raw, &document); err != nil {
		return domainenrollment.DeploymentArtifact{}, fmt.Errorf("decode deployment artifact: %w", err)
	}
	return domainenrollment.DeploymentArtifact{ID: document.ID, Version: document.Version, OS: document.OS,
		Arch: document.Arch, SHA256: document.SHA256, Status: document.Status,
		DownloadURL: strings.TrimSpace(document.Metadata["download_url"]), CreatedAt: document.CreatedAt}, nil
}

func (repository installMaterialRepository) artifactForChannel(ctx context.Context, tenantID tenant.ID, channel string) (string, error) {
	var artifactID string
	err := repository.executor.QueryRowContext(ctx,
		`SELECT artifact_id FROM artifact_channels WHERE tenant_id=$1 AND channel_name=$2`, tenantID.String(), channel).
		Scan(&artifactID)
	if err == sql.ErrNoRows {
		return "", domainenrollment.ErrChannelNotFound
	}
	if err != nil {
		return "", fmt.Errorf("query artifact channel: %w", err)
	}
	return artifactID, nil
}
