package artifact

import (
	"context"
	"database/sql"
	"fmt"
	"strings"

	domainartifact "github.com/sysarmor/sysarmor-next-project/apps/manager/internal/domain/artifact"
	"github.com/sysarmor/sysarmor-next-project/apps/manager/internal/domain/failure"
	"github.com/sysarmor/sysarmor-next-project/apps/manager/internal/domain/tenant"
	"github.com/sysarmor/sysarmor-next-project/apps/manager/internal/ports"
)

type artifactRepository struct{ executor sqlExecutor }

func (repository artifactRepository) Get(ctx context.Context, tenantID tenant.ID, id string) (domainartifact.Artifact, error) {
	if tenantID.IsZero() || strings.TrimSpace(id) == "" {
		return domainartifact.Artifact{}, failure.New(failure.InvalidArgument, "artifact identity is required")
	}
	var raw []byte
	err := repository.executor.QueryRowContext(ctx,
		`SELECT data FROM artifacts WHERE tenant_id=$1 AND artifact_id=$2`, tenantID.String(), id).Scan(&raw)
	if err == sql.ErrNoRows {
		return domainartifact.Artifact{}, failure.New(failure.NotFound, "artifact not found")
	}
	if err != nil {
		return domainartifact.Artifact{}, fmt.Errorf("get artifact: %w", err)
	}
	return decodeArtifact(raw)
}

func (repository artifactRepository) List(ctx context.Context, tenantID tenant.ID, filter ports.ArtifactFilter) ([]domainartifact.Artifact, error) {
	if tenantID.IsZero() {
		return nil, failure.New(failure.InvalidArgument, "tenant is required")
	}
	rows, err := repository.executor.QueryContext(ctx, `SELECT data FROM artifacts
WHERE tenant_id=$1 AND ($2='' OR artifact_kind=$2) AND ($3='' OR status=$3)
ORDER BY created_at,artifact_id`, tenantID.String(), filter.Kind, string(filter.Status))
	if err != nil {
		return nil, fmt.Errorf("list artifacts: %w", err)
	}
	defer rows.Close()
	values := []domainartifact.Artifact{}
	for rows.Next() {
		var raw []byte
		if err := rows.Scan(&raw); err != nil {
			return nil, fmt.Errorf("scan artifact: %w", err)
		}
		value, err := decodeArtifact(raw)
		if err != nil {
			return nil, err
		}
		values = append(values, value)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate artifacts: %w", err)
	}
	return values, nil
}

func (repository artifactRepository) Put(ctx context.Context, value domainartifact.Artifact) (domainartifact.Artifact, error) {
	if value.TenantID.IsZero() {
		return domainartifact.Artifact{}, failure.New(failure.InvalidArgument, "tenant is required")
	}
	raw, err := encodeArtifact(value)
	if err != nil {
		return domainartifact.Artifact{}, fmt.Errorf("encode artifact: %w", err)
	}
	_, err = repository.executor.ExecContext(ctx, `INSERT INTO artifacts
(tenant_id,artifact_id,artifact_name,artifact_kind,artifact_version,artifact_os,artifact_arch,sha256,size_bytes,status,storage_path,created_at,updated_at,data)
VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14)
ON CONFLICT (tenant_id,artifact_id) DO UPDATE SET artifact_name=excluded.artifact_name,
artifact_kind=excluded.artifact_kind,artifact_version=excluded.artifact_version,artifact_os=excluded.artifact_os,
artifact_arch=excluded.artifact_arch,sha256=excluded.sha256,size_bytes=excluded.size_bytes,status=excluded.status,
storage_path=excluded.storage_path,updated_at=excluded.updated_at,data=excluded.data`, value.TenantID.String(), value.ID,
		value.Name, value.Kind, value.Version, value.OS, value.Arch, value.SHA256, value.SizeBytes, string(value.Status),
		value.StoragePath, value.CreatedAt, value.UpdatedAt, raw)
	if err != nil {
		return domainartifact.Artifact{}, fmt.Errorf("put artifact: %w", err)
	}
	return value, nil
}

type channelRepository struct{ executor sqlExecutor }

func (repository channelRepository) Get(ctx context.Context, tenantID tenant.ID, name string) (domainartifact.Channel, error) {
	if tenantID.IsZero() || strings.TrimSpace(name) == "" {
		return domainartifact.Channel{}, failure.New(failure.InvalidArgument, "artifact channel identity is required")
	}
	var raw []byte
	err := repository.executor.QueryRowContext(ctx,
		`SELECT data FROM artifact_channels WHERE tenant_id=$1 AND channel_name=$2`, tenantID.String(), name).Scan(&raw)
	if err == sql.ErrNoRows {
		return domainartifact.Channel{}, failure.New(failure.NotFound, "artifact channel not found")
	}
	if err != nil {
		return domainartifact.Channel{}, fmt.Errorf("get artifact channel: %w", err)
	}
	return decodeChannel(raw)
}

func (repository channelRepository) List(ctx context.Context, tenantID tenant.ID) ([]domainartifact.Channel, error) {
	if tenantID.IsZero() {
		return nil, failure.New(failure.InvalidArgument, "tenant is required")
	}
	rows, err := repository.executor.QueryContext(ctx,
		`SELECT data FROM artifact_channels WHERE tenant_id=$1 ORDER BY channel_name`, tenantID.String())
	if err != nil {
		return nil, fmt.Errorf("list artifact channels: %w", err)
	}
	defer rows.Close()
	values := []domainartifact.Channel{}
	for rows.Next() {
		var raw []byte
		if err := rows.Scan(&raw); err != nil {
			return nil, fmt.Errorf("scan artifact channel: %w", err)
		}
		value, err := decodeChannel(raw)
		if err != nil {
			return nil, err
		}
		values = append(values, value)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate artifact channels: %w", err)
	}
	return values, nil
}

func (repository channelRepository) Put(ctx context.Context, value domainartifact.Channel) (domainartifact.Channel, error) {
	if value.TenantID.IsZero() {
		return domainartifact.Channel{}, failure.New(failure.InvalidArgument, "tenant is required")
	}
	current, err := repository.Get(ctx, value.TenantID, value.Name)
	if err == nil {
		value.CreatedAt = current.CreatedAt
	} else if failure.KindOf(err) != failure.NotFound {
		return domainartifact.Channel{}, err
	}
	raw, err := encodeChannel(value)
	if err != nil {
		return domainartifact.Channel{}, fmt.Errorf("encode artifact channel: %w", err)
	}
	_, err = repository.executor.ExecContext(ctx, `INSERT INTO artifact_channels
(tenant_id,channel_name,artifact_id,created_at,updated_at,data) VALUES ($1,$2,$3,$4,$5,$6)
ON CONFLICT (tenant_id,channel_name) DO UPDATE SET artifact_id=excluded.artifact_id,
updated_at=excluded.updated_at,data=excluded.data`, value.TenantID.String(), value.Name, value.ArtifactID,
		value.CreatedAt, value.UpdatedAt, raw)
	if err != nil {
		return domainartifact.Channel{}, fmt.Errorf("put artifact channel: %w", err)
	}
	return value, nil
}
