package artifact

import (
	"context"
	"database/sql"
	"errors"
	"testing"
	"time"

	domainartifact "github.com/sysarmor/sysarmor-next-project/apps/manager/internal/domain/artifact"
	"github.com/sysarmor/sysarmor-next-project/apps/manager/internal/domain/failure"
	"github.com/sysarmor/sysarmor-next-project/apps/manager/internal/domain/tenant"
	"github.com/sysarmor/sysarmor-next-project/apps/manager/internal/ports"
	_ "modernc.org/sqlite"
)

func TestArtifactRepositoryRoundTripsArtifactAndChannel(t *testing.T) {
	db := newArtifactTestDB(t)
	uow := NewUnitOfWork(db)
	value := adapterArtifact(t)
	channel, err := domainartifact.NewChannel(domainartifact.Channel{
		TenantID: value.TenantID, Name: "stable",
	}, value, "operator-a", time.Unix(200, 0).UTC())
	if err != nil {
		t.Fatal(err)
	}
	if err := uow.Execute(context.Background(), func(ctx context.Context, tx ports.ArtifactTransaction) error {
		if _, err := tx.Artifacts().Put(ctx, value); err != nil {
			return err
		}
		_, err := tx.Channels().Put(ctx, channel)
		return err
	}); err != nil {
		t.Fatal(err)
	}
	if err := uow.Execute(context.Background(), func(ctx context.Context, tx ports.ArtifactTransaction) error {
		got, err := tx.Artifacts().Get(ctx, value.TenantID, value.ID)
		if err != nil {
			return err
		}
		gotChannel, err := tx.Channels().Get(ctx, value.TenantID, "stable")
		if err != nil {
			return err
		}
		if got.SHA256 != "sha256-a" || got.Metadata["source"] != "upload" || gotChannel.ArtifactID != value.ID {
			t.Fatalf("artifact=%+v channel=%+v", got, gotChannel)
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
}

func TestArtifactUnitOfWorkRollsBackMetadata(t *testing.T) {
	db := newArtifactTestDB(t)
	uow := NewUnitOfWork(db)
	wantErr := errors.New("stop transaction")
	err := uow.Execute(context.Background(), func(ctx context.Context, tx ports.ArtifactTransaction) error {
		if _, err := tx.Artifacts().Put(ctx, adapterArtifact(t)); err != nil {
			return err
		}
		return wantErr
	})
	if !errors.Is(err, wantErr) {
		t.Fatalf("error=%v", err)
	}
	var count int
	if err := db.QueryRow(`SELECT COUNT(*) FROM artifacts`).Scan(&count); err != nil || count != 0 {
		t.Fatalf("count=%d error=%v", count, err)
	}
}

func TestArtifactRepositoryRequiresTenant(t *testing.T) {
	uow := NewUnitOfWork(newArtifactTestDB(t))
	err := uow.Execute(context.Background(), func(ctx context.Context, tx ports.ArtifactTransaction) error {
		_, err := tx.Artifacts().Get(ctx, tenant.ID(""), "agent-a")
		return err
	})
	if failure.KindOf(err) != failure.InvalidArgument {
		t.Fatalf("kind=%v error=%v", failure.KindOf(err), err)
	}
}

func TestChannelUpdatePreservesCreatedAt(t *testing.T) {
	uow := NewUnitOfWork(newArtifactTestDB(t))
	value := adapterArtifact(t)
	first, err := domainartifact.NewChannel(domainartifact.Channel{
		TenantID: value.TenantID, Name: "stable",
	}, value, "operator-a", time.Unix(200, 0).UTC())
	if err != nil {
		t.Fatal(err)
	}
	second := first
	second.ArtifactID = "agent-b"
	second.CreatedAt = time.Unix(300, 0).UTC()
	second.UpdatedAt = time.Unix(300, 0).UTC()
	if err := uow.Execute(context.Background(), func(ctx context.Context, tx ports.ArtifactTransaction) error {
		if _, err := tx.Channels().Put(ctx, first); err != nil {
			return err
		}
		_, err := tx.Channels().Put(ctx, second)
		return err
	}); err != nil {
		t.Fatal(err)
	}
	if err := uow.Execute(context.Background(), func(ctx context.Context, tx ports.ArtifactTransaction) error {
		got, err := tx.Channels().Get(ctx, value.TenantID, first.Name)
		if err != nil {
			return err
		}
		if !got.CreatedAt.Equal(first.CreatedAt) || got.ArtifactID != second.ArtifactID {
			t.Fatalf("channel=%+v", got)
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
}

func newArtifactTestDB(t *testing.T) *sql.DB {
	t.Helper()
	db, err := sql.Open("sqlite", "file:"+t.Name()+"?mode=memory&cache=shared")
	if err != nil {
		t.Fatal(err)
	}
	db.SetMaxOpenConns(1)
	t.Cleanup(func() { _ = db.Close() })
	statements := []string{
		`CREATE TABLE artifacts (tenant_id TEXT, artifact_id TEXT, artifact_name TEXT, artifact_kind TEXT, artifact_version TEXT, artifact_os TEXT, artifact_arch TEXT, sha256 TEXT, size_bytes INTEGER, status TEXT, storage_path TEXT, created_at TIMESTAMP, updated_at TIMESTAMP, data BLOB, PRIMARY KEY (tenant_id,artifact_id))`,
		`CREATE TABLE artifact_channels (tenant_id TEXT, channel_name TEXT, artifact_id TEXT, created_at TIMESTAMP, updated_at TIMESTAMP, data BLOB, PRIMARY KEY (tenant_id,channel_name))`,
	}
	for _, statement := range statements {
		if _, err := db.Exec(statement); err != nil {
			t.Fatal(err)
		}
	}
	return db
}

func adapterArtifact(t *testing.T) domainartifact.Artifact {
	t.Helper()
	value, err := domainartifact.New(domainartifact.Artifact{
		ID: "agent-a", TenantID: "tenant-a", Name: "sysarmor-agent", Kind: "agent", Version: "1.0.0",
		SHA256: "sha256-a", Status: domainartifact.StatusActive, Metadata: map[string]string{"source": "upload"},
	}, time.Unix(100, 0).UTC())
	if err != nil {
		t.Fatal(err)
	}
	return value
}
