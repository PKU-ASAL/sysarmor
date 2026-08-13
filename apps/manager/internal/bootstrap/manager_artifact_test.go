package bootstrap

import (
	"database/sql"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	managerapp "github.com/sysarmor/sysarmor-next-project/apps/manager/internal/application/manager"
	"github.com/sysarmor/sysarmor-next-project/apps/manager/internal/domain/tenant"
	_ "modernc.org/sqlite"
)

func TestNewManagerArtifactRejectsIncompleteConfig(t *testing.T) {
	if _, err := NewManagerArtifact(ArtifactConfig{}); err == nil || !strings.Contains(err.Error(), "database") {
		t.Fatalf("empty config error=%v", err)
	}
	if _, err := NewManagerArtifact(ArtifactConfig{DB: &sql.DB{}}); err == nil || !strings.Contains(err.Error(), "resolver") {
		t.Fatalf("resolver error=%v", err)
	}
}

func TestNewManagerArtifactWiresPostgresRoutes(t *testing.T) {
	db, err := sql.Open("sqlite", "file:"+t.Name()+"?mode=memory&cache=shared")
	if err != nil {
		t.Fatal(err)
	}
	db.SetMaxOpenConns(1)
	t.Cleanup(func() { _ = db.Close() })
	for _, statement := range []string{
		`CREATE TABLE artifacts (tenant_id TEXT, artifact_id TEXT, artifact_name TEXT, artifact_kind TEXT, artifact_version TEXT, artifact_os TEXT, artifact_arch TEXT, sha256 TEXT, size_bytes INTEGER, status TEXT, storage_path TEXT, created_at TIMESTAMP, updated_at TIMESTAMP, data BLOB, PRIMARY KEY (tenant_id,artifact_id))`,
		`CREATE TABLE artifact_channels (tenant_id TEXT, channel_name TEXT, artifact_id TEXT, created_at TIMESTAMP, updated_at TIMESTAMP, data BLOB, PRIMARY KEY (tenant_id,channel_name))`,
	} {
		if _, err := db.Exec(statement); err != nil {
			t.Fatal(err)
		}
	}
	_, publicKeyFile := writeEnrollmentTestCA(t)
	tenantID, _ := tenant.NewID("tenant-a")
	slice, err := NewManagerArtifact(ArtifactConfig{DB: db, ArtifactDir: t.TempDir(),
		ArtifactPublicKeyFile: publicKeyFile, Resolve: func(*http.Request) (managerapp.RequestContext, error) {
			return managerapp.RequestContext{Actor: tenant.Actor{Subject: "viewer-a", TenantID: tenantID,
				Roles: tenant.NewRoleSet(tenant.RoleViewer)}}, nil
		}})
	if err != nil {
		t.Fatal(err)
	}
	recorder := httptest.NewRecorder()
	slice.Routes.Artifacts(recorder, httptest.NewRequest(http.MethodGet, "/api/v1/artifacts", nil))
	if recorder.Code != http.StatusOK || recorder.Body.String() != "{\"artifacts\":[]}\n" || slice.Feed == nil {
		t.Fatalf("status=%d body=%s feed=%v", recorder.Code, recorder.Body.String(), slice.Feed)
	}
}
