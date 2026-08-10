package enrollment

import (
	"context"
	"testing"
	"time"

	domainenrollment "github.com/sysarmor/sysarmor-next-project/apps/manager/internal/domain/enrollment"
	"github.com/sysarmor/sysarmor-next-project/apps/manager/internal/domain/tenant"
	"github.com/sysarmor/sysarmor-next-project/apps/manager/internal/ports"
)

func TestDeploymentOptionsUsesActorTenantForArtifactsAndEnrollments(t *testing.T) {
	tenantID, _ := tenant.NewID("tenant-a")
	enrollments := &enrollmentRepositoryStub{listed: []domainenrollment.Enrollment{{ID: "enroll-a", TenantID: tenantID}}}
	materials := &installMaterialRepositoryStub{artifacts: []domainenrollment.DeploymentArtifact{{ID: "artifact-a"}}}
	service := NewQueryService(&enrollmentUnitOfWorkStub{tx: enrollmentTransactionStub{
		enrollments: enrollments, unenrollments: &unenrollmentRepositoryStub{}, materials: materials,
	}})

	result, err := service.DeploymentOptions(context.Background(), viewerRequest(t, "tenant-a"))
	if err != nil {
		t.Fatal(err)
	}
	if enrollments.listTenant != tenantID || materials.listTenant != tenantID ||
		len(result.Enrollments) != 1 || len(result.Artifacts) != 1 {
		t.Fatalf("result=%#v enrollment tenant=%q artifact tenant=%q", result, enrollments.listTenant, materials.listTenant)
	}
}

func TestCreateEnrollmentFallsBackToArtifactForDeployment(t *testing.T) {
	repository := &enrollmentRepositoryStub{}
	materials := &installMaterialRepositoryStub{
		resolveErrors: []error{domainenrollment.ErrChannelNotFound, nil},
		value:         domainenrollment.InstallMaterial{ArtifactID: "artifact-a", ArtifactSHA256: "sha256-a"},
	}
	service := NewCreateService(
		&enrollmentUnitOfWorkStub{tx: enrollmentTransactionStub{enrollments: repository, materials: materials}},
		&tokenGeneratorStub{values: []ports.EnrollmentToken{
			{Plaintext: "enrollment-token", Hash: "enrollment-hash", Preview: "enr_...oken"},
			{Plaintext: "bootstrap-token", Hash: "bootstrap-hash", Preview: "enr_...boot"},
		}}, clockStub{now: time.Unix(100, 0).UTC()}, idGeneratorStub{value: "enroll-a"},
	)

	_, err := service.Execute(context.Background(), operatorRequest(t, "tenant-a"), CreateEnrollmentCommand{
		TenantID: "tenant-a", AgentID: "agent-a", GatewayAddress: "gateway:9444", TTL: time.Hour,
		Channel: "linux-systemd-missing", ArtifactID: "artifact-a", FallbackToArtifact: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(materials.resolveCalls) != 2 || materials.resolveCalls[1] != [2]string{"", "artifact-a"} {
		t.Fatalf("material calls = %#v", materials.resolveCalls)
	}
	if repository.putValue.Channel != "" || repository.putValue.ArtifactID != "artifact-a" {
		t.Fatalf("enrollment = %#v", repository.putValue)
	}
}
