package enrollment

import (
	"context"
	"errors"
	"testing"
	"time"

	managerapp "github.com/sysarmor/sysarmor-next-project/apps/manager/internal/application/manager"
	domainenrollment "github.com/sysarmor/sysarmor-next-project/apps/manager/internal/domain/enrollment"
	"github.com/sysarmor/sysarmor-next-project/apps/manager/internal/domain/failure"
	"github.com/sysarmor/sysarmor-next-project/apps/manager/internal/domain/tenant"
	"github.com/sysarmor/sysarmor-next-project/apps/manager/internal/ports"
)

func TestIssueCertificateReturnsNoResultWhenCommitFails(t *testing.T) {
	wantErr := errors.New("commit failed")
	repository := &enrollmentRepositoryStub{current: activeEnrollment(t)}
	certificates := &certificateRepositoryStub{}
	service := NewIssueService(
		&enrollmentUnitOfWorkStub{tx: enrollmentTransactionStub{enrollments: repository, certificates: certificates}, commitErr: wantErr},
		certificateIssuerStub{issuance: issuance(t)},
		clockStub{now: time.Unix(200, 0).UTC()},
	)

	result, err := service.Execute(context.Background(), IssueCertificateCommand{
		TokenHash: "token-hash",
		CSR:       []byte("csr"),
	})
	if !errors.Is(err, wantErr) {
		t.Fatalf("issue error = %v", err)
	}
	if result.Enrollment.ID != "" || result.Certificate.SerialNumber != "" {
		t.Fatalf("result escaped failed transaction = %#v", result)
	}
	if repository.puts != 1 || certificates.puts != 1 {
		t.Fatalf("writes enrollment=%d certificate=%d", repository.puts, certificates.puts)
	}
}

func TestCompleteUnenrollmentReturnsNoResultWhenCommitFails(t *testing.T) {
	wantErr := errors.New("commit failed")
	record := pendingUnenrollment(t)
	repository := &unenrollmentRepositoryStub{current: record}
	uow := &enrollmentUnitOfWorkStub{
		tx: enrollmentTransactionStub{unenrollments: repository}, commitErr: wantErr,
	}
	service := NewCompletionService(uow, clockStub{now: time.Unix(300, 0).UTC()})

	result, err := service.Execute(context.Background(), CompleteUnenrollmentCommand{
		Identity: record.Identity, Receipt: record.Receipt, TokenHash: record.CompletionTokenHash,
	})
	if !errors.Is(err, wantErr) {
		t.Fatalf("completion error = %v", err)
	}
	if result != (CompleteUnenrollmentResult{}) {
		t.Fatalf("result escaped failed transaction = %#v", result)
	}
	if repository.puts != 1 {
		t.Fatalf("unenrollment writes = %d", repository.puts)
	}
}

func TestCreateEnrollmentReturnsNoTokensWhenCommitFails(t *testing.T) {
	wantErr := errors.New("commit failed")
	repository := &enrollmentRepositoryStub{}
	service := NewCreateService(
		&enrollmentUnitOfWorkStub{tx: enrollmentTransactionStub{enrollments: repository}, commitErr: wantErr},
		&tokenGeneratorStub{values: []ports.EnrollmentToken{
			{Plaintext: "enrollment-token", Hash: "enrollment-hash", Preview: "enroll...token"},
			{Plaintext: "bootstrap-token", Hash: "bootstrap-hash", Preview: "boot...token"},
		}},
		clockStub{now: time.Unix(100, 0).UTC()}, idGeneratorStub{value: "enroll-a"},
	)

	result, err := service.Execute(context.Background(), operatorRequest(t, "tenant-a"), CreateEnrollmentCommand{
		TenantID: "tenant-a", AgentID: "agent-a", GatewayAddress: "gateway:9444", TTL: time.Hour,
	})
	if !errors.Is(err, wantErr) {
		t.Fatalf("create error = %v", err)
	}
	if result.Enrollment.ID != "" || result.Token != "" || result.BootstrapTicket != "" {
		t.Fatalf("tokens escaped failed transaction = %#v", result)
	}
	if repository.puts != 1 {
		t.Fatalf("enrollment writes = %d", repository.puts)
	}
}

func TestCreateEnrollmentRequiresOperator(t *testing.T) {
	service := NewCreateService(nil, nil, nil, nil)

	_, err := service.Execute(context.Background(), managerapp.RequestContext{
		Actor: tenant.Actor{TenantID: mustApplicationTenant(t), Roles: tenant.NewRoleSet(tenant.RoleViewer)},
	}, CreateEnrollmentCommand{
		TenantID: "tenant-a", AgentID: "agent-a", GatewayAddress: "gateway:9444", TTL: time.Hour,
	})
	if failure.KindOf(err) != failure.PermissionDenied {
		t.Fatalf("create failure kind = %v", failure.KindOf(err))
	}
}

func TestCreateEnrollmentRejectsCrossTenantCommand(t *testing.T) {
	service := NewCreateService(nil, nil, nil, nil)

	_, err := service.Execute(context.Background(), operatorRequest(t, "tenant-a"), CreateEnrollmentCommand{
		TenantID: "tenant-b", AgentID: "agent-a", GatewayAddress: "gateway:9444", TTL: time.Hour,
	})
	if failure.KindOf(err) != failure.PermissionDenied {
		t.Fatalf("create failure kind = %v", failure.KindOf(err))
	}
}

func TestCreateEnrollmentRejectsUnsafeIdentityComponents(t *testing.T) {
	tests := []struct {
		name, tenantID, agentID string
	}{
		{name: "tenant path", tenantID: "tenant/a", agentID: "agent-a"},
		{name: "agent path", tenantID: "tenant-a", agentID: "../victim/agent/admin"},
		{name: "agent URI query", tenantID: "tenant-a", agentID: "agent?admin=true"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			service := NewCreateService(nil, nil, nil, nil)
			_, err := service.Execute(context.Background(), operatorRequest(t, tt.tenantID), CreateEnrollmentCommand{
				TenantID: tt.tenantID, AgentID: tt.agentID, GatewayAddress: "gateway:9444", TTL: time.Hour,
			})
			if failure.KindOf(err) != failure.InvalidArgument {
				t.Fatalf("create failure kind = %v error=%v", failure.KindOf(err), err)
			}
		})
	}
}

func TestCreateEnrollmentRejectsInvalidGateway(t *testing.T) {
	tests := []struct{ address, serverName string }{
		{address: ":"},
		{address: "gateway:not-a-port"},
		{address: "gateway:70000"},
		{address: "gateway:9444", serverName: "gateway:9444"},
		{address: "gateway:9444", serverName: "gateway/path"},
	}
	for _, tt := range tests {
		service := NewCreateService(nil, nil, nil, nil)
		_, err := service.Execute(context.Background(), operatorRequest(t, "tenant-a"), CreateEnrollmentCommand{
			TenantID: "tenant-a", AgentID: "agent-a", GatewayAddress: tt.address,
			GatewayServerName: tt.serverName, TTL: time.Hour,
		})
		if failure.KindOf(err) != failure.InvalidArgument {
			t.Fatalf("gateway=%q sni=%q kind=%v error=%v", tt.address, tt.serverName, failure.KindOf(err), err)
		}
	}
}

func TestListEnrollmentsUsesActorTenantAndProjectsUnenrollment(t *testing.T) {
	value := activeEnrollment(t)
	record := pendingUnenrollment(t)
	enrollments := &enrollmentRepositoryStub{listed: []domainenrollment.Enrollment{value}}
	unenrollments := &unenrollmentRepositoryStub{listed: []domainenrollment.Unenrollment{record}}
	service := NewQueryService(&enrollmentUnitOfWorkStub{tx: enrollmentTransactionStub{
		enrollments: enrollments, unenrollments: unenrollments,
	}})

	result, err := service.List(context.Background(), operatorRequest(t, "tenant-a"), ListEnrollmentsQuery{
		Status: domainenrollment.StatusIssued,
	})
	if err != nil {
		t.Fatal(err)
	}
	if enrollments.listTenant != value.TenantID || unenrollments.listTenant != value.TenantID {
		t.Fatalf("list tenants enrollment=%q unenrollment=%q", enrollments.listTenant, unenrollments.listTenant)
	}
	if enrollments.listStatus != domainenrollment.StatusIssued {
		t.Fatalf("list status = %q", enrollments.listStatus)
	}
	if len(result.Enrollments) != 1 || !result.Enrollments[0].HasUnenrollment ||
		result.Enrollments[0].Unenrollment.Status != domainenrollment.UnenrollmentPending {
		t.Fatalf("result = %#v", result)
	}
}

func TestRedeemBootstrapReturnsNoTokenWhenCommitFails(t *testing.T) {
	wantErr := errors.New("commit failed")
	current := activeEnrollment(t)
	current.BootstrapTokenHash = "bootstrap-hash"
	repository := &enrollmentRepositoryStub{bootstrapCurrent: current}
	service := NewBootstrapService(
		&enrollmentUnitOfWorkStub{tx: enrollmentTransactionStub{enrollments: repository}, commitErr: wantErr},
		&tokenGeneratorStub{values: []ports.EnrollmentToken{{
			Plaintext: "rotated-token", Hash: "rotated-hash", Preview: "enr_...ated",
		}}},
		clockStub{now: time.Unix(100, 0).UTC()},
	)

	result, err := service.Redeem(context.Background(), RedeemBootstrapCommand{TicketHash: "bootstrap-hash"})
	if !errors.Is(err, wantErr) {
		t.Fatalf("redeem error = %v", err)
	}
	if result.Token != "" || result.Enrollment.ID != "" {
		t.Fatalf("token escaped failed transaction = %#v", result)
	}
	if repository.puts != 1 {
		t.Fatalf("enrollment writes = %d", repository.puts)
	}
}

func TestCreateEnrollmentResolvesChannelInsideTransaction(t *testing.T) {
	repository := &enrollmentRepositoryStub{}
	materials := &installMaterialRepositoryStub{value: domainenrollment.InstallMaterial{
		Channel: "linux-systemd-stable", ArtifactID: "artifact-a", ArtifactSHA256: "sha256-a",
		ArtifactURL: "https://packages.example/agent.tar.gz",
	}}
	service := NewCreateService(
		&enrollmentUnitOfWorkStub{tx: enrollmentTransactionStub{enrollments: repository, materials: materials}},
		&tokenGeneratorStub{values: []ports.EnrollmentToken{
			{Plaintext: "enrollment-token", Hash: "enrollment-hash", Preview: "enr_...oken"},
			{Plaintext: "bootstrap-token", Hash: "bootstrap-hash", Preview: "enr_...boot"},
		}},
		clockStub{now: time.Unix(100, 0).UTC()}, idGeneratorStub{value: "enroll-a"},
	)

	_, err := service.Execute(context.Background(), operatorRequest(t, "tenant-a"), CreateEnrollmentCommand{
		TenantID: "tenant-a", AgentID: "agent-a", GatewayAddress: "gateway:9444", TTL: time.Hour,
		Channel: "linux-systemd-stable", ArtifactID: "ignored-artifact",
	})
	if err != nil {
		t.Fatal(err)
	}
	if materials.channel != "linux-systemd-stable" || materials.artifactID != "ignored-artifact" {
		t.Fatalf("material query channel=%q artifact=%q", materials.channel, materials.artifactID)
	}
	if repository.putValue.ArtifactID != "artifact-a" || repository.putValue.ArtifactSHA256 != "sha256-a" ||
		repository.putValue.Channel != "linux-systemd-stable" {
		t.Fatalf("enrollment = %#v", repository.putValue)
	}
}

func TestAuthorizeArtifactUsesEnrollmentTenantAndBinding(t *testing.T) {
	current := activeEnrollment(t)
	current.ArtifactID = "artifact-a"
	materials := &installMaterialRepositoryStub{artifact: domainenrollment.InstallArtifact{
		ID: "artifact-a", SHA256: "sha256-a", Status: "active", StoragePath: "/artifacts/agent.tar.gz",
	}}
	service := NewArtifactService(&enrollmentUnitOfWorkStub{tx: enrollmentTransactionStub{
		enrollments: &enrollmentRepositoryStub{current: current}, materials: materials,
	}}, clockStub{now: time.Unix(100, 0).UTC()})

	result, err := service.Authorize(context.Background(), AuthorizeArtifactCommand{TokenHash: "token-hash"})
	if err != nil {
		t.Fatal(err)
	}
	if materials.artifactTenant != current.TenantID || materials.requestedArtifactID != "artifact-a" ||
		result.Artifact.ID != "artifact-a" {
		t.Fatalf("result=%#v tenant=%q artifact=%q", result, materials.artifactTenant, materials.requestedArtifactID)
	}
}

type enrollmentUnitOfWorkStub struct {
	tx        ports.EnrollmentTransaction
	commitErr error
}

func (stub *enrollmentUnitOfWorkStub) Execute(ctx context.Context, fn func(context.Context, ports.EnrollmentTransaction) error) error {
	if err := fn(ctx, stub.tx); err != nil {
		return err
	}
	return stub.commitErr
}

type enrollmentTransactionStub struct {
	enrollments   ports.EnrollmentRepository
	materials     ports.InstallMaterialRepository
	certificates  ports.CertificateRepository
	unenrollments ports.UnenrollmentRepository
}

func (stub enrollmentTransactionStub) Enrollments() ports.EnrollmentRepository {
	return stub.enrollments
}
func (stub enrollmentTransactionStub) InstallMaterials() ports.InstallMaterialRepository {
	return stub.materials
}
func (stub enrollmentTransactionStub) Certificates() ports.CertificateRepository {
	return stub.certificates
}
func (stub enrollmentTransactionStub) Unenrollments() ports.UnenrollmentRepository {
	return stub.unenrollments
}

type enrollmentRepositoryStub struct {
	current          domainenrollment.Enrollment
	bootstrapCurrent domainenrollment.Enrollment
	listed           []domainenrollment.Enrollment
	listTenant       tenant.ID
	listStatus       domainenrollment.Status
	putValue         domainenrollment.Enrollment
	puts             int
}

func (stub *enrollmentRepositoryStub) ByTokenHash(context.Context, string) (domainenrollment.Enrollment, error) {
	return stub.current, nil
}

func (stub *enrollmentRepositoryStub) ByBootstrapTokenHash(context.Context, string) (domainenrollment.Enrollment, error) {
	return stub.bootstrapCurrent, nil
}

func (stub *enrollmentRepositoryStub) Put(_ context.Context, value domainenrollment.Enrollment) error {
	stub.puts++
	stub.putValue = value
	return nil
}

func (stub *enrollmentRepositoryStub) RedeemBootstrap(_ context.Context, _, _ domainenrollment.Enrollment) error {
	stub.puts++
	return nil
}

func (stub *enrollmentRepositoryStub) List(_ context.Context, tenantID tenant.ID, status domainenrollment.Status) ([]domainenrollment.Enrollment, error) {
	stub.listTenant, stub.listStatus = tenantID, status
	return stub.listed, nil
}

type certificateRepositoryStub struct{ puts int }

func (stub *certificateRepositoryStub) Put(context.Context, domainenrollment.Certificate) error {
	stub.puts++
	return nil
}

type unenrollmentRepositoryStub struct {
	current    domainenrollment.Unenrollment
	listed     []domainenrollment.Unenrollment
	listTenant tenant.ID
	puts       int
}

func (stub *unenrollmentRepositoryStub) Get(context.Context, tenant.ID, string) (domainenrollment.Unenrollment, error) {
	return stub.current, nil
}

func (stub *unenrollmentRepositoryStub) Put(context.Context, domainenrollment.Unenrollment) error {
	stub.puts++
	return nil
}

func (stub *unenrollmentRepositoryStub) List(_ context.Context, tenantID tenant.ID) ([]domainenrollment.Unenrollment, error) {
	stub.listTenant = tenantID
	return stub.listed, nil
}

type installMaterialRepositoryStub struct {
	value               domainenrollment.InstallMaterial
	channel, artifactID string
	resolveCalls        [][2]string
	resolveErrors       []error
	artifact            domainenrollment.InstallArtifact
	artifactTenant      tenant.ID
	requestedArtifactID string
	artifacts           []domainenrollment.DeploymentArtifact
	listTenant          tenant.ID
}

func (stub *installMaterialRepositoryStub) ListArtifacts(_ context.Context, tenantID tenant.ID) ([]domainenrollment.DeploymentArtifact, error) {
	stub.listTenant = tenantID
	return stub.artifacts, nil
}

func (stub *installMaterialRepositoryStub) GetArtifact(_ context.Context, tenantID tenant.ID, artifactID string) (domainenrollment.InstallArtifact, error) {
	stub.artifactTenant, stub.requestedArtifactID = tenantID, artifactID
	return stub.artifact, nil
}

func (stub *installMaterialRepositoryStub) Resolve(_ context.Context, _ tenant.ID, channel, artifactID string) (domainenrollment.InstallMaterial, error) {
	stub.channel, stub.artifactID = channel, artifactID
	stub.resolveCalls = append(stub.resolveCalls, [2]string{channel, artifactID})
	if len(stub.resolveErrors) == 0 {
		return stub.value, nil
	}
	err := stub.resolveErrors[0]
	stub.resolveErrors = stub.resolveErrors[1:]
	return stub.value, err
}

type certificateIssuerStub struct{ issuance domainenrollment.Issuance }

func (stub certificateIssuerStub) Issue(context.Context, domainenrollment.Enrollment, []byte) (domainenrollment.Issuance, error) {
	return stub.issuance, nil
}

type clockStub struct{ now time.Time }

func (stub clockStub) Now() time.Time { return stub.now }

type idGeneratorStub struct{ value string }

func (stub idGeneratorStub) New() string { return stub.value }

type tokenGeneratorStub struct {
	values []ports.EnrollmentToken
	index  int
}

func (stub *tokenGeneratorStub) New() (ports.EnrollmentToken, error) {
	value := stub.values[stub.index]
	stub.index++
	return value, nil
}

func activeEnrollment(t *testing.T) domainenrollment.Enrollment {
	t.Helper()
	tid, err := tenant.NewID("tenant-a")
	if err != nil {
		t.Fatal(err)
	}
	value, err := domainenrollment.NewEnrollment(domainenrollment.Enrollment{
		ID: "enroll-a", TenantID: tid, AgentID: "agent-a", TokenHash: "token-hash",
		Status: domainenrollment.StatusActive, ExpiresAt: time.Unix(500, 0).UTC(),
	})
	if err != nil {
		t.Fatal(err)
	}
	return value
}

func issuance(t *testing.T) domainenrollment.Issuance {
	t.Helper()
	return domainenrollment.Issuance{
		KeySHA256: "key-hash",
		Certificate: domainenrollment.Certificate{
			SerialNumber: "42", CertificatePEM: "certificate", NotAfter: time.Unix(500, 0).UTC(),
		},
		CAPEM: "ca",
	}
}

func pendingUnenrollment(t *testing.T) domainenrollment.Unenrollment {
	t.Helper()
	value, err := domainenrollment.NewPendingUnenrollment(domainenrollment.UnenrollmentIdentity{
		TenantID: mustApplicationTenant(t), AgentID: "agent-a", EnrollmentID: "enroll-a", CertificateSerial: "42",
	}, "receipt-a", "token-hash", time.Unix(100, 0).UTC())
	if err != nil {
		t.Fatal(err)
	}
	return value
}

func mustApplicationTenant(t *testing.T) tenant.ID {
	t.Helper()
	value, err := tenant.NewID("tenant-a")
	if err != nil {
		t.Fatal(err)
	}
	return value
}

func operatorRequest(t *testing.T, tenantID string) managerapp.RequestContext {
	t.Helper()
	value, err := tenant.NewID(tenantID)
	if err != nil {
		t.Fatal(err)
	}
	return managerapp.RequestContext{Actor: tenant.Actor{
		Subject: "operator-a", TenantID: value, Roles: tenant.NewRoleSet(tenant.RoleOperator),
	}}
}

func viewerRequest(t *testing.T, tenantID string) managerapp.RequestContext {
	t.Helper()
	value, err := tenant.NewID(tenantID)
	if err != nil {
		t.Fatal(err)
	}
	return managerapp.RequestContext{Actor: tenant.Actor{
		Subject: "viewer-a", TenantID: value, Roles: tenant.NewRoleSet(tenant.RoleViewer),
	}}
}
