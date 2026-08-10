package enrollment

import (
	"context"
	"errors"
	"testing"
	"time"

	domainenrollment "github.com/sysarmor/sysarmor-next-project/apps/manager/internal/domain/enrollment"
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
	if result != (IssueCertificateResult{}) {
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
	certificates  ports.CertificateRepository
	unenrollments ports.UnenrollmentRepository
}

func (stub enrollmentTransactionStub) Enrollments() ports.EnrollmentRepository {
	return stub.enrollments
}
func (stub enrollmentTransactionStub) Certificates() ports.CertificateRepository {
	return stub.certificates
}
func (stub enrollmentTransactionStub) Unenrollments() ports.UnenrollmentRepository {
	return stub.unenrollments
}

type enrollmentRepositoryStub struct {
	current domainenrollment.Enrollment
	puts    int
}

func (stub *enrollmentRepositoryStub) ByTokenHash(context.Context, string) (domainenrollment.Enrollment, error) {
	return stub.current, nil
}

func (stub *enrollmentRepositoryStub) Put(context.Context, domainenrollment.Enrollment) error {
	stub.puts++
	return nil
}

type certificateRepositoryStub struct{ puts int }

func (stub *certificateRepositoryStub) Put(context.Context, domainenrollment.Certificate) error {
	stub.puts++
	return nil
}

type unenrollmentRepositoryStub struct {
	current domainenrollment.Unenrollment
	puts    int
}

func (stub *unenrollmentRepositoryStub) Get(context.Context, tenant.ID, string) (domainenrollment.Unenrollment, error) {
	return stub.current, nil
}

func (stub *unenrollmentRepositoryStub) Put(context.Context, domainenrollment.Unenrollment) error {
	stub.puts++
	return nil
}

type certificateIssuerStub struct{ issuance domainenrollment.Issuance }

func (stub certificateIssuerStub) Issue(context.Context, domainenrollment.Enrollment, []byte) (domainenrollment.Issuance, error) {
	return stub.issuance, nil
}

type clockStub struct{ now time.Time }

func (stub clockStub) Now() time.Time { return stub.now }

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
