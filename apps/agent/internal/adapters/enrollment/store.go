package enrollment

import (
	"context"
	"fmt"
	"time"

	"github.com/sysarmor/sysarmor-next-project/apps/agent/internal/adapters/sqlite"
	"github.com/sysarmor/sysarmor-next-project/apps/agent/internal/ports"
)

type Backend interface {
	Enrollment(context.Context) (sqlite.Enrollment, error)
	Stats(context.Context) (sqlite.Stats, error)
	SetEnrolling(context.Context, sqlite.Enrollment) error
	BeginUnenrollment(context.Context) (sqlite.Enrollment, error)
	PrepareUnenrollment(context.Context, string, string) (sqlite.Enrollment, error)
	UnenrollmentCompletion(context.Context) (sqlite.UnenrollmentCompletion, bool, error)
	RecordUnenrollmentError(context.Context, string) error
	ConfirmEnrollmentRevocation(context.Context, string, time.Time) error
}

type Store struct {
	backend  Backend
	complete func(context.Context, string) error
}

func NewStore(backend Backend, complete func(context.Context, string) error) *Store {
	return &Store{backend: backend, complete: complete}
}

func (s *Store) Enrollment(ctx context.Context) (ports.Enrollment, error) {
	enrollment, err := s.backend.Enrollment(ctx)
	return fromLocalEnrollment(enrollment), err
}

func (s *Store) Stats(ctx context.Context) (ports.EnrollmentStats, error) {
	stats, err := s.backend.Stats(ctx)
	return ports.EnrollmentStats{
		OldestEventSequence: stats.OldestEventSequence,
		LatestEventSequence: stats.LatestEventSequence,
	}, err
}

func (s *Store) SetEnrolling(ctx context.Context, enrollment ports.Enrollment) error {
	return s.backend.SetEnrolling(ctx, toLocalEnrollment(enrollment))
}

func (s *Store) BeginUnenrollment(ctx context.Context) (ports.Enrollment, error) {
	enrollment, err := s.backend.BeginUnenrollment(ctx)
	return fromLocalEnrollment(enrollment), err
}

func (s *Store) PrepareUnenrollment(ctx context.Context, token, tokenHash string) (ports.Enrollment, ports.UnenrollmentCompletion, error) {
	current, err := s.backend.Enrollment(ctx)
	if err != nil {
		return ports.Enrollment{}, ports.UnenrollmentCompletion{}, err
	}
	switch current.UnenrollmentProtocol {
	case sqlite.UnenrollmentProtocolLegacyMTLS:
		current, err = s.backend.BeginUnenrollment(ctx)
		return fromLocalEnrollment(current), ports.UnenrollmentCompletion{}, err
	case sqlite.UnenrollmentProtocolCompletionV1:
		return s.prepareCompletion(ctx, current, token, tokenHash)
	default:
		return ports.Enrollment{}, ports.UnenrollmentCompletion{}, fmt.Errorf("unsupported unenrollment protocol %q", current.UnenrollmentProtocol)
	}
}

func (s *Store) prepareCompletion(ctx context.Context, current sqlite.Enrollment, token, tokenHash string) (ports.Enrollment, ports.UnenrollmentCompletion, error) {
	var err error
	if current.State != sqlite.StateUnenrolling {
		current, err = s.backend.PrepareUnenrollment(ctx, token, tokenHash)
		if err != nil {
			return ports.Enrollment{}, ports.UnenrollmentCompletion{}, err
		}
	}
	completion, ok, err := s.backend.UnenrollmentCompletion(ctx)
	if err != nil {
		return ports.Enrollment{}, ports.UnenrollmentCompletion{}, fmt.Errorf("read prepared unenrollment completion: %w", err)
	}
	if !ok {
		return ports.Enrollment{}, ports.UnenrollmentCompletion{}, fmt.Errorf("prepared unenrollment completion does not exist")
	}
	return fromLocalEnrollment(current), fromLocalCompletion(completion), nil
}

func (s *Store) UnenrollmentCompletion(ctx context.Context) (ports.UnenrollmentCompletion, bool, error) {
	completion, ok, err := s.backend.UnenrollmentCompletion(ctx)
	return fromLocalCompletion(completion), ok, err
}

func (s *Store) RecordUnenrollmentError(ctx context.Context, message string) error {
	return s.backend.RecordUnenrollmentError(ctx, message)
}

func (s *Store) ConfirmEnrollmentRevocation(ctx context.Context, receipt string, revokedAt time.Time) error {
	return s.backend.ConfirmEnrollmentRevocation(ctx, receipt, revokedAt)
}

func (s *Store) CompleteUnenrollment(ctx context.Context, kind string) error {
	return s.complete(ctx, kind)
}

func fromLocalEnrollment(value sqlite.Enrollment) ports.Enrollment {
	return ports.Enrollment{
		State: value.State, TenantID: value.TenantID, AgentID: value.AgentID,
		EnrollmentID: value.EnrollmentID, CertificateSerial: value.CertificateSerial,
		ManagerURL:     value.ManagerURL,
		GatewayAddress: value.GatewayAddress, TLSCAPath: value.TLSCAPath,
		TLSCertPath: value.TLSCertPath, TLSKeyPath: value.TLSKeyPath,
		TLSServerName: value.TLSServerName, UploadHistory: value.UploadHistory,
		ManagedFromSequence: value.ManagedFromSequence, RevocationConfirmed: value.RevocationConfirmed,
		RevokedAt: value.RevokedAt, RevocationReceipt: value.RevocationReceipt,
	}
}

func toLocalEnrollment(value ports.Enrollment) sqlite.Enrollment {
	return sqlite.Enrollment{
		State: value.State, TenantID: value.TenantID, AgentID: value.AgentID,
		EnrollmentID: value.EnrollmentID, CertificateSerial: value.CertificateSerial,
		ManagerURL:     value.ManagerURL,
		GatewayAddress: value.GatewayAddress, TLSCAPath: value.TLSCAPath,
		TLSCertPath: value.TLSCertPath, TLSKeyPath: value.TLSKeyPath,
		TLSServerName: value.TLSServerName, UploadHistory: value.UploadHistory,
		ManagedFromSequence: value.ManagedFromSequence, RevocationConfirmed: value.RevocationConfirmed,
		RevokedAt: value.RevokedAt, RevocationReceipt: value.RevocationReceipt,
	}
}

func fromLocalCompletion(value sqlite.UnenrollmentCompletion) ports.UnenrollmentCompletion {
	return ports.UnenrollmentCompletion{Token: value.Token, TokenHash: value.TokenHash, Status: value.Status}
}
