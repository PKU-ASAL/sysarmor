package session

import (
	"context"
	"testing"

	domainidentity "github.com/sysarmor/sysarmor-next-project/apps/manager/internal/domain/identity"
	"github.com/sysarmor/sysarmor-next-project/apps/manager/internal/domain/tenant"
)

type fakeSessions struct{ values []domainidentity.Session }

func (fake fakeSessions) List(context.Context, tenant.ID, domainidentity.SessionFilter) ([]domainidentity.Session, error) {
	return fake.values, nil
}

func TestResumeAndDuplicateUseSessionRepository(t *testing.T) {
	service := NewQueryService(fakeSessions{values: []domainidentity.Session{{ID: "session-a", LastAckCursor: "batch-a"}}})
	resume, err := service.Resume(context.Background(), "tenant-a", "agent-a")
	if err != nil || resume.SessionID != "session-a" || resume.Cursor != "batch-a" {
		t.Fatalf("resume=%+v err=%v", resume, err)
	}
	duplicate, err := service.IsDuplicate(context.Background(), "tenant-a", "agent-a", "batch-a")
	if err != nil || !duplicate {
		t.Fatalf("duplicate=%t err=%v", duplicate, err)
	}
}
