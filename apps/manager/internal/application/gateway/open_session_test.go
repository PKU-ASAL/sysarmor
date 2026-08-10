package gateway

import (
	"context"
	"errors"
	"strings"
	"testing"

	domaingateway "github.com/sysarmor/sysarmor-next-project/apps/manager/internal/domain/gateway"
)

type sessionRepositoryStub struct {
	result domaingateway.OpenSession
	err    error
	args   []string
}

func (stub *sessionRepositoryStub) Open(_ context.Context, tenantID, agentID, scopeType, scopeSelector string) (domaingateway.OpenSession, error) {
	stub.args = []string{tenantID, agentID, scopeType, scopeSelector}
	return stub.result, stub.err
}

func TestOpenSessionRejectsBlankIdentity(t *testing.T) {
	service := NewOpenSessionService(&sessionRepositoryStub{})
	for _, identity := range [][2]string{{"", "agent-a"}, {"tenant-a", " "}} {
		if _, err := service.Open(context.Background(), identity[0], identity[1], "", ""); err == nil || !strings.Contains(err.Error(), "required") {
			t.Fatalf("Open(%q, %q) error = %v", identity[0], identity[1], err)
		}
	}
}

func TestOpenSessionPropagatesRepositoryError(t *testing.T) {
	want := errors.New("database unavailable")
	service := NewOpenSessionService(&sessionRepositoryStub{err: want})
	if _, err := service.Open(context.Background(), "tenant-a", "agent-a", "host", "host-a"); !errors.Is(err, want) {
		t.Fatalf("Open() error = %v, want %v", err, want)
	}
}
