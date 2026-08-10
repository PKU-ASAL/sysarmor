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

type deliveryStub struct {
	commandIDs []string
	err        error
}

func (stub *deliveryStub) MarkSent(_ context.Context, _, _, commandID string) error {
	stub.commandIDs = append(stub.commandIDs, commandID)
	return stub.err
}

func (stub *sessionRepositoryStub) Open(_ context.Context, tenantID, agentID, scopeType, scopeSelector string) (domaingateway.OpenSession, error) {
	stub.args = []string{tenantID, agentID, scopeType, scopeSelector}
	return stub.result, stub.err
}

func TestOpenSessionRejectsBlankIdentity(t *testing.T) {
	service := NewOpenSessionService(&sessionRepositoryStub{}, &deliveryStub{})
	for _, identity := range [][2]string{{"", "agent-a"}, {"tenant-a", " "}} {
		if _, err := service.Open(context.Background(), identity[0], identity[1], "", ""); err == nil || !strings.Contains(err.Error(), "required") {
			t.Fatalf("Open(%q, %q) error = %v", identity[0], identity[1], err)
		}
	}
}

func TestOpenSessionPropagatesRepositoryError(t *testing.T) {
	want := errors.New("database unavailable")
	service := NewOpenSessionService(&sessionRepositoryStub{err: want}, &deliveryStub{})
	if _, err := service.Open(context.Background(), "tenant-a", "agent-a", "host", "host-a"); !errors.Is(err, want) {
		t.Fatalf("Open() error = %v, want %v", err, want)
	}
}

func TestOpenSessionMarksControlCommandsSent(t *testing.T) {
	repository := &sessionRepositoryStub{result: domaingateway.OpenSession{Messages: []domaingateway.Message{
		{Type: "control_command", ID: "command-a"},
		{Type: "evidence_pullback", ID: "evidence-a"},
	}}}
	delivery := &deliveryStub{}
	service := NewOpenSessionService(repository, delivery)

	if _, err := service.Open(context.Background(), "tenant-a", "agent-a", "host", "host-a"); err != nil {
		t.Fatal(err)
	}
	if len(delivery.commandIDs) != 1 || delivery.commandIDs[0] != "command-a" {
		t.Fatalf("marked commands = %v", delivery.commandIDs)
	}
}

func TestOpenSessionFailsWhenCommandCannotBeMarkedSent(t *testing.T) {
	want := errors.New("write failed")
	repository := &sessionRepositoryStub{result: domaingateway.OpenSession{Messages: []domaingateway.Message{
		{Type: "control_command", ID: "command-a"},
	}}}
	service := NewOpenSessionService(repository, &deliveryStub{err: want})

	if _, err := service.Open(context.Background(), "tenant-a", "agent-a", "host", "host-a"); !errors.Is(err, want) {
		t.Fatalf("Open() error = %v, want %v", err, want)
	}
}
