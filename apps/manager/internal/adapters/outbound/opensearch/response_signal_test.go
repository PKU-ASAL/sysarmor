package opensearch

import (
	"context"
	"encoding/json"
	"testing"

	managerapp "github.com/sysarmor/sysarmor-next-project/apps/manager/internal/application/manager"
	responseapp "github.com/sysarmor/sysarmor-next-project/apps/manager/internal/application/manager/response"
	"github.com/sysarmor/sysarmor-next-project/apps/manager/internal/domain/failure"
	"github.com/sysarmor/sysarmor-next-project/apps/manager/internal/domain/tenant"
)

func TestResponseSignalResolverScopesQueryAndMapsIntent(t *testing.T) {
	searcher := &responseSignalSearcherStub{documents: []json.RawMessage{json.RawMessage(`{
		"id":"signal-a","tenant_id":"tenant-a","name":"suspicious shell","labels":{"host":"a"},
		"entities":[{"kind":"process","key":"process:p1"}],
		"response_intent":{"response_intent":"contain","recommended_action":"collect","confidence":90,"reason":"high risk"}
	}`)}}
	resolver := NewResponseSignalResolver(searcher)
	request := managerapp.RequestContext{Actor: tenant.Actor{TenantID: "tenant-a"}}

	command, err := resolver.Resolve(context.Background(), request, responseapp.DecisionCommand{
		SignalID: "signal-a", AgentID: "agent-a",
	})
	if err != nil {
		t.Fatal(err)
	}
	if command.ID != "resp-signal-a" || command.Action != "collect" || command.Target != "process:p1" ||
		command.Reason != "signal=signal-a name=suspicious shell response_intent=contain confidence=90 reason=high risk" {
		t.Fatalf("command=%+v", command)
	}
	if searcher.request.Index != SignalsReadAlias || searcher.request.Exact["tenant_id"] != "tenant-a" ||
		searcher.request.Exact["id"] != "signal-a" {
		t.Fatalf("search request=%+v", searcher.request)
	}
}

func TestResponseSignalResolverMapsCamelCaseIntent(t *testing.T) {
	searcher := &responseSignalSearcherStub{documents: []json.RawMessage{json.RawMessage(`{
		"id":"signal-a","tenant_id":"tenant-a","name":"suspicious shell",
		"responseIntent":{"responseIntent":"contain","recommendedAction":"kill","confidence":80}
	}`)}}
	resolver := NewResponseSignalResolver(searcher)

	command, err := resolver.Resolve(context.Background(), responseSignalRequest(), responseapp.DecisionCommand{
		SignalID: "signal-a", AgentID: "agent-a",
	})
	if err != nil {
		t.Fatal(err)
	}
	if command.Action != "kill" || command.Reason != "signal=signal-a name=suspicious shell response_intent=contain confidence=80" {
		t.Fatalf("command=%+v", command)
	}
}

func TestResponseSignalResolverReturnsNotFoundForMissingSignal(t *testing.T) {
	resolver := NewResponseSignalResolver(&responseSignalSearcherStub{})

	_, err := resolver.Resolve(context.Background(), responseSignalRequest(), responseapp.DecisionCommand{
		SignalID: "missing", AgentID: "agent-a",
	})
	if failure.KindOf(err) != failure.NotFound {
		t.Fatalf("kind=%v error=%v", failure.KindOf(err), err)
	}
}

func TestResponseSignalResolverRejectsSignalWithoutIntent(t *testing.T) {
	searcher := &responseSignalSearcherStub{documents: []json.RawMessage{
		json.RawMessage(`{"id":"signal-a","tenant_id":"tenant-a","name":"suspicious shell"}`),
	}}
	resolver := NewResponseSignalResolver(searcher)

	_, err := resolver.Resolve(context.Background(), responseSignalRequest(), responseapp.DecisionCommand{
		SignalID: "signal-a", AgentID: "agent-a",
	})
	if failure.KindOf(err) != failure.InvalidArgument {
		t.Fatalf("kind=%v error=%v", failure.KindOf(err), err)
	}
}

func responseSignalRequest() managerapp.RequestContext {
	return managerapp.RequestContext{Actor: tenant.Actor{TenantID: "tenant-a"}}
}

type responseSignalSearcherStub struct {
	documents []json.RawMessage
	request   SearchRequest
}

func (stub *responseSignalSearcherStub) Search(_ context.Context, request SearchRequest) ([]json.RawMessage, error) {
	stub.request = request
	return stub.documents, nil
}
