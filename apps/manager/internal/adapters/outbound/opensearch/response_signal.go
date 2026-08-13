package opensearch

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	managerapp "github.com/sysarmor/sysarmor-next-project/apps/manager/internal/application/manager"
	responseapp "github.com/sysarmor/sysarmor-next-project/apps/manager/internal/application/manager/response"
	"github.com/sysarmor/sysarmor-next-project/apps/manager/internal/domain/failure"
	domainresponse "github.com/sysarmor/sysarmor-next-project/apps/manager/internal/domain/response"
)

type ResponseSignalResolver struct{ searcher Searcher }

func NewResponseSignalResolver(searcher Searcher) ResponseSignalResolver {
	return ResponseSignalResolver{searcher: searcher}
}

func (resolver ResponseSignalResolver) Resolve(ctx context.Context, request managerapp.RequestContext, query responseapp.DecisionCommand) (domainresponse.Command, error) {
	if strings.TrimSpace(query.SignalID) == "" || strings.TrimSpace(query.AgentID) == "" {
		return domainresponse.Command{}, failure.New(failure.InvalidArgument, "signal_id and agent_id are required")
	}
	if query.TenantID != "" && query.TenantID != request.Actor.TenantID.String() {
		return domainresponse.Command{}, failure.New(failure.PermissionDenied, "response tenant does not match actor tenant")
	}
	if resolver.searcher == nil {
		return domainresponse.Command{}, failure.New(failure.NotFound, "signal not found")
	}
	documents, err := resolver.searcher.Search(ctx, SearchRequest{Index: SignalsReadAlias, Size: 2,
		Exact: map[string]string{"tenant_id": request.Actor.TenantID.String(), "id": query.SignalID}})
	if err != nil {
		return domainresponse.Command{}, fmt.Errorf("read response signal: %w", err)
	}
	for _, document := range documents {
		command, found, err := mapResponseSignal(document, request, query)
		if err != nil {
			return domainresponse.Command{}, err
		}
		if found {
			return command, nil
		}
	}
	return domainresponse.Command{}, failure.New(failure.NotFound, "signal not found")
}

type signalEntity struct {
	Kind string `json:"kind"`
	Key  string `json:"key"`
}

type responseSignal struct {
	ID       string            `json:"id"`
	TenantID string            `json:"tenant_id"`
	Name     string            `json:"name"`
	Labels   map[string]string `json:"labels"`
	Entities []signalEntity    `json:"entities"`
}

func mapResponseSignal(raw []byte, request managerapp.RequestContext, query responseapp.DecisionCommand) (domainresponse.Command, bool, error) {
	var signal responseSignal
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(raw, &signal); err != nil {
		return domainresponse.Command{}, false, fmt.Errorf("decode response signal: %w", err)
	}
	if signal.ID != query.SignalID || signal.TenantID != request.Actor.TenantID.String() {
		return domainresponse.Command{}, false, nil
	}
	if err := json.Unmarshal(raw, &fields); err != nil {
		return domainresponse.Command{}, false, fmt.Errorf("decode response signal: %w", err)
	}
	intent, err := decodeResponseIntent(fields)
	if err != nil {
		return domainresponse.Command{}, false, err
	}
	if intent.Name == "" {
		return domainresponse.Command{}, false, failure.New(failure.InvalidArgument, "signal response intent not found")
	}
	target := query.Target
	if target == "" {
		target = responseSignalTarget(signal.Entities)
	}
	action := intent.Action
	if action == "" {
		action = intent.Name
	}
	reason := fmt.Sprintf("signal=%s name=%s response_intent=%s confidence=%d", signal.ID, signal.Name, intent.Name, intent.Confidence)
	if intent.Reason != "" {
		reason += " reason=" + intent.Reason
	}
	return domainresponse.Command{ID: "resp-" + signal.ID, TenantID: request.Actor.TenantID, AgentID: query.AgentID,
		SignalID: signal.ID, Labels: signal.Labels, Scope: query.Scope, Action: action, Mode: "observe",
		Target: target, Reason: reason}, true, nil
}

type responseIntent struct {
	Name       string
	Action     string
	Confidence uint32
	Reason     string
}

func decodeResponseIntent(fields map[string]json.RawMessage) (responseIntent, error) {
	raw := fields["response_intent"]
	if len(raw) == 0 {
		raw = fields["responseIntent"]
	}
	if len(raw) == 0 {
		return responseIntent{}, nil
	}
	var values map[string]json.RawMessage
	if err := json.Unmarshal(raw, &values); err != nil {
		return responseIntent{}, fmt.Errorf("decode signal response intent: %w", err)
	}
	var result responseIntent
	decodeResponseString(values, []string{"response_intent", "responseIntent"}, &result.Name)
	decodeResponseString(values, []string{"recommended_action", "recommendedAction"}, &result.Action)
	decodeResponseString(values, []string{"reason"}, &result.Reason)
	_ = json.Unmarshal(values["confidence"], &result.Confidence)
	return result, nil
}

func decodeResponseString(values map[string]json.RawMessage, keys []string, target *string) {
	for _, key := range keys {
		if len(values[key]) > 0 && json.Unmarshal(values[key], target) == nil && *target != "" {
			return
		}
	}
}

func responseSignalTarget(entities []signalEntity) string {
	for _, entity := range entities {
		if entity.Kind == "process" && entity.Key != "" {
			return entity.Key
		}
	}
	for _, entity := range entities {
		if entity.Key != "" {
			return entity.Key
		}
	}
	return ""
}
