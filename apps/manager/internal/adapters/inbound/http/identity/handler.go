package identity

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"

	managerapp "github.com/sysarmor/sysarmor-next-project/apps/manager/internal/application/manager"
	identityapp "github.com/sysarmor/sysarmor-next-project/apps/manager/internal/application/manager/identity"
	"github.com/sysarmor/sysarmor-next-project/apps/manager/internal/domain/failure"
	domainidentity "github.com/sysarmor/sysarmor-next-project/apps/manager/internal/domain/identity"
)

type RequestContextResolver func(*http.Request) (managerapp.RequestContext, error)

type Queries interface {
	ListAgents(context.Context, managerapp.RequestContext, identityapp.ListAgentsQuery) (identityapp.ListAgentsResult, error)
	GetHealth(context.Context, managerapp.RequestContext, domainidentity.AgentID) (domainidentity.Health, error)
	ListHealth(context.Context, managerapp.RequestContext, identityapp.ListHealthQuery) (identityapp.ListHealthResult, error)
	ListSessions(context.Context, managerapp.RequestContext, identityapp.ListSessionsQuery) (identityapp.ListSessionsResult, error)
	Resume(context.Context, managerapp.RequestContext, string) (identityapp.ResumeResult, error)
	Metrics(context.Context, managerapp.RequestContext) (domainidentity.Metrics, error)
	Rarity(context.Context, managerapp.RequestContext) (domainidentity.RarityBaseline, error)
	AgentOverview(context.Context, managerapp.RequestContext) (domainidentity.AgentOverview, error)
}

type Options struct {
	Query   Queries
	Resolve RequestContextResolver
}
type Handler struct{ options Options }

func NewHandler(options Options) *Handler { return &Handler{options: options} }

func (handler *Handler) Agents(w http.ResponseWriter, r *http.Request) {
	request, ok := handler.getRequest(w, r)
	if !ok {
		return
	}
	query := r.URL.Query()
	filter := domainidentity.AgentFilter{ScopeType: query.Get("scope_type"), ScopeSelector: query.Get("scope_selector"), HealthStatus: query.Get("health_status")}
	agents, err := handler.options.Query.ListAgents(r.Context(), request, identityapp.ListAgentsQuery{Filter: filter})
	if err != nil {
		writeFailure(w, err)
		return
	}
	health, err := handler.options.Query.ListHealth(r.Context(), request, identityapp.ListHealthQuery{})
	if err != nil {
		writeFailure(w, err)
		return
	}
	writeJSON(w, agentItems(agents.Agents, health.Health, filter))
}

func (handler *Handler) Health(w http.ResponseWriter, r *http.Request) {
	request, ok := handler.getRequest(w, r)
	if !ok {
		return
	}
	agentID := r.URL.Query().Get("agent_id")
	if agentID == "" {
		result, err := handler.options.Query.ListHealth(r.Context(), request, identityapp.ListHealthQuery{})
		if err != nil {
			writeFailure(w, err)
			return
		}
		writeJSON(w, healthDocuments(result.Health))
		return
	}
	value, err := handler.options.Query.GetHealth(r.Context(), request, domainidentity.AgentID(agentID))
	if err != nil {
		writeFailure(w, err)
		return
	}
	writeJSON(w, json.RawMessage(value.Document))
}

func (handler *Handler) Sessions(w http.ResponseWriter, r *http.Request) {
	request, ok := handler.getRequest(w, r)
	if !ok {
		return
	}
	result, err := handler.options.Query.ListSessions(r.Context(), request, identityapp.ListSessionsQuery{Filter: domainidentity.SessionFilter{AgentID: r.URL.Query().Get("agent_id")}})
	if err != nil {
		writeFailure(w, err)
		return
	}
	writeJSON(w, map[string]any{"sessions": sessionDTOs(result.Sessions)})
}

func (handler *Handler) Resume(w http.ResponseWriter, r *http.Request) {
	request, ok := handler.getRequest(w, r)
	if !ok {
		return
	}
	agentID := r.URL.Query().Get("agent_id")
	if agentID == "" {
		writeFailure(w, failure.New(failure.InvalidArgument, "agent_id is required"))
		return
	}
	result, err := handler.options.Query.Resume(r.Context(), request, agentID)
	if err != nil {
		writeFailure(w, err)
		return
	}
	writeJSON(w, resumeDTO{TenantID: result.TenantID, AgentID: result.AgentID, SessionID: result.SessionID, ResumeCursor: result.ResumeCursor})
}

func (handler *Handler) Metrics(w http.ResponseWriter, r *http.Request) {
	request, ok := handler.getRequest(w, r)
	if !ok {
		return
	}
	value, err := handler.options.Query.Metrics(r.Context(), request)
	if err != nil {
		writeFailure(w, err)
		return
	}
	writeJSON(w, mapMetrics(value))
}

func (handler *Handler) Rarity(w http.ResponseWriter, r *http.Request) {
	request, ok := handler.getRequest(w, r)
	if !ok {
		return
	}
	value, err := handler.options.Query.Rarity(r.Context(), request)
	if err != nil {
		writeFailure(w, err)
		return
	}
	query := r.URL.Query()
	writeJSON(w, map[string]any{"baseline": rarityDocument(value), "count": value.Count(query.Get("workload"), query.Get("signal"))})
}

func (handler *Handler) AgentOverview(r *http.Request) (domainidentity.AgentOverview, error) {
	request, err := handler.resolve(r)
	if err != nil {
		return domainidentity.AgentOverview{}, err
	}
	return handler.options.Query.AgentOverview(r.Context(), request)
}

func (handler *Handler) MetricsQuery(r *http.Request) (domainidentity.Metrics, error) {
	request, err := handler.resolve(r)
	if err != nil {
		return domainidentity.Metrics{}, err
	}
	return handler.options.Query.Metrics(r.Context(), request)
}

func (handler *Handler) getRequest(w http.ResponseWriter, r *http.Request) (managerapp.RequestContext, bool) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return managerapp.RequestContext{}, false
	}
	request, err := handler.resolve(r)
	if err != nil {
		writeFailure(w, err)
		return managerapp.RequestContext{}, false
	}
	return request, true
}

func (handler *Handler) resolve(r *http.Request) (managerapp.RequestContext, error) {
	if handler.options.Resolve == nil {
		return managerapp.RequestContext{}, failure.New(failure.Unauthenticated, "unauthorized")
	}
	return handler.options.Resolve(r)
}

func writeFailure(w http.ResponseWriter, err error) {
	status := http.StatusInternalServerError
	switch failure.KindOf(err) {
	case failure.InvalidArgument, failure.FailedPrecondition:
		status = http.StatusBadRequest
	case failure.Unauthenticated:
		status = http.StatusUnauthorized
	case failure.PermissionDenied:
		status = http.StatusForbidden
	case failure.NotFound:
		status = http.StatusNotFound
	case failure.Conflict:
		status = http.StatusConflict
	}
	http.Error(w, err.Error(), status)
}

func writeJSON(w http.ResponseWriter, value any) {
	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(value); err != nil {
		http.Error(w, fmt.Sprintf("encode response: %v", err), http.StatusInternalServerError)
	}
}
