package overview

import (
	"context"
	"encoding/json"
	"net/http"
	"time"

	managerapp "github.com/sysarmor/sysarmor-next-project/apps/manager/internal/application/manager"
	overviewapp "github.com/sysarmor/sysarmor-next-project/apps/manager/internal/application/manager/overview"
	"github.com/sysarmor/sysarmor-next-project/apps/manager/internal/domain/failure"
)

type Service interface {
	Query(context.Context, managerapp.RequestContext) (overviewapp.Result, error)
}

type RequestContextResolver func(*http.Request) (managerapp.RequestContext, error)

type Options struct {
	Service Service
	Resolve RequestContextResolver
}

type Handler struct{ options Options }

func NewHandler(options Options) *Handler { return &Handler{options: options} }

func (handler *Handler) Overview(writer http.ResponseWriter, request *http.Request) {
	if request.Method != http.MethodGet {
		http.Error(writer, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	requestContext, ok := handler.resolve(writer, request)
	if !ok {
		return
	}
	result, err := handler.options.Service.Query(request.Context(), requestContext)
	if err != nil {
		writeFailure(writer, err)
		return
	}
	writeJSON(writer, responseFromResult(result))
}

func (handler *Handler) resolve(writer http.ResponseWriter, request *http.Request) (managerapp.RequestContext, bool) {
	if handler == nil || handler.options.Resolve == nil {
		writeFailure(writer, failure.New(failure.Unauthenticated, "unauthorized"))
		return managerapp.RequestContext{}, false
	}
	requestContext, err := handler.options.Resolve(request)
	if err != nil {
		writeFailure(writer, err)
		return managerapp.RequestContext{}, false
	}
	if handler.options.Service == nil {
		writeFailure(writer, failure.New(failure.Internal, "overview service is not configured"))
		return managerapp.RequestContext{}, false
	}
	return requestContext, true
}

type overviewResponse struct {
	GeneratedAt time.Time           `json:"generated_at"`
	Agents      agentsResponse      `json:"agents"`
	Telemetry   telemetryResponse   `json:"telemetry"`
	Incidents   incidentsResponse   `json:"incidents"`
	Store       storeStatusResponse `json:"store"`
}

type agentsResponse struct {
	Total    int `json:"total"`
	Online   int `json:"online"`
	Degraded int `json:"degraded"`
	Offline  int `json:"offline"`
}

type telemetryResponse struct {
	Events24h  uint64 `json:"events_24h"`
	Signals24h uint64 `json:"signals_24h"`
}

type incidentsResponse struct {
	Open     int `json:"open"`
	Critical int `json:"critical"`
	High     int `json:"high"`
	Medium   int `json:"medium"`
}

type storeStatusResponse struct {
	Backend               string `json:"backend"`
	StateVersion          int    `json:"state_version,omitempty"`
	MigrationVersion      int    `json:"migration_version,omitempty"`
	PostgresSchemaVersion int    `json:"postgres_schema_version,omitempty"`
}

func responseFromResult(result overviewapp.Result) overviewResponse {
	return overviewResponse{GeneratedAt: time.Now().UTC(),
		Agents: agentsResponse{Total: result.Agents.Total, Online: result.Agents.Online,
			Degraded: result.Agents.Degraded, Offline: result.Agents.Offline},
		Telemetry: telemetryResponse{Events24h: result.Telemetry.Events24h, Signals24h: result.Telemetry.Signals24h},
		Incidents: incidentsResponse{Open: result.Incidents.Open, Critical: result.Incidents.Critical,
			High: result.Incidents.High, Medium: result.Incidents.Medium},
		Store: storeStatusResponse{Backend: result.Storage.Backend, StateVersion: result.Storage.StateVersion,
			MigrationVersion: result.Storage.MigrationVersion, PostgresSchemaVersion: result.Storage.PostgresSchemaVersion}}
}

func writeJSON(writer http.ResponseWriter, value any) {
	writer.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(writer).Encode(value)
}

func writeFailure(writer http.ResponseWriter, err error) {
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
	case failure.RetryableDependency:
		status = http.StatusBadGateway
	}
	http.Error(writer, err.Error(), status)
}
