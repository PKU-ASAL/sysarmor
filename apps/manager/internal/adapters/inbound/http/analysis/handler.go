package analysis

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"

	contractmapper "github.com/sysarmor/sysarmor-next-project/apps/manager/internal/adapters/contracts"
	managerapp "github.com/sysarmor/sysarmor-next-project/apps/manager/internal/application/manager"
	analysisapp "github.com/sysarmor/sysarmor-next-project/apps/manager/internal/application/manager/analysis"
	"github.com/sysarmor/sysarmor-next-project/apps/manager/internal/domain/failure"
	domainpolicy "github.com/sysarmor/sysarmor-next-project/apps/manager/internal/domain/policy"
	domaintelemetry "github.com/sysarmor/sysarmor-next-project/apps/manager/internal/domain/telemetry"
	"google.golang.org/protobuf/encoding/protojson"
)

type Service interface {
	Recompute(context.Context, managerapp.RequestContext, analysisapp.Query) (domaintelemetry.Analysis, error)
}

type RequestContextResolver func(*http.Request) (managerapp.RequestContext, error)

type Options struct {
	Service Service
	Resolve RequestContextResolver
}

type Handler struct{ options Options }

func NewHandler(options Options) *Handler { return &Handler{options: options} }

func (handler *Handler) Recompute(writer http.ResponseWriter, request *http.Request) {
	if request.Method != http.MethodGet {
		http.Error(writer, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	requestContext, ok := handler.resolve(writer, request)
	if !ok {
		return
	}
	query := request.URL.Query()
	result, err := handler.options.Service.Recompute(request.Context(), requestContext, analysisapp.Query{
		Target: domainpolicy.Target{AgentID: query.Get("agent_id"), ScopeType: query.Get("scope_type"), ScopeSelector: query.Get("scope_selector")},
		Labels: parseLabels(query["label"]), Disable: query.Get("disable"), Mode: query.Get("mode"),
	})
	if err != nil {
		writeFailure(writer, err)
		return
	}
	if err := writeResult(writer, result); err != nil {
		http.Error(writer, fmt.Sprintf("encode analysis result: %v", err), http.StatusInternalServerError)
	}
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
		http.Error(writer, "analysis application is not configured", http.StatusServiceUnavailable)
		return managerapp.RequestContext{}, false
	}
	return requestContext, true
}

func writeResult(writer http.ResponseWriter, result domaintelemetry.Analysis) error {
	cloud := make([]json.RawMessage, 0, len(result.CloudSignals))
	for _, signal := range result.CloudSignals {
		raw, err := protojson.MarshalOptions{UseProtoNames: true}.Marshal(contractmapper.SignalFromDomain(signal))
		if err != nil {
			return err
		}
		cloud = append(cloud, raw)
	}
	incidents := make([]json.RawMessage, 0, len(result.Incidents))
	for _, incident := range result.Incidents {
		raw, err := protojson.MarshalOptions{UseProtoNames: true}.Marshal(contractmapper.IncidentFromDomain(incident))
		if err != nil {
			return err
		}
		incidents = append(incidents, raw)
	}
	writer.Header().Set("Content-Type", "application/json")
	return json.NewEncoder(writer).Encode(map[string]any{"cloud_signals": cloud, "incidents": incidents})
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
	case failure.RetryableDependency:
		status = http.StatusBadGateway
	}
	http.Error(writer, err.Error(), status)
}

func parseLabels(values []string) map[string]string {
	result := make(map[string]string)
	for _, raw := range values {
		key, value, ok := strings.Cut(raw, "=")
		key, value = strings.TrimSpace(key), strings.TrimSpace(value)
		if ok && key != "" {
			result[key] = value
		}
	}
	return result
}
