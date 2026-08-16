package telemetry

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"
	"strings"

	managerapp "github.com/sysarmor/sysarmor-next-project/apps/manager/internal/application/manager"
	telemetryapp "github.com/sysarmor/sysarmor-next-project/apps/manager/internal/application/manager/telemetry"
	"github.com/sysarmor/sysarmor-next-project/apps/manager/internal/domain/failure"
	domaintelemetry "github.com/sysarmor/sysarmor-next-project/apps/manager/internal/domain/telemetry"
)

type Service interface {
	Events(context.Context, managerapp.RequestContext, telemetryapp.EventQuery) ([]domaintelemetry.Document, error)
	Signals(context.Context, managerapp.RequestContext, telemetryapp.SignalQuery) ([]domaintelemetry.Document, error)
	Incidents(context.Context, managerapp.RequestContext, telemetryapp.IncidentQuery) ([]domaintelemetry.Document, error)
}

type RequestContextResolver func(*http.Request) (managerapp.RequestContext, error)

type Options struct {
	Service Service
	Resolve RequestContextResolver
}

type Handler struct{ options Options }

func NewHandler(options Options) *Handler { return &Handler{options: options} }

func (handler *Handler) Events(writer http.ResponseWriter, request *http.Request) {
	if request.Method != http.MethodGet {
		http.Error(writer, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	requestContext, ok := handler.resolve(writer, request)
	if !ok {
		return
	}
	query := request.URL.Query()
	values, err := handler.options.Service.Events(request.Context(), requestContext, telemetryapp.EventQuery{
		Labels: parseLabels(query["label"]), Behavior: query.Get("behavior"),
		Limit: parseNonNegative(query.Get("limit")), Offset: parseNonNegative(query.Get("offset")),
	})
	writeDocuments(writer, values, err)
}

func (handler *Handler) Signals(writer http.ResponseWriter, request *http.Request) {
	if request.Method != http.MethodGet {
		http.Error(writer, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	requestContext, ok := handler.resolve(writer, request)
	if !ok {
		return
	}
	query := request.URL.Query()
	stage, err := parseSignalStage(query.Get("stage"))
	if err != nil {
		writeFailure(writer, err)
		return
	}
	values, err := handler.options.Service.Signals(request.Context(), requestContext, telemetryapp.SignalQuery{
		Labels: parseLabels(query["label"]), Layer: query.Get("layer"), Stage: stage,
		Limit: parseNonNegative(query.Get("limit")), Offset: parseNonNegative(query.Get("offset")),
	})
	writeDocuments(writer, values, err)
}

func (handler *Handler) Incidents(writer http.ResponseWriter, request *http.Request) {
	if request.Method != http.MethodGet {
		http.Error(writer, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	requestContext, ok := handler.resolve(writer, request)
	if !ok {
		return
	}
	query := request.URL.Query()
	id := strings.TrimSpace(query.Get("incident_id"))
	values, err := handler.options.Service.Incidents(request.Context(), requestContext, telemetryapp.IncidentQuery{
		Labels: parseLabels(query["label"]), ID: id, Limit: parseNonNegative(query.Get("limit")),
		Offset: parseNonNegative(query.Get("offset")),
	})
	if err != nil {
		writeFailure(writer, err)
		return
	}
	if id != "" {
		if len(values) == 0 {
			http.Error(writer, "incident report not found", http.StatusNotFound)
			return
		}
		writer.Header().Set("Content-Type", "application/json")
		_, _ = writer.Write(values[0])
		return
	}
	writeDocuments(writer, values, nil)
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
		writeFailure(writer, failure.New(failure.Internal, "telemetry service is not configured"))
		return managerapp.RequestContext{}, false
	}
	return requestContext, true
}

func writeDocuments(writer http.ResponseWriter, values []domaintelemetry.Document, err error) {
	if err != nil {
		writeFailure(writer, err)
		return
	}
	raw := make([]json.RawMessage, 0, len(values))
	for _, value := range values {
		raw = append(raw, json.RawMessage(value))
	}
	writer.Header().Set("Content-Type", "application/json")
	if encodeErr := json.NewEncoder(writer).Encode(raw); encodeErr != nil {
		http.Error(writer, fmt.Sprintf("encode response: %v", encodeErr), http.StatusInternalServerError)
	}
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

func parseLabels(values []string) map[string]string {
	result := map[string]string{}
	for _, raw := range values {
		key, value, ok := strings.Cut(raw, "=")
		key, value = strings.TrimSpace(key), strings.TrimSpace(value)
		if ok && key != "" {
			result[key] = value
		}
	}
	return result
}

func parseNonNegative(raw string) int {
	value, err := strconv.Atoi(strings.TrimSpace(raw))
	if err != nil || value < 0 {
		return 0
	}
	return value
}

func parseSignalStage(raw string) (*domaintelemetry.SignalStage, error) {
	switch strings.ToLower(strings.TrimSpace(raw)) {
	case "":
		return nil, nil
	case "candidate":
		value := domaintelemetry.SignalStageCandidate
		return &value, nil
	case "conclusion":
		value := domaintelemetry.SignalStageConclusion
		return &value, nil
	default:
		return nil, failure.New(failure.InvalidArgument, "signal stage must be candidate or conclusion")
	}
}
