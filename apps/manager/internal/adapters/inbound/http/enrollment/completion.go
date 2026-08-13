package enrollment

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strings"

	enrollmentapp "github.com/sysarmor/sysarmor-next-project/apps/manager/internal/application/manager/enrollment"
	domainenrollment "github.com/sysarmor/sysarmor-next-project/apps/manager/internal/domain/enrollment"
	"github.com/sysarmor/sysarmor-next-project/apps/manager/internal/domain/failure"
	"github.com/sysarmor/sysarmor-next-project/apps/manager/internal/domain/tenant"
)

const maxCompletionBody = 16 << 10

type completionRequest struct {
	SchemaVersion     string `json:"schema_version"`
	TenantID          string `json:"tenant_id"`
	AgentID           string `json:"agent_id"`
	EnrollmentID      string `json:"enrollment_id"`
	CertificateSerial string `json:"certificate_serial"`
	RevocationReceipt string `json:"revocation_receipt"`
	CompletionToken   string `json:"completion_token"`
}

func (handler *Handler) Completion(writer http.ResponseWriter, request *http.Request) {
	if request.Method != http.MethodPost {
		http.Error(writer, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	input, err := decodeCompletion(request.Body)
	if err != nil {
		writeAPIError(writer, http.StatusBadRequest, "invalid_request", "Invalid request")
		return
	}
	command, err := completionCommand(input)
	if err != nil {
		writeAPIError(writer, http.StatusBadRequest, "invalid_request", "Invalid request")
		return
	}
	result, err := handler.completion.Execute(request.Context(), command)
	if err != nil {
		writeCompletionError(writer, err)
		return
	}
	writeJSON(writer, map[string]any{"status": result.Unenrollment.Status, "endpoint_completed_at": result.Unenrollment.CompletedAt})
}

func decodeCompletion(body io.Reader) (completionRequest, error) {
	raw, err := io.ReadAll(io.LimitReader(body, maxCompletionBody+1))
	if err != nil || len(raw) > maxCompletionBody {
		return completionRequest{}, errors.New("invalid completion body")
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	var value completionRequest
	if err := decoder.Decode(&value); err != nil || decoder.Decode(&struct{}{}) != io.EOF {
		return completionRequest{}, errors.New("invalid completion document")
	}
	if value.SchemaVersion != "sysarmor.unenrollment-completion/v1" {
		return completionRequest{}, errors.New("invalid completion schema")
	}
	return value, nil
}

func completionCommand(input completionRequest) (enrollmentapp.CompleteUnenrollmentCommand, error) {
	tenantID, err := tenant.NewID(input.TenantID)
	if err != nil {
		return enrollmentapp.CompleteUnenrollmentCommand{}, err
	}
	values := []string{input.AgentID, input.EnrollmentID, input.CertificateSerial, input.RevocationReceipt, input.CompletionToken}
	for _, value := range values {
		if strings.TrimSpace(value) == "" {
			return enrollmentapp.CompleteUnenrollmentCommand{}, errors.New("completion identity is incomplete")
		}
	}
	return enrollmentapp.CompleteUnenrollmentCommand{Identity: domainenrollment.UnenrollmentIdentity{
		TenantID: tenantID, AgentID: strings.TrimSpace(input.AgentID), EnrollmentID: strings.TrimSpace(input.EnrollmentID),
		CertificateSerial: strings.TrimSpace(input.CertificateSerial),
	}, Receipt: strings.TrimSpace(input.RevocationReceipt), TokenHash: hashToken(input.CompletionToken)}, nil
}

func writeCompletionError(writer http.ResponseWriter, err error) {
	if kind := failure.KindOf(err); kind == failure.Conflict || kind == failure.NotFound {
		writeAPIError(writer, http.StatusUnauthorized, "unauthorized", "Unauthorized")
		return
	}
	writeAPIError(writer, http.StatusInternalServerError, "store_error", "Store operation failed")
}

func writeAPIError(writer http.ResponseWriter, status int, code, message string) {
	writer.Header().Set("Content-Type", "application/json")
	writer.WriteHeader(status)
	_ = json.NewEncoder(writer).Encode(map[string]any{"error": map[string]string{"code": code, "message": message}})
}

func writeJSON(writer http.ResponseWriter, value any) {
	writer.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(writer).Encode(value)
}
