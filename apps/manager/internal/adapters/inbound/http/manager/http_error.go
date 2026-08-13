package managerapi

import (
	"encoding/json"
	"net/http"
	"strings"
)

type apiErrorEnvelope struct {
	Error struct {
		Code    string `json:"code"`
		Message string `json:"message"`
	} `json:"error"`
}

func writeAPIError(w http.ResponseWriter, status int, code, message string) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	envelope := apiErrorEnvelope{}
	envelope.Error.Code = code
	envelope.Error.Message = message
	_ = json.NewEncoder(w).Encode(envelope)
}

func normalizeAPIErrors(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		writer := &apiErrorWriter{ResponseWriter: w}
		next.ServeHTTP(writer, r)
		writer.flushPending()
	})
}

type apiErrorWriter struct {
	http.ResponseWriter
	pendingStatus int
}

func (w *apiErrorWriter) WriteHeader(status int) {
	if status >= 400 && strings.HasPrefix(w.Header().Get("Content-Type"), "text/plain") {
		w.pendingStatus = status
		return
	}
	w.ResponseWriter.WriteHeader(status)
}

func (w *apiErrorWriter) Write(body []byte) (int, error) {
	if w.pendingStatus != 0 {
		status := w.pendingStatus
		w.pendingStatus = 0
		code, fallback := errorIdentity(status)
		message := strings.TrimSpace(string(body))
		if status >= 500 || message == "" {
			message = fallback
		}
		w.Header().Del("Content-Length")
		writeAPIError(w.ResponseWriter, status, code, message)
		return len(body), nil
	}
	return w.ResponseWriter.Write(body)
}

func (w *apiErrorWriter) flushPending() {
	if w.pendingStatus == 0 {
		return
	}
	status := w.pendingStatus
	w.pendingStatus = 0
	code, message := errorIdentity(status)
	w.Header().Del("Content-Length")
	writeAPIError(w.ResponseWriter, status, code, message)
}

func errorIdentity(status int) (string, string) {
	switch status {
	case http.StatusBadRequest:
		return "invalid_request", "Invalid request"
	case http.StatusUnauthorized:
		return "unauthorized", "Unauthorized"
	case http.StatusForbidden:
		return "forbidden", "Forbidden"
	case http.StatusNotFound:
		return "not_found", "Not found"
	case http.StatusMethodNotAllowed:
		return "method_not_allowed", "Method not allowed"
	case http.StatusRequestEntityTooLarge:
		return "request_too_large", "Request body too large"
	default:
		return "request_failed", "Request failed"
	}
}
