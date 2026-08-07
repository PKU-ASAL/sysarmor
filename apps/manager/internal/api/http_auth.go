package managerapi

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"strings"

	managerauth "github.com/sysarmor/sysarmor-next-project/apps/manager/internal/auth"
)

const maxAuthenticatedBody = 4 << 20
const maxManagerRequestBody = 128 << 20

func (s *Server) HandlerWithAuth(verifier *managerauth.Verifier) http.Handler {
	base := s.Handler()
	protected := verifier.Middleware(bindPrincipalTenant(base))
	return normalizeAPIErrors(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if isEnrollmentTokenEndpoint(r.URL.Path) {
			base.ServeHTTP(w, r)
			return
		}
		protected.ServeHTTP(w, r)
	}))
}

func bindPrincipalTenant(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/healthz" || isEnrollmentTokenEndpoint(r.URL.Path) {
			next.ServeHTTP(w, r)
			return
		}
		principal, ok := managerauth.PrincipalFromContext(r.Context())
		if !ok {
			writeAPIError(w, http.StatusUnauthorized, "unauthorized", "Unauthorized")
			return
		}
		query := r.URL.Query()
		if tenant := query.Get("tenant_id"); tenant != "" && tenant != principal.TenantID {
			writeAPIError(w, http.StatusForbidden, "forbidden", "Forbidden")
			return
		}
		query.Set("tenant_id", principal.TenantID)
		r.URL.RawQuery = query.Encode()
		if !bindJSONTenant(w, r, principal.TenantID) {
			return
		}
		next.ServeHTTP(w, r)
	})
}

func requestTenantID(r *http.Request) string {
	if principal, ok := managerauth.PrincipalFromContext(r.Context()); ok {
		return strings.TrimSpace(principal.TenantID)
	}
	return strings.TrimSpace(r.URL.Query().Get("tenant_id"))
}

func limitRequestBody(next http.Handler, maxBytes int64) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if maxBytes > 0 && r.Body != nil {
			if r.ContentLength > maxBytes {
				writeAPIError(w, http.StatusRequestEntityTooLarge, "request_too_large", "Request body too large")
				return
			}
			r.Body = http.MaxBytesReader(w, r.Body, maxBytes)
		}
		next.ServeHTTP(w, r)
	})
}

func requireProductionPrincipal(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/healthz" || isEnrollmentTokenEndpoint(r.URL.Path) {
			next.ServeHTTP(w, r)
			return
		}
		if _, ok := managerauth.PrincipalFromContext(r.Context()); !ok {
			writeAPIError(w, http.StatusUnauthorized, "unauthorized", "Unauthorized")
			return
		}
		next.ServeHTTP(w, r)
	})
}

func isEnrollmentTokenEndpoint(path string) bool {
	return path == "/api/v1/enrollment-artifact" || path == "/api/v1/enrollment-certificate" ||
		path == "/api/v1/unenrollment-completions" || path == "/api/v1/agent-install.sh"
}

func bindJSONTenant(w http.ResponseWriter, r *http.Request, tenantID string) bool {
	if r.Body == nil || !strings.Contains(r.Header.Get("Content-Type"), "application/json") {
		return true
	}
	raw, err := io.ReadAll(io.LimitReader(r.Body, maxAuthenticatedBody+1))
	if err != nil || len(raw) > maxAuthenticatedBody {
		writeAPIError(w, http.StatusRequestEntityTooLarge, "request_too_large", "Request body too large")
		return false
	}
	if len(bytes.TrimSpace(raw)) == 0 {
		r.Body = io.NopCloser(bytes.NewReader(raw))
		return true
	}
	var object map[string]any
	if json.Unmarshal(raw, &object) != nil {
		r.Body = io.NopCloser(bytes.NewReader(raw))
		return true
	}
	if tenant, _ := object["tenant_id"].(string); tenant != "" && tenant != tenantID {
		writeAPIError(w, http.StatusForbidden, "forbidden", "Forbidden")
		return false
	}
	object["tenant_id"] = tenantID
	bound, err := json.Marshal(object)
	if err != nil {
		writeAPIError(w, http.StatusBadRequest, "invalid_request", "Invalid request")
		return false
	}
	r.Body = io.NopCloser(bytes.NewReader(bound))
	r.ContentLength = int64(len(bound))
	return true
}
