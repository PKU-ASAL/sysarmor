package managerapi

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	managerauth "github.com/sysarmor/sysarmor-next-project/apps/manager/internal/auth"
	"github.com/sysarmor/sysarmor-next-project/apps/manager/internal/store"
)

func TestHandlerWithAuthAcceptsSignedJWTForProtectedAPI(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	publicDER, err := x509.MarshalPKIXPublicKey(&key.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	verifier, err := managerauth.NewVerifierPEM(
		pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: publicDER}),
		"sysarmor-test", "manager-test",
	)
	if err != nil {
		t.Fatal(err)
	}
	claims := managerauth.Claims{
		RegisteredClaims: jwt.RegisteredClaims{
			Subject: "viewer-a", Issuer: "sysarmor-test",
			Audience:  jwt.ClaimStrings{"manager-test"},
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(time.Hour)),
		},
		TenantID: "tenant-a", Roles: []string{"viewer"},
	}
	raw, err := jwt.NewWithClaims(jwt.SigningMethodRS256, claims).SignedString(key)
	if err != nil {
		t.Fatal(err)
	}
	handler := NewServer(&store.Store{}).HandlerWithAuth(verifier)
	req := httptest.NewRequest(http.MethodGet, "/api/v1/store-status", nil)
	req.Header.Set("Authorization", "Bearer "+raw)
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", rec.Code, rec.Body.String())
	}
}

func TestProtectedHandlerRejectsUnauthenticatedRequest(t *testing.T) {
	handler := NewServer(&store.Store{}).Handler()
	req := httptest.NewRequest(http.MethodGet, "/api/v1/agents", nil)
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusUnauthorized)
	}
	assertAPIError(t, rec, "unauthorized")
}

func TestEnrollmentTokenEndpointsDoNotRequirePrincipal(t *testing.T) {
	handler := NewServer(&store.Store{}).Handler()
	for _, request := range []*http.Request{
		httptest.NewRequest(http.MethodPost, "/api/v1/enrollment-certificate", strings.NewReader(`{"token":"invalid","csr":"invalid"}`)),
		httptest.NewRequest(http.MethodGet, "/api/v1/agent-install.sh?token=invalid", nil),
	} {
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, request)
		if rec.Code == http.StatusUnauthorized {
			t.Fatalf("%s unexpectedly requires principal", request.URL.Path)
		}
	}
}

func TestHandlerRejectsOversizedAnonymousBodyBeforeEndpoint(t *testing.T) {
	handler := NewServer(&store.Store{}).Handler()
	req := httptest.NewRequest(http.MethodPost, "/api/v1/enrollment-certificate", strings.NewReader(`{}`))
	req.ContentLength = maxManagerRequestBody + 1
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusRequestEntityTooLarge {
		t.Fatalf("status = %d, want %d body=%s", rec.Code, http.StatusRequestEntityTooLarge, rec.Body.String())
	}
}

func TestForgedIdentityHeadersDoNotCreatePrincipal(t *testing.T) {
	handler := NewServer(&store.Store{}).Handler()
	req := httptest.NewRequest(http.MethodPost, "/api/v1/reset", nil)
	req.Header.Set("X-SysArmor-Operator-Token", "operator-token")
	req.Header.Set("X-SysArmor-Actor", "forged-admin")
	req.Header.Set("X-SysArmor-Role", "admin")
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusUnauthorized)
	}
}

func TestProductionRouterDoesNotExposeReset(t *testing.T) {
	handler := newAdminTestServer(&store.Store{}).Handler()
	req := httptest.NewRequest(http.MethodPost, "/api/v1/reset", nil)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusNotFound {
		t.Fatalf("reset status = %d, want %d body=%s", rec.Code, http.StatusNotFound, rec.Body.String())
	}
}

func TestBindPrincipalTenantRejectsMismatch(t *testing.T) {
	handler := bindPrincipalTenant(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		t.Fatal("next handler called")
	}))
	req := httptest.NewRequest(http.MethodGet, "/api/v1/agents?tenant_id=tenant-b", nil)
	req = req.WithContext(managerauth.WithPrincipal(req.Context(), managerauth.Principal{Subject: "user", TenantID: "tenant-a", Roles: []string{"viewer"}}))
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("status = %d", rec.Code)
	}
	assertAPIError(t, rec, "forbidden")
}

func assertAPIError(t *testing.T, rec *httptest.ResponseRecorder, code string) {
	t.Helper()
	if got := rec.Header().Get("Content-Type"); got != "application/json; charset=utf-8" {
		t.Fatalf("content-type=%q", got)
	}
	var envelope struct {
		Error struct{ Code, Message string } `json:"error"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &envelope); err != nil {
		t.Fatalf("decode error: %v body=%q", err, rec.Body.String())
	}
	if envelope.Error.Code != code || envelope.Error.Message == "" {
		t.Fatalf("error=%+v", envelope.Error)
	}
}

func TestBindPrincipalTenantInjectsQueryAndJSONBody(t *testing.T) {
	handler := bindPrincipalTenant(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		if r.URL.Query().Get("tenant_id") != "tenant-a" || !strings.Contains(string(body), `"tenant_id":"tenant-a"`) {
			t.Fatalf("request tenant not bound: query=%s body=%s", r.URL.RawQuery, body)
		}
		w.WriteHeader(http.StatusNoContent)
	}))
	req := httptest.NewRequest(http.MethodPost, "/api/v1/policies", strings.NewReader(`{"policy_id":"p1"}`))
	req.Header.Set("Content-Type", "application/json")
	req = req.WithContext(managerauth.WithPrincipal(req.Context(), managerauth.Principal{Subject: "user", TenantID: "tenant-a", Roles: []string{"operator"}}))
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusNoContent {
		t.Fatalf("status = %d", rec.Code)
	}
}

func TestOperatorPrincipalCannotSatisfyAdminRequirement(t *testing.T) {
	server := &Server{}
	req := httptest.NewRequest(http.MethodPost, "/api/v1/admin", nil)
	req = req.WithContext(managerauth.WithPrincipal(req.Context(), managerauth.Principal{Subject: "user", TenantID: "tenant-a", Roles: []string{"operator"}}))
	rec := httptest.NewRecorder()
	allowed := server.requireOperator(rec, req, "admin")
	if allowed || rec.Code != http.StatusForbidden {
		t.Fatalf("operator satisfied admin requirement: allowed=%t status=%d", allowed, rec.Code)
	}
}

func TestProductionServerRequiresSecurityFiles(t *testing.T) {
	t.Setenv("SYSARMOR_ARTIFACT_PUBLIC_KEY", "")
	t.Setenv("SYSARMOR_AGENT_CA_CERT", "")
	t.Setenv("SYSARMOR_AGENT_CA_KEY", "")

	_, err := NewProductionServerWithSearch(&store.Store{}, nil)
	if err == nil || !strings.Contains(err.Error(), "SYSARMOR_ARTIFACT_PUBLIC_KEY") {
		t.Fatalf("NewProductionServerWithSearch error = %v, want artifact public key requirement", err)
	}
}
