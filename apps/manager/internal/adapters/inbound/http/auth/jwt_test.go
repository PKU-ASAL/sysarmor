package auth

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

func TestVerifierAcceptsRS256Principal(t *testing.T) {
	key, verifier := testVerifier(t)
	token := signClaims(t, key, jwt.SigningMethodRS256, Claims{
		RegisteredClaims: jwt.RegisteredClaims{Subject: "operator-a", Issuer: "issuer-a", Audience: jwt.ClaimStrings{"manager-a"}, ExpiresAt: jwt.NewNumericDate(time.Now().Add(time.Hour))},
		TenantID:         "tenant-a", Roles: []string{"viewer"},
	})
	principal, err := verifier.Verify(token)
	if err != nil || principal.Subject != "operator-a" || principal.TenantID != "tenant-a" || !principal.HasRole("viewer") {
		t.Fatalf("Verify() principal=%+v error=%v", principal, err)
	}
}

func TestMiddlewareRequiresBearerAndExemptsHealth(t *testing.T) {
	key, verifier := testVerifier(t)
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/healthz" {
			if _, ok := PrincipalFromContext(r.Context()); !ok {
				t.Fatal("principal missing from context")
			}
		}
		w.WriteHeader(http.StatusNoContent)
	})
	handler := verifier.Middleware(next)

	health := httptest.NewRecorder()
	handler.ServeHTTP(health, httptest.NewRequest(http.MethodGet, "/healthz", nil))
	if health.Code != http.StatusNoContent {
		t.Fatalf("health status = %d", health.Code)
	}
	unauthorized := httptest.NewRecorder()
	handler.ServeHTTP(unauthorized, httptest.NewRequest(http.MethodGet, "/api/v1/agents", nil))
	if unauthorized.Code != http.StatusUnauthorized {
		t.Fatalf("anonymous status = %d", unauthorized.Code)
	}
	claims := Claims{RegisteredClaims: jwt.RegisteredClaims{Subject: "operator-a", Issuer: "issuer-a", Audience: jwt.ClaimStrings{"manager-a"}, ExpiresAt: jwt.NewNumericDate(time.Now().Add(time.Hour))}, TenantID: "tenant-a", Roles: []string{"viewer"}}
	authorized := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/api/v1/agents", nil)
	req.Header.Set("Authorization", "Bearer "+signClaims(t, key, jwt.SigningMethodRS256, claims))
	handler.ServeHTTP(authorized, req)
	if authorized.Code != http.StatusNoContent {
		t.Fatalf("authorized status = %d", authorized.Code)
	}
}

func TestVerifierRejectsInvalidClaims(t *testing.T) {
	key, verifier := testVerifier(t)
	valid := Claims{RegisteredClaims: jwt.RegisteredClaims{Subject: "operator-a", Issuer: "issuer-a", Audience: jwt.ClaimStrings{"manager-a"}, ExpiresAt: jwt.NewNumericDate(time.Now().Add(time.Hour))}, TenantID: "tenant-a", Roles: []string{"viewer"}}
	for _, tc := range []struct {
		name   string
		claims Claims
		method jwt.SigningMethod
	}{{"algorithm", valid, jwt.SigningMethodRS512}, {"issuer", withIssuer(valid, "wrong"), jwt.SigningMethodRS256}, {"tenant", withTenant(valid, ""), jwt.SigningMethodRS256}, {"roles", withRoles(valid, nil), jwt.SigningMethodRS256}} {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := verifier.Verify(signClaims(t, key, tc.method, tc.claims)); err == nil {
				t.Fatal("Verify() error = nil")
			}
		})
	}
}

func testVerifier(t *testing.T) (*rsa.PrivateKey, *Verifier) {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	publicDER, err := x509.MarshalPKIXPublicKey(&key.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	verifier, err := NewVerifierPEM(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: publicDER}), "issuer-a", "manager-a")
	if err != nil {
		t.Fatal(err)
	}
	return key, verifier
}

func signClaims(t *testing.T, key *rsa.PrivateKey, method jwt.SigningMethod, claims Claims) string {
	t.Helper()
	token, err := jwt.NewWithClaims(method, claims).SignedString(key)
	if err != nil {
		t.Fatal(err)
	}
	return token
}

func withIssuer(claims Claims, issuer string) Claims { claims.Issuer = issuer; return claims }
func withTenant(claims Claims, tenant string) Claims { claims.TenantID = tenant; return claims }
func withRoles(claims Claims, roles []string) Claims { claims.Roles = roles; return claims }
