package auth

import (
	"context"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"net/http"
	"strings"

	"github.com/golang-jwt/jwt/v5"
)

type Claims struct {
	TenantID string   `json:"tenant_id"`
	Roles    []string `json:"roles"`
	jwt.RegisteredClaims
}

type Principal struct {
	Subject  string
	TenantID string
	Roles    []string
}

func (p Principal) HasRole(role string) bool {
	for _, granted := range p.Roles {
		if granted == role || granted == "admin" {
			return true
		}
	}
	return false
}

type Verifier struct {
	keys     keyProvider
	issuer   string
	audience string
}

type keyProvider interface {
	Key(*jwt.Token) (any, error)
}

type staticKeyProvider struct{ key *rsa.PublicKey }

func (p staticKeyProvider) Key(*jwt.Token) (any, error) { return p.key, nil }

func NewVerifierPEM(publicKey []byte, issuer, audience string) (*Verifier, error) {
	block, _ := pem.Decode(publicKey)
	if block == nil {
		return nil, fmt.Errorf("decode JWT public key PEM")
	}
	parsed, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("parse JWT public key: %w", err)
	}
	key, ok := parsed.(*rsa.PublicKey)
	if !ok {
		return nil, fmt.Errorf("JWT public key must be RSA")
	}
	if strings.TrimSpace(issuer) == "" || strings.TrimSpace(audience) == "" {
		return nil, fmt.Errorf("JWT issuer and audience are required")
	}
	return &Verifier{keys: staticKeyProvider{key: key}, issuer: strings.TrimSpace(issuer), audience: strings.TrimSpace(audience)}, nil
}

func (v *Verifier) Verify(raw string) (Principal, error) {
	if v == nil || v.keys == nil {
		return Principal{}, fmt.Errorf("JWT verifier is not configured")
	}
	claims := &Claims{}
	token, err := jwt.ParseWithClaims(raw, claims, func(token *jwt.Token) (any, error) {
		return v.keys.Key(token)
	}, jwt.WithValidMethods([]string{"RS256"}), jwt.WithIssuer(v.issuer), jwt.WithAudience(v.audience), jwt.WithExpirationRequired())
	if err != nil || !token.Valid {
		return Principal{}, fmt.Errorf("verify JWT: %w", err)
	}
	principal := Principal{Subject: strings.TrimSpace(claims.Subject), TenantID: strings.TrimSpace(claims.TenantID), Roles: recognizedRoles(claims.Roles)}
	if principal.Subject == "" || principal.TenantID == "" || len(principal.Roles) == 0 {
		return Principal{}, fmt.Errorf("JWT subject, tenant_id, and recognized roles are required")
	}
	return principal, nil
}

type principalKey struct{}

func WithPrincipal(ctx context.Context, principal Principal) context.Context {
	return context.WithValue(ctx, principalKey{}, principal)
}

func PrincipalFromContext(ctx context.Context) (Principal, bool) {
	principal, ok := ctx.Value(principalKey{}).(Principal)
	return principal, ok
}

func (v *Verifier) Middleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/healthz" {
			next.ServeHTTP(w, r)
			return
		}
		scheme, raw, ok := strings.Cut(r.Header.Get("Authorization"), " ")
		if !ok || !strings.EqualFold(scheme, "Bearer") || strings.TrimSpace(raw) == "" {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		principal, err := v.Verify(strings.TrimSpace(raw))
		if err != nil {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		next.ServeHTTP(w, r.WithContext(WithPrincipal(r.Context(), principal)))
	})
}

func recognizedRoles(roles []string) []string {
	out := make([]string, 0, len(roles))
	for _, role := range roles {
		switch strings.TrimSpace(role) {
		case "viewer", "operator", "admin":
			out = append(out, strings.TrimSpace(role))
		}
	}
	return out
}
