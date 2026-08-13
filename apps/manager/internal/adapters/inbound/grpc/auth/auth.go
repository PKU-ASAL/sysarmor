package auth

import (
	"context"
	"net/url"
	"strings"

	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/peer"
)

type Identity struct {
	TenantID string
	AgentID  string
	Serial   string
}

func TokenAuthorized(ctx context.Context, token string) bool {
	if token == "" {
		return true
	}
	values, ok := metadata.FromIncomingContext(ctx)
	if !ok {
		return false
	}
	for _, value := range append(values.Get("x-sysarmor-agent-token"), values.Get("authorization")...) {
		if value == token || value == "Bearer "+token {
			return true
		}
	}
	return false
}

func PeerIdentity(ctx context.Context) (Identity, bool) {
	value, ok := peer.FromContext(ctx)
	if !ok {
		return Identity{}, false
	}
	info, ok := value.AuthInfo.(credentials.TLSInfo)
	if !ok || len(info.State.PeerCertificates) == 0 {
		return Identity{}, false
	}
	certificate := info.State.PeerCertificates[0]
	for _, uri := range certificate.URIs {
		if identity, ok := identityURI(uri); ok {
			identity.Serial = certificate.SerialNumber.String()
			return identity, true
		}
	}
	parts := strings.SplitN(strings.TrimSpace(certificate.Subject.CommonName), "/", 2)
	if len(parts) != 2 || parts[0] == "" || parts[1] == "" {
		return Identity{}, false
	}
	return Identity{TenantID: parts[0], AgentID: parts[1], Serial: certificate.SerialNumber.String()}, true
}

func identityURI(uri *url.URL) (Identity, bool) {
	parts := strings.Split(strings.Trim(uri.Path, "/"), "/")
	for index := 0; index+3 < len(parts); index++ {
		if parts[index] == "tenant" && parts[index+2] == "agent" && parts[index+1] != "" && parts[index+3] != "" {
			return Identity{TenantID: parts[index+1], AgentID: parts[index+3]}, true
		}
	}
	return Identity{}, false
}
