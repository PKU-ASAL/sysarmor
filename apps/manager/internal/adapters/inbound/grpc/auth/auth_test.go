package auth

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"math/big"
	"net/url"
	"testing"

	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/peer"
)

func TestTokenAuthorizerAcceptsHeaderAndBearer(t *testing.T) {
	values := [][2]string{{"x-sysarmor-agent-token", "secret"}, {"authorization", "Bearer secret"}}
	for _, item := range values {
		ctx := metadata.NewIncomingContext(context.Background(), metadata.Pairs(item[0], item[1]))
		if !TokenAuthorized(ctx, "secret") {
			t.Fatalf("header %s was rejected", item[0])
		}
	}
	if TokenAuthorized(context.Background(), "secret") {
		t.Fatal("missing token was accepted")
	}
}

func TestPeerIdentityReadsSPIFFEURIAndSerial(t *testing.T) {
	uri, _ := url.Parse("spiffe://sysarmor/tenant/tenant-a/agent/agent-a")
	certificate := &x509.Certificate{SerialNumber: big.NewInt(42), URIs: []*url.URL{uri}}
	ctx := peer.NewContext(context.Background(), &peer.Peer{AuthInfo: credentials.TLSInfo{State: tls.ConnectionState{PeerCertificates: []*x509.Certificate{certificate}}}})
	identity, ok := PeerIdentity(ctx)
	if !ok || identity.TenantID != "tenant-a" || identity.AgentID != "agent-a" || identity.Serial != "42" {
		t.Fatalf("identity = %+v, ok = %t", identity, ok)
	}
}
