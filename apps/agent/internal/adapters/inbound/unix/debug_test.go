package localapi

import (
	"context"
	"testing"
	"time"

	appdiagnostics "github.com/sysarmor/sysarmor-next-project/apps/agent/internal/application/diagnostics"
	controlplanev1 "github.com/sysarmor/sysarmor-next-project/packages/contracts/proto/controlplane/v1"
)

type diagnosticsService struct {
	request appdiagnostics.Request
}

func (s *diagnosticsService) Capture(_ context.Context, request appdiagnostics.Request) (appdiagnostics.Result, error) {
	s.request = request
	return appdiagnostics.Result{
		Request: request, StartedAt: time.Unix(42, 0).UTC(), FinishedAt: time.Unix(43, 0).UTC(), Profile: []byte("profile"),
	}, nil
}

func TestHandlerDebugProfileDelegatesToApplication(t *testing.T) {
	service := &diagnosticsService{}
	handler := NewHandler(Dependencies{Diagnostics: service})
	response, err := handler.DebugProfile(t.Context(), &controlplanev1.DebugProfileRequest{
		ProfileType: "runtime", Seconds: 2, Label: "test-profile",
	})
	if err != nil {
		t.Fatal(err)
	}
	if service.request.Type != "runtime" || service.request.Seconds != 2 || service.request.Label != "test-profile" {
		t.Fatalf("request=%+v", service.request)
	}
	if response.GetProfileType() != "runtime" || response.GetStartedAt() != "1970-01-01T00:00:42Z" || string(response.GetProfile()) != "profile" {
		t.Fatalf("response=%+v", response)
	}
}
