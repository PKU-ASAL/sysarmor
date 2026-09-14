package localapi

import (
	"context"
	"fmt"
	"time"

	appdiagnostics "github.com/sysarmor/sysarmor-next-project/apps/agent/internal/application/diagnostics"
	controlplanev1 "github.com/sysarmor/sysarmor-next-project/packages/contracts/proto/controlplane/v1"
)

func (h *Handler) DebugProfile(ctx context.Context, req *controlplanev1.DebugProfileRequest) (*controlplanev1.DebugProfileResponse, error) {
	if err := h.validate(req.GetContext()); err != nil {
		return nil, err
	}
	if h.deps.Diagnostics == nil {
		return nil, fmt.Errorf("local api diagnostics handler is unavailable")
	}
	result, err := h.deps.Diagnostics.Capture(ctx, appdiagnostics.Request{
		Type: req.GetProfileType(), Seconds: req.GetSeconds(), Label: req.GetLabel(),
	})
	if err != nil {
		return nil, err
	}
	return &controlplanev1.DebugProfileResponse{
		ProfileType: result.Type, Seconds: result.Seconds, StartedAt: result.StartedAt.Format(time.RFC3339Nano),
		FinishedAt: result.FinishedAt.Format(time.RFC3339Nano), Profile: result.Profile, Label: result.Label,
	}, nil
}
