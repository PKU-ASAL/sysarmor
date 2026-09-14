package system

import (
	"encoding/json"
	"testing"
	"time"

	"github.com/sysarmor/sysarmor-next-project/apps/agent/internal/ports"
)

func TestProfileCapturerCapturesRuntimeSnapshot(t *testing.T) {
	startedAt := time.Unix(42, 0).UTC()
	profile, err := NewProfileCapturer().Capture(t.Context(), ports.ProfileRequest{
		Type: "runtime", Label: "test-profile", StartedAt: startedAt,
	})
	if err != nil {
		t.Fatal(err)
	}
	var payload map[string]any
	if err := json.Unmarshal(profile, &payload); err != nil {
		t.Fatal(err)
	}
	if payload["label"] != "test-profile" || payload["observed_at"] != startedAt.Format(time.RFC3339Nano) {
		t.Fatalf("payload=%+v", payload)
	}
}

func TestProfileCapturerRejectsUnsupportedProfile(t *testing.T) {
	_, err := NewProfileCapturer().Capture(t.Context(), ports.ProfileRequest{Type: "unknown"})
	if err == nil {
		t.Fatal("Capture() error=nil")
	}
}
