package diagnostics

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/sysarmor/sysarmor-next-project/apps/agent/internal/ports"
)

type blockingCapturer struct {
	started chan struct{}
	release chan struct{}
}

func (c *blockingCapturer) Capture(context.Context, ports.ProfileRequest) ([]byte, error) {
	close(c.started)
	<-c.release
	return []byte("profile"), nil
}

func TestServiceRejectsConcurrentProfile(t *testing.T) {
	capturer := &blockingCapturer{started: make(chan struct{}), release: make(chan struct{})}
	service := NewService(capturer)
	done := make(chan error, 1)
	go func() {
		_, err := service.Capture(t.Context(), Request{Type: "runtime"})
		done <- err
	}()
	<-capturer.started
	_, err := service.Capture(t.Context(), Request{Type: "runtime"})
	if err == nil || !strings.Contains(err.Error(), "already running") {
		t.Fatalf("err=%v", err)
	}
	close(capturer.release)
	if err := <-done; err != nil {
		t.Fatal(err)
	}
}

func TestServiceNormalizesAndValidatesRequest(t *testing.T) {
	service := NewService(&recordingCapturer{})
	result, err := service.Capture(t.Context(), Request{Label: " test "})
	if err != nil || result.Type != "cpu" || result.Seconds != 10 || result.Label != "test" {
		t.Fatalf("result=%+v err=%v", result, err)
	}
	if _, err := service.Capture(t.Context(), Request{Type: "cpu", Seconds: 301}); err == nil {
		t.Fatal("Capture() error=nil")
	}
}

type recordingCapturer struct{}

func (*recordingCapturer) Capture(context.Context, ports.ProfileRequest) ([]byte, error) {
	return []byte("profile"), nil
}

func TestServiceRecordsCaptureWindow(t *testing.T) {
	service := NewService(&recordingCapturer{})
	service.now = func() time.Time { return time.Unix(42, 0).UTC() }
	result, err := service.Capture(t.Context(), Request{Type: "heap", Seconds: 1})
	if err != nil || !result.StartedAt.Equal(time.Unix(42, 0).UTC()) || !result.FinishedAt.Equal(result.StartedAt) {
		t.Fatalf("result=%+v err=%v", result, err)
	}
}
