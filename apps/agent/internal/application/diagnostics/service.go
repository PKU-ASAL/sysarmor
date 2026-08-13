package diagnostics

import (
	"context"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/sysarmor/sysarmor-next-project/apps/agent/internal/ports"
)

type Request struct {
	Type    string
	Seconds uint32
	Label   string
}

type Result struct {
	Request
	StartedAt  time.Time
	FinishedAt time.Time
	Profile    []byte
}

type Service struct {
	capturer ports.ProfileCapturer
	now      func() time.Time
	mu       sync.Mutex
	running  bool
}

func NewService(capturer ports.ProfileCapturer) *Service {
	return &Service{capturer: capturer, now: func() time.Time { return time.Now().UTC() }}
}

func (s *Service) Capture(ctx context.Context, request Request) (Result, error) {
	request, err := normalize(request)
	if err != nil {
		return Result{}, err
	}
	if !s.begin() {
		return Result{}, fmt.Errorf("debug profile already running")
	}
	defer s.end()
	started := s.now()
	profile, err := s.capturer.Capture(ctx, ports.ProfileRequest{
		Type: request.Type, Seconds: request.Seconds, Label: request.Label, StartedAt: started,
	})
	if err != nil {
		return Result{}, err
	}
	return Result{Request: request, StartedAt: started, FinishedAt: s.now(), Profile: profile}, nil
}

func (s *Service) begin() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.running {
		return false
	}
	s.running = true
	return true
}

func (s *Service) end() {
	s.mu.Lock()
	s.running = false
	s.mu.Unlock()
}

func normalize(request Request) (Request, error) {
	request.Type = strings.TrimSpace(request.Type)
	if request.Type == "" {
		request.Type = "cpu"
	}
	switch request.Type {
	case "cpu", "heap", "allocs", "goroutine", "threadcreate", "block", "mutex", "runtime":
	default:
		return Request{}, fmt.Errorf("unsupported debug profile type %q", request.Type)
	}
	if request.Seconds == 0 {
		request.Seconds = 10
	}
	if request.Seconds > 300 {
		return Request{}, fmt.Errorf("debug profile seconds must be <= 300")
	}
	request.Label = strings.TrimSpace(request.Label)
	return request, nil
}
