package ports

import (
	"context"
	"time"
)

type ProfileRequest struct {
	Type      string
	Seconds   uint32
	Label     string
	StartedAt time.Time
}

type ProfileCapturer interface {
	Capture(context.Context, ProfileRequest) ([]byte, error)
}
