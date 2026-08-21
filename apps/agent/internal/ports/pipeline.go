package ports

import (
	domaindetection "github.com/sysarmor/sysarmor-next-project/apps/agent/internal/domain/detection"
	domainevent "github.com/sysarmor/sysarmor-next-project/apps/agent/internal/domain/event"
	domainprocess "github.com/sysarmor/sysarmor-next-project/apps/agent/internal/domain/process"
)

type EventDetector interface {
	Process(domainevent.Event) []*domaindetection.Signal
}

type ProfileDetector interface {
	Process(domainprocess.Snapshot) []*domaindetection.Signal
}

type ProfileDetectorIdentity struct {
	Ref     string
	Version string
	Digest  string
}

type IdentifiedProfileDetector interface {
	ProfileDetector
	Identity() ProfileDetectorIdentity
}

type ConditionalProfileDetector interface {
	ProfileDetector
	Enabled() bool
}
