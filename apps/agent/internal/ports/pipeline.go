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
