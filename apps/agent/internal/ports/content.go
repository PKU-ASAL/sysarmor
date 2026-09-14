package ports

import (
	"context"

	domaincontent "github.com/sysarmor/sysarmor-next-project/apps/agent/internal/domain/content"
)

type ContentRepository interface {
	Validate(document string, allowUnsigned bool) (domaincontent.Record, error)
	Prepare(document string, allowUnsigned bool) (domaincontent.Record, domaincontent.Snapshot, error)
	Commit(record domaincontent.Record) error
	List(kind string) []domaincontent.Record
	Get(ref string) (domaincontent.Record, bool)
}

type ContentRuntime interface {
	BuildDetection(snapshot domaincontent.Snapshot) (DetectionBuild, error)
	ActivateDetection(snapshot domaincontent.Snapshot, built DetectionBuild)
}

type DetectionBuild interface {
	DetectionReport() DetectionReport
}

type DetectionReport struct {
	Status   string
	Warnings []string
	Details  []string
}

type ContentMutation interface {
	Begin(context.Context, bool) (func(), error)
}
