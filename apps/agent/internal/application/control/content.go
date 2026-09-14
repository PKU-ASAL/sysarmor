package control

import (
	"context"
	"fmt"
	"strings"
)

type ContentRecord struct {
	Ref, Kind, Version, Digest, Status, RawJSON string
	Signed                                      bool
}

type ContentApplyReport struct {
	Status   string
	Warnings []string
}

type ContentCommand struct {
	Context       RequestContext
	Document      string
	DryRun        bool
	AllowUnsigned bool
	Source        PolicySource
}

type ContentController interface {
	ApplyContent(context.Context, ContentCommand) Result
	ListContent(context.Context, string) ([]ContentRecord, error)
	GetContent(context.Context, string) (ContentRecord, bool, error)
}

type ContentIdentity struct {
	TenantID string
	AgentID  string
}

type ContentApplication interface {
	ContentIdentity() ContentIdentity
	BeginLocalContentMutation(context.Context, bool) (func(), error)
	ValidateContentContext(RequestContext) error
	ValidateContent(string, bool) (ContentRecord, error)
	Activate(string, bool) (ContentRecord, ContentApplyReport, error)
	ListContent(string) []ContentRecord
	GetContent(string) (ContentRecord, bool)
}

type contentController struct {
	application ContentApplication
}

func NewContentController(application ContentApplication) ContentController {
	return &contentController{application: application}
}

func (c *contentController) ApplyContent(ctx context.Context, command ContentCommand) Result {
	identity := c.application.ContentIdentity()
	if command.Source != PolicySourceManaged {
		release, err := c.application.BeginLocalContentMutation(ctx, !command.DryRun)
		if err != nil {
			return rejectedContentResult(identity, command.Context.RequestID, err.Error())
		}
		defer release()
	}
	if err := c.application.ValidateContentContext(command.Context); err != nil {
		return rejectedContentResult(identity, command.Context.RequestID, err.Error())
	}
	if command.DryRun {
		return c.validateContent(command, identity)
	}
	return c.activateContent(ctx, command, identity)
}

func (c *contentController) validateContent(command ContentCommand, identity ContentIdentity) Result {
	record, err := c.application.ValidateContent(command.Document, command.AllowUnsigned)
	if err != nil {
		return rejectedContentResult(identity, command.Context.RequestID, err.Error())
	}
	record.Status = "validated"
	return appliedContentResult(identity, command.Context.RequestID, record, ContentApplyReport{})
}

func (c *contentController) activateContent(ctx context.Context, command ContentCommand, identity ContentIdentity) Result {
	record, report, err := c.application.Activate(command.Document, command.AllowUnsigned)
	if err != nil {
		return rejectedContentResult(identity, command.Context.RequestID, err.Error())
	}
	return appliedContentResult(identity, command.Context.RequestID, record, report)
}

func (c *contentController) ListContent(_ context.Context, kind string) ([]ContentRecord, error) {
	return c.application.ListContent(strings.TrimSpace(kind)), nil
}

func (c *contentController) GetContent(_ context.Context, ref string) (ContentRecord, bool, error) {
	record, ok := c.application.GetContent(strings.TrimSpace(ref))
	return record, ok, nil
}

func rejectedContentResult(identity ContentIdentity, requestID, message string) Result {
	return Result{
		RequestID: requestID, TenantID: identity.TenantID, AgentID: identity.AgentID,
		Status: "rejected", Message: message,
		Sections: []SectionResult{{Name: "content", Status: "rejected", Message: message}},
	}
}

func appliedContentResult(identity ContentIdentity, requestID string, record ContentRecord, report ContentApplyReport) Result {
	status := record.Status
	if report.Status == "degraded" {
		status = "degraded"
	}
	message := fmt.Sprintf("content %s %s@%s digest=%s", status, record.Ref, record.Version, record.Digest)
	if len(report.Warnings) > 0 {
		message += "; detection dependencies degraded: " + strings.Join(report.Warnings, "; ")
	}
	return Result{
		RequestID: requestID, TenantID: identity.TenantID, AgentID: identity.AgentID,
		Status: status, Message: message, PolicyID: record.Ref,
		Sections: []SectionResult{{Name: "content", Status: status, Message: message}},
	}
}
