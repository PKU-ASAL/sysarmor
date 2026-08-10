package bootstrap

import (
	"context"

	controlpostgres "github.com/sysarmor/sysarmor-next-project/apps/manager/internal/adapters/outbound/postgres/control"
	controlapp "github.com/sysarmor/sysarmor-next-project/apps/manager/internal/application/manager/control"
	domaincontrol "github.com/sysarmor/sysarmor-next-project/apps/manager/internal/domain/control"
	domaingateway "github.com/sysarmor/sysarmor-next-project/apps/manager/internal/domain/gateway"
	domainidentity "github.com/sysarmor/sysarmor-next-project/apps/manager/internal/domain/identity"
)

type gatewayControlStateWriter struct {
	legacy  controlpostgres.StateWriter
	results *controlapp.ResultService
}

func (writer gatewayControlStateWriter) RecordHealth(ctx context.Context, value domainidentity.Health) error {
	return writer.legacy.RecordHealth(ctx, value)
}

func (writer gatewayControlStateWriter) RecordCapability(ctx context.Context, value domaingateway.Capability) error {
	return writer.legacy.RecordCapability(ctx, value)
}

func (writer gatewayControlStateWriter) AckResponse(ctx context.Context, value domaingateway.Ack) error {
	return writer.legacy.AckResponse(ctx, value)
}

func (writer gatewayControlStateWriter) AckCommand(ctx context.Context, value domaingateway.Ack) error {
	_, err := writer.results.Acknowledge(ctx, controlapp.AcknowledgeCommand{
		TenantID: value.TenantID, AgentID: value.AgentID, CommandID: value.ID,
		Status: domaincontrol.CommandStatus(value.Status), Message: value.Message,
		PolicyID: value.PolicyID, PolicyVersion: value.PolicyVersion, Report: value.ReportJSON,
		ObservedAt: value.ObservedAt,
	})
	return err
}

func (writer gatewayControlStateWriter) CompleteEvidence(ctx context.Context, value domaingateway.EvidenceResult) error {
	_, err := writer.results.CompleteEvidence(ctx, controlapp.CompleteEvidenceCommand{
		TenantID: value.TenantID, AgentID: value.AgentID, RequestID: value.RequestID,
		OK: value.OK, Message: value.Error, Evidence: value.Evidence, ObservedAt: value.ObservedAt,
	})
	return err
}
