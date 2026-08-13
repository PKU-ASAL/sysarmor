package daemon

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	detection "github.com/sysarmor/sysarmor-next-project/apps/agent/internal/adapters/detection"
	agentpolicy "github.com/sysarmor/sysarmor-next-project/apps/agent/internal/adapters/policy"
	applicationpolicy "github.com/sysarmor/sysarmor-next-project/apps/agent/internal/application/policy"
	agentcontrol "github.com/sysarmor/sysarmor-next-project/apps/agent/internal/control"
	policymodel "github.com/sysarmor/sysarmor-next-project/packages/policy"
)

type detectionCandidate struct {
	detection policymodel.DetectionPolicy
	endpoint  agentpolicy.EndpointPolicy
	policy    policymodel.Policy
	engine    *detection.Engine
	report    detection.ApplyReport
}

func (c *detectionCandidate) PolicyID() string      { return c.detection.PolicyID }
func (c *detectionCandidate) PolicyVersion() uint64 { return c.detection.Version }
func (c *detectionCandidate) BuildReport() applicationpolicy.DetectionReport {
	reportJSON, _ := json.Marshal(c.report)
	message := c.report.Message
	if c.report.Status == "rejected" && len(c.report.Details) > 0 {
		message = "detection policy rejected: " + strings.Join(c.report.Details, "; ")
	}
	return applicationpolicy.DetectionReport{
		Status: c.report.Status, Message: message, Details: append([]string(nil), c.report.Details...),
		Warnings: append([]string(nil), c.report.Warnings...), ReportJSON: string(reportJSON),
	}
}

type detectionPolicyApplication struct {
	runner  *AgentRuntime
	service *applicationpolicy.DetectionService
}

func newDetectionPolicyApplication(runner *AgentRuntime) *detectionPolicyApplication {
	application := &detectionPolicyApplication{runner: runner}
	application.service = applicationpolicy.NewDetectionService(application, application)
	return application
}

func NewDetectionPolicyApplication(runner *AgentRuntime) agentcontrol.DetectionApplication {
	return newDetectionPolicyApplication(runner)
}

func (a *detectionPolicyApplication) PolicyIdentity() agentcontrol.PolicyIdentity {
	identity := a.runner.currentIdentity()
	return agentcontrol.PolicyIdentity{TenantID: identity.TenantID, AgentID: identity.AgentID}
}

func (a *detectionPolicyApplication) ValidatePolicyContext(ctx agentcontrol.RequestContext) error {
	return a.runner.validateControlIdentity(ctx.TenantID, ctx.AgentID)
}

func (a *detectionPolicyApplication) BeginLocalPolicyMutation(ctx context.Context, mutation bool) (func(), error) {
	return a.runner.beginLocalPolicyMutation(ctx, mutation)
}

func (a *detectionPolicyApplication) ValidateDetection(ctx context.Context, document string) (applicationpolicy.DetectionCandidate, error) {
	return a.service.Validate(ctx, document)
}

func (a *detectionPolicyApplication) ActivateDetection(ctx context.Context, document string) (applicationpolicy.DetectionResult, error) {
	var result applicationpolicy.DetectionResult
	var activationErr error
	a.runner.withDetectionUpdateTransaction(func() {
		result, activationErr = a.service.Activate(ctx, document)
	})
	return result, activationErr
}

func (a *detectionPolicyApplication) PrepareDetection(_ context.Context, document string) (applicationpolicy.DetectionCandidate, error) {
	policy, err := parseDetectionPolicy(document)
	if err != nil {
		return nil, err
	}
	policy = policymodel.NormalizeDetectionPolicy(policy)
	engine, report := detection.NewWithRuntimeLimits(&policy, a.runner.currentCollectionIntent(), a.runner.detectionContentSnapshot(), a.runner.detectionLimits())
	active := policymodel.Normalize(a.runner.activePolicy())
	active.Detection = &policy
	endpoint := a.runner.currentEndpointPolicy()
	endpoint.Detection = policy
	endpoint.Version++
	return &detectionCandidate{detection: policy, endpoint: endpoint, policy: active, engine: engine, report: report}, nil
}

func parseDetectionPolicy(document string) (policymodel.DetectionPolicy, error) {
	var envelope struct {
		Detection *policymodel.DetectionPolicy `json:"detection"`
	}
	if err := json.Unmarshal([]byte(document), &envelope); err == nil && envelope.Detection != nil {
		return *envelope.Detection, nil
	}
	var policy policymodel.DetectionPolicy
	if err := json.Unmarshal([]byte(document), &policy); err != nil {
		return policymodel.DetectionPolicy{}, fmt.Errorf("invalid detection policy json: %w", err)
	}
	return policy, nil
}

func (a *detectionPolicyApplication) PersistDetection(ctx context.Context, candidate applicationpolicy.DetectionCandidate) error {
	prepared, err := preparedDetection(candidate)
	if err != nil {
		return err
	}
	if a.runner.localStore == nil {
		return nil
	}
	return agentpolicy.SaveEffectiveEndpointPolicy(ctx, a.runner.localStore, prepared.endpoint)
}

func (a *detectionPolicyApplication) RecordRejectedDetection(candidate applicationpolicy.DetectionCandidate) {
	prepared, err := preparedDetection(candidate)
	if err != nil {
		return
	}
	a.runner.setDetectionStatus(prepared.policy, prepared.report, a.runner.contentStore().Snapshot())
}

func (a *detectionPolicyApplication) PublishDetection(candidate applicationpolicy.DetectionCandidate) {
	prepared, err := preparedDetection(candidate)
	if err != nil {
		return
	}
	a.runner.setEndpointPolicy(prepared.endpoint)
	a.runner.setPolicy(prepared.policy)
	a.runner.setDetection(prepared.engine)
	a.runner.setDetectionStatus(prepared.policy, prepared.report, a.runner.contentStore().Snapshot())
}

func preparedDetection(candidate applicationpolicy.DetectionCandidate) (*detectionCandidate, error) {
	prepared, ok := candidate.(*detectionCandidate)
	if !ok || prepared == nil {
		return nil, fmt.Errorf("unsupported detection policy candidate")
	}
	return prepared, nil
}
