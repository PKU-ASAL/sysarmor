package runtime

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/sysarmor/sysarmor-next-project/apps/agent/internal/adapters/config"
	detectionadapter "github.com/sysarmor/sysarmor-next-project/apps/agent/internal/adapters/detection"
	agentpolicy "github.com/sysarmor/sysarmor-next-project/apps/agent/internal/adapters/policy"
	sensorruntime "github.com/sysarmor/sysarmor-next-project/apps/agent/internal/adapters/sensor/runtime"
	"github.com/sysarmor/sysarmor-next-project/apps/agent/internal/adapters/sensor/tetragon"
	agentcontrol "github.com/sysarmor/sysarmor-next-project/apps/agent/internal/application/control"
	applicationpolicy "github.com/sysarmor/sysarmor-next-project/apps/agent/internal/application/policy"
	detectionruntime "github.com/sysarmor/sysarmor-next-project/apps/agent/internal/domain/detection/runtime"
	policymodel "github.com/sysarmor/sysarmor-next-project/apps/agent/internal/domain/policy"
	"github.com/sysarmor/sysarmor-next-project/packages/sensor-sdk/contract"
)

type collectionCandidate struct {
	policy   policymodel.CollectionPolicy
	endpoint policymodel.EndpointPolicy
	intent   contract.CollectionIntent
	previous contract.CollectionIntent
	compile  contract.CollectionCompileReport
	engine   *detectionruntime.State
	report   detectionruntime.ApplyReport
	result   applicationpolicy.CollectionReport
}

func (c *collectionCandidate) PolicyID() string      { return c.policy.Identity.ID }
func (c *collectionCandidate) PolicyVersion() uint64 { return c.policy.Identity.Version }
func (c *collectionCandidate) ValidationReport() applicationpolicy.CollectionReport {
	return c.result
}

type collectionPolicyApplication struct {
	runner  *Runtime
	runtime sensorruntime.Runtime
	service *applicationpolicy.CollectionService
}

func newCollectionPolicyApplication(runner *Runtime, runtime sensorruntime.Runtime) *collectionPolicyApplication {
	application := &collectionPolicyApplication{runner: runner, runtime: runtime}
	application.service = applicationpolicy.NewCollectionService(application, application)
	return application
}

func NewCollectionPolicyApplication(runner *Runtime, runtime sensorruntime.Runtime) agentcontrol.CollectionApplication {
	return newCollectionPolicyApplication(runner, runtime)
}

func (a *collectionPolicyApplication) PolicyIdentity() agentcontrol.PolicyIdentity {
	identity := a.runner.currentIdentity()
	return agentcontrol.PolicyIdentity{TenantID: identity.TenantID, AgentID: identity.AgentID}
}

func (a *collectionPolicyApplication) ValidatePolicyContext(ctx agentcontrol.RequestContext) error {
	return a.runner.validateControlIdentity(ctx.TenantID, ctx.AgentID)
}

func (a *collectionPolicyApplication) BeginLocalPolicyMutation(ctx context.Context, mutation bool) (func(), error) {
	return a.runner.beginLocalPolicyMutation(ctx, mutation)
}

func (a *collectionPolicyApplication) ValidateCollection(ctx context.Context, document string, scope applicationpolicy.CollectionScope) (applicationpolicy.CollectionCandidate, error) {
	return a.service.Validate(ctx, document, scope)
}

func (a *collectionPolicyApplication) ActivateCollection(ctx context.Context, document string, scope applicationpolicy.CollectionScope) (applicationpolicy.CollectionResult, error) {
	var result applicationpolicy.CollectionResult
	var activationErr error
	a.runner.withDetectionUpdateTransaction(func() {
		result, activationErr = a.service.Activate(ctx, document, scope)
	})
	return result, activationErr
}

func (a *collectionPolicyApplication) PrepareCollection(_ context.Context, document string, scope applicationpolicy.CollectionScope) (applicationpolicy.CollectionCandidate, error) {
	policy, err := agentpolicy.ParseCollectionPolicyJSON([]byte(document), a.runner.Config.Sensor.ObserveOnly)
	if err != nil {
		return nil, fmt.Errorf("invalid collection policy: %w", err)
	}
	if err := applyCollectionScope(&policy, scope, a.runner.Config.Sensor); err != nil {
		return nil, err
	}
	policy, expansion, err := agentpolicy.ExpandCollectionPolicyRefs(policy, collectionContentSnapshot(a.runner.contentStore().Snapshot()))
	if err != nil {
		return nil, fmt.Errorf("resolve collection policy refs: %w", err)
	}
	intent, err := agentpolicy.CollectionPolicyIntent(policy)
	if err != nil {
		return nil, fmt.Errorf("compile collection policy: %w", err)
	}
	compile := tetragon.CompileReport(intent)
	compile.ResolvedRefs = expansion.ResolvedRefs
	if len(compile.UnsupportedSelectors) > 0 {
		return nil, fmt.Errorf("collection policy contains unsupported selectors")
	}
	detectionIntent := intent
	if len(detectionIntent.Capabilities) == 0 {
		detectionIntent.Capabilities = append([]contract.CollectionBehaviorCapability(nil), a.runner.capability.Collection...)
	}
	engine, report := detectionadapter.NewWithRuntimeLimits(a.runner.activePolicy().Detection, detectionIntent, a.runner.detectionContentSnapshot(), a.runner.detectionLimits())
	endpoint := a.runner.currentEndpointPolicy()
	endpoint.Collection = policy
	endpoint.Version++
	return &collectionCandidate{
		policy: policy, endpoint: endpoint, intent: intent, previous: a.runner.currentCollectionIntent(),
		compile: compile, engine: engine, report: report, result: collectionValidationReport(compile, report),
	}, nil
}

func (a *collectionPolicyApplication) PersistCollection(ctx context.Context, candidate applicationpolicy.CollectionCandidate) error {
	prepared, err := preparedCollection(candidate)
	if err != nil {
		return err
	}
	if a.runner.localStore == nil {
		return nil
	}
	return agentpolicy.SaveEffectiveEndpointPolicy(ctx, a.runner.localStore, prepared.endpoint)
}

func (a *collectionPolicyApplication) ApplyCollection(ctx context.Context, candidate applicationpolicy.CollectionCandidate) error {
	prepared, err := preparedCollection(candidate)
	if err != nil {
		return err
	}
	reconciler := endpointPolicyReconciler{runtime: a.runtime, supervisor: a.runner.currentSensorSupervisor()}
	_, err = reconciler.Apply(ctx, prepared.intent)
	return err
}

func (a *collectionPolicyApplication) RollbackCollection(ctx context.Context, candidate applicationpolicy.CollectionCandidate) error {
	prepared, err := preparedCollection(candidate)
	if err != nil {
		return err
	}
	reconciler := endpointPolicyReconciler{runtime: a.runtime, supervisor: a.runner.currentSensorSupervisor()}
	_, err = reconciler.Apply(ctx, prepared.previous)
	return err
}

func (a *collectionPolicyApplication) PublishCollection(candidate applicationpolicy.CollectionCandidate) {
	prepared, err := preparedCollection(candidate)
	if err != nil {
		return
	}
	a.runner.setEndpointPolicy(prepared.endpoint)
	a.runner.setCollectionIntent(prepared.intent)
	a.runner.setDetection(prepared.engine)
	prepared.result = collectionActivationReport(prepared.compile, prepared.report)
}

func applyCollectionScope(policy *policymodel.CollectionPolicy, requested applicationpolicy.CollectionScope, sensorConfig config.SensorConfig) error {
	if policy.ScopeType == "" && requested.Type != "" {
		policy.ScopeType = requested.Type
		policy.ScopeSelector = requested.Selector
	}
	if policy.ScopeType != "" {
		return nil
	}
	fallback, err := sensorConfig.EffectiveScope()
	if err != nil {
		return err
	}
	policy.ScopeType = fallback.Type
	policy.ScopeSelector = fallback.Selector
	return nil
}

type collectionReportPayload struct {
	contract.CollectionCompileReport
	DetectionCoverage *detectionruntime.CoverageReport `json:"detection_coverage,omitempty"`
}

func collectionValidationReport(compile contract.CollectionCompileReport, detectionReport detectionruntime.ApplyReport) applicationpolicy.CollectionReport {
	status := "validated"
	message := "collection policy accepted in dry-run"
	if detectionReport.Status == "degraded" {
		status = "degraded"
		message += "; detection dependencies degraded"
	}
	return buildCollectionReport(compile, detectionReport, status, message)
}

func collectionActivationReport(compile contract.CollectionCompileReport, detectionReport detectionruntime.ApplyReport) applicationpolicy.CollectionReport {
	status := "applied"
	message := "collection policy applied"
	if detectionReport.Status == "degraded" {
		status = "degraded"
		message += "; detection dependencies degraded"
	}
	return buildCollectionReport(compile, detectionReport, status, message)
}

func buildCollectionReport(compile contract.CollectionCompileReport, detectionReport detectionruntime.ApplyReport, status, message string) applicationpolicy.CollectionReport {
	payload, _ := json.Marshal(collectionReportPayload{CollectionCompileReport: compile, DetectionCoverage: &detectionReport.Coverage})
	return applicationpolicy.CollectionReport{Status: status, Message: message, Warnings: collectionReportDetails(compile, detectionReport.Coverage), ReportJSON: string(payload)}
}

func collectionReportDetails(report contract.CollectionCompileReport, coverage detectionruntime.CoverageReport) []string {
	details := []string{
		fmt.Sprintf("backend=%s", report.Backend),
		fmt.Sprintf("pushed_down_selectors=%d", len(report.PushedDownSelectors)),
		fmt.Sprintf("agent_side_selectors=%d", len(report.AgentSideSelectors)),
		fmt.Sprintf("unsupported_selectors=%d", len(report.UnsupportedSelectors)),
	}
	if len(report.ResolvedRefs) > 0 {
		details = append(details, fmt.Sprintf("resolved_refs=%d", len(report.ResolvedRefs)))
	}
	if report.GeneratedPolicyHash != "" {
		details = append(details, "generated_policy_hash="+report.GeneratedPolicyHash)
	}
	for _, warning := range report.Warnings {
		if warning != "" {
			details = append(details, "warning="+warning)
		}
	}
	if coverage.Status != "" {
		details = append(details, "detection_coverage="+coverage.Status)
	}
	for _, warning := range coverage.Warnings {
		if warning != "" {
			details = append(details, "coverage_warning="+warning)
		}
	}
	return details
}

func preparedCollection(candidate applicationpolicy.CollectionCandidate) (*collectionCandidate, error) {
	prepared, ok := candidate.(*collectionCandidate)
	if !ok || prepared == nil {
		return nil, fmt.Errorf("unsupported collection policy candidate")
	}
	return prepared, nil
}
