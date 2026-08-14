package runtime

import (
	"context"
	"fmt"
	"reflect"
	"strings"

	"github.com/sysarmor/sysarmor-next-project/apps/agent/internal/adapters/config"
	detectionadapter "github.com/sysarmor/sysarmor-next-project/apps/agent/internal/adapters/detection"
	agentpolicy "github.com/sysarmor/sysarmor-next-project/apps/agent/internal/adapters/policy"
	sensorruntime "github.com/sysarmor/sysarmor-next-project/apps/agent/internal/adapters/sensor/runtime"
	"github.com/sysarmor/sysarmor-next-project/apps/agent/internal/adapters/sensor/tetragon"
	"github.com/sysarmor/sysarmor-next-project/apps/agent/internal/adapters/sqlite"
	telemetryadapter "github.com/sysarmor/sysarmor-next-project/apps/agent/internal/adapters/telemetry"
	agentcontrol "github.com/sysarmor/sysarmor-next-project/apps/agent/internal/application/control"
	applicationpolicy "github.com/sysarmor/sysarmor-next-project/apps/agent/internal/application/policy"
	detectionruntime "github.com/sysarmor/sysarmor-next-project/apps/agent/internal/domain/detection/runtime"
	policymodel "github.com/sysarmor/sysarmor-next-project/apps/agent/internal/domain/policy"
	"github.com/sysarmor/sysarmor-next-project/packages/sensor-sdk/contract"
)

type endpointCandidate struct {
	endpoint  policymodel.EndpointPolicy
	intent    contract.CollectionIntent
	previous  contract.CollectionIntent
	policy    policymodel.Policy
	detection *detectionruntime.State
	report    detectionruntime.ApplyReport
	telemetry config.EffectiveTelemetry
	compile   contract.CollectionCompileReport
	source    applicationpolicy.Source
}

func (c *endpointCandidate) PolicyID() string                       { return c.endpoint.PolicyID }
func (c *endpointCandidate) PolicyVersion() uint64                  { return c.endpoint.Version }
func (c *endpointCandidate) PolicySource() applicationpolicy.Source { return c.source }

type endpointPolicyApplication struct {
	policy  *policyRuntime
	runtime sensorruntime.Runtime
	batcher *telemetryadapter.Batcher
	service *applicationpolicy.EndpointService
}

func newEndpointPolicyApplication(policy *policyRuntime, runtime sensorruntime.Runtime, batcher *telemetryadapter.Batcher) *endpointPolicyApplication {
	application := &endpointPolicyApplication{policy: policy, runtime: runtime, batcher: batcher}
	application.service = applicationpolicy.NewEndpointService(application, application)
	return application
}

func (a *endpointPolicyApplication) PolicyIdentity() agentcontrol.PolicyIdentity {
	identity := a.policy.management.currentIdentity()
	return agentcontrol.PolicyIdentity{TenantID: identity.TenantID, AgentID: identity.AgentID}
}

func (a *endpointPolicyApplication) ValidatePolicyContext(ctx agentcontrol.RequestContext) error {
	return a.policy.management.validateControlIdentity(ctx.TenantID, ctx.AgentID)
}

func (a *endpointPolicyApplication) BeginLocalPolicyMutation(ctx context.Context, mutation bool) (func(), error) {
	return a.policy.beginLocalPolicyMutation(ctx, mutation)
}

func (a *endpointPolicyApplication) ValidateEndpoint(ctx context.Context, document string, source applicationpolicy.Source) (applicationpolicy.EndpointCandidate, error) {
	return a.service.Validate(ctx, document, source)
}

func (a *endpointPolicyApplication) ActivateStandaloneEndpoint(ctx context.Context, document string) (applicationpolicy.EndpointResult, error) {
	var result applicationpolicy.EndpointResult
	var activationErr error
	a.policy.withDetectionUpdateTransaction(func() {
		result, activationErr = a.service.ActivateStandalone(ctx, document)
	})
	return result, activationErr
}

func (a *endpointPolicyApplication) ActivateManagedEndpoint(ctx context.Context, document string) (applicationpolicy.EndpointResult, error) {
	return a.service.ActivateManaged(ctx, document)
}

func (a *endpointPolicyApplication) PrepareEndpoint(_ context.Context, document string, source applicationpolicy.Source) (applicationpolicy.EndpointCandidate, error) {
	endpoint, err := agentpolicy.ParseEndpointPolicy([]byte(document))
	if err != nil {
		return nil, err
	}
	return a.prepare(endpoint, source)
}

func (a *endpointPolicyApplication) prepare(endpoint policymodel.EndpointPolicy, source applicationpolicy.Source) (*endpointCandidate, error) {
	collection, expansion, err := agentpolicy.ExpandCollectionPolicyRefs(endpoint.Collection, collectionContentSnapshot(a.policy.contentStore().Snapshot()))
	if err != nil {
		return nil, err
	}
	endpoint.Collection = collection
	intent, err := agentpolicy.CollectionPolicyIntent(collection)
	if err != nil {
		return nil, err
	}
	compile := tetragon.CompileReport(intent)
	compile.ResolvedRefs = expansion.ResolvedRefs
	if len(compile.UnsupportedSelectors) > 0 {
		return nil, fmt.Errorf("unsupported collection selectors: %+v", compile.UnsupportedSelectors)
	}
	effective, err := config.ResolveTelemetry(a.policy.config.Telemetry, &endpoint.Telemetry)
	if err != nil {
		return nil, err
	}
	detectionIntent := intent
	if len(detectionIntent.Capabilities) == 0 {
		detectionIntent.Capabilities = append([]contract.CollectionBehaviorCapability(nil), a.policy.sensor.capability.Collection...)
	}
	runtimePolicy := endpointRuntimePolicy(a.policy.management.currentIdentity().TenantID, endpoint)
	engine, report := detectionadapter.NewWithRuntimeLimits(runtimePolicy.Detection, detectionIntent, a.policy.detectionContentSnapshot(), a.policy.detectionLimits())
	if report.Status == "rejected" {
		return nil, fmt.Errorf("detection policy rejected: %s", strings.Join(report.Details, "; "))
	}
	return &endpointCandidate{
		endpoint: endpoint, intent: intent, previous: a.policy.currentCollectionIntent(), policy: runtimePolicy,
		detection: engine, report: report, telemetry: effective, compile: compile, source: source,
	}, nil
}

func endpointRuntimePolicy(tenantID string, endpoint policymodel.EndpointPolicy) policymodel.Policy {
	policy := policymodel.DefaultPolicy(tenantID)
	policy.PolicyID = endpoint.PolicyID
	policy.Version = endpoint.Version
	policy.Detection = &endpoint.Detection
	policy.Telemetry = &endpoint.Telemetry
	policy.Response = endpoint.Response
	return policy
}

func (a *endpointPolicyApplication) PersistEndpoint(ctx context.Context, candidate applicationpolicy.EndpointCandidate) error {
	prepared, err := endpointPrepared(candidate)
	if err != nil {
		return err
	}
	if a.policy.management.localStore == nil {
		return fmt.Errorf("local store is unavailable")
	}
	return agentpolicy.SaveEffectiveEndpointPolicy(ctx, a.policy.management.localStore, prepared.endpoint)
}

func (a *endpointPolicyApplication) SaveDesiredManaged(ctx context.Context, candidate applicationpolicy.EndpointCandidate) error {
	prepared, err := endpointPrepared(candidate)
	if err != nil {
		return err
	}
	if a.policy.management.localStore == nil {
		return fmt.Errorf("local store is unavailable")
	}
	a.policy.policyAuthorityMu.Lock()
	defer a.policy.policyAuthorityMu.Unlock()
	return agentpolicy.SaveDesiredManagedEndpointPolicy(ctx, a.policy.management.localStore, prepared.endpoint)
}

func (a *endpointPolicyApplication) BeginManagedTransition(ctx context.Context, candidate applicationpolicy.EndpointCandidate) (func(), error) {
	prepared, err := endpointPrepared(candidate)
	if err != nil {
		return nil, err
	}
	a.policy.policyAuthorityMu.Lock()
	a.policy.detectionUpdateMu.Lock()
	if err := a.requireCurrentPending(ctx, prepared); err != nil {
		a.policy.detectionUpdateMu.Unlock()
		a.policy.policyAuthorityMu.Unlock()
		return nil, err
	}
	return func() {
		a.policy.detectionUpdateMu.Unlock()
		a.policy.policyAuthorityMu.Unlock()
	}, nil
}

func (a *endpointPolicyApplication) ActivateManagedDurable(ctx context.Context, candidate applicationpolicy.EndpointCandidate) error {
	prepared, err := endpointPrepared(candidate)
	if err != nil {
		return err
	}
	if a.policy.management.localStore == nil {
		return fmt.Errorf("local store is unavailable")
	}
	return agentpolicy.ActivateManagedEndpointPolicy(ctx, a.policy.management.localStore, prepared.endpoint)
}

func (a *endpointPolicyApplication) PromoteManaged(ctx context.Context, _ applicationpolicy.EndpointCandidate) error {
	if a.policy.management.localStore == nil {
		return fmt.Errorf("local store is unavailable")
	}
	enrollment, err := a.policy.management.localStore.Enrollment(ctx)
	if err != nil {
		return fmt.Errorf("read enrollment for managed policy activation: %w", err)
	}
	if enrollment.State != sqlite.StateManaged {
		return fmt.Errorf("managed policy authority promotion requires managed enrollment, got %s", enrollment.State)
	}
	return a.policy.management.reconcileManagementContext(enrollment)
}

func (a *endpointPolicyApplication) PendingManaged(ctx context.Context) (applicationpolicy.EndpointCandidate, bool, error) {
	if a.policy.management.localStore == nil {
		return nil, false, nil
	}
	record, status, ok, err := a.policy.management.localStore.DesiredPolicy(ctx, "endpoint", sqlite.PolicySourceManaged)
	if err != nil {
		return nil, false, err
	}
	if ok && status == sqlite.PolicyStatusPending {
		return a.prepareDocument(record.Document, applicationpolicy.SourceManaged, "prepare pending managed endpoint policy")
	}
	record, source, ok, err := a.policy.management.localStore.ActivePolicy(ctx, "endpoint")
	if err != nil || !ok || source != sqlite.PolicySourceManaged {
		return nil, false, err
	}
	return a.prepareDocument(record.Document, applicationpolicy.SourceManaged, "prepare active managed endpoint policy")
}

func (a *endpointPolicyApplication) LoadStandalone(ctx context.Context) (applicationpolicy.EndpointCandidate, bool, error) {
	if a.policy.management.localStore == nil {
		return nil, false, nil
	}
	endpoint, ok, err := agentpolicy.LoadEndpointPolicy(ctx, a.policy.management.localStore, sqlite.PolicySourceStandalone)
	if err != nil || !ok {
		return nil, ok, err
	}
	prepared, err := a.prepare(endpoint, applicationpolicy.SourceStandalone)
	return prepared, err == nil, err
}

func (a *endpointPolicyApplication) prepareDocument(document []byte, source applicationpolicy.Source, stage string) (applicationpolicy.EndpointCandidate, bool, error) {
	candidate, err := a.PrepareEndpoint(context.Background(), string(document), source)
	if err != nil {
		return nil, false, fmt.Errorf("%s: %w", stage, err)
	}
	return candidate, true, nil
}

func (a *endpointPolicyApplication) ApplyEndpoint(ctx context.Context, candidate applicationpolicy.EndpointCandidate) (applicationpolicy.EndpointReport, error) {
	prepared, err := endpointPrepared(candidate)
	if err != nil {
		return applicationpolicy.EndpointReport{}, err
	}
	reconciler := endpointPolicyReconciler{runtime: a.runtime, supervisor: a.policy.sensor.currentSupervisor()}
	if _, err := reconciler.Apply(ctx, prepared.intent); err != nil {
		return applicationpolicy.EndpointReport{}, err
	}
	return applicationpolicy.EndpointReport{Status: prepared.report.Status, Warnings: prepared.report.Warnings, RequiresRestart: true}, nil
}

func (a *endpointPolicyApplication) RollbackEndpoint(ctx context.Context, candidate applicationpolicy.EndpointCandidate) error {
	prepared, err := endpointPrepared(candidate)
	if err != nil {
		return err
	}
	reconciler := endpointPolicyReconciler{runtime: a.runtime, supervisor: a.policy.sensor.currentSupervisor()}
	_, err = reconciler.Apply(ctx, prepared.previous)
	return err
}

func (a *endpointPolicyApplication) ActivateEndpoint(candidate applicationpolicy.EndpointCandidate, _ applicationpolicy.EndpointReport) {
	prepared, err := endpointPrepared(candidate)
	if err != nil {
		return
	}
	a.policy.setEndpointPolicy(prepared.endpoint)
	a.policy.setCollectionIntent(prepared.intent)
	a.policy.setPolicy(prepared.policy)
	a.policy.setDetection(prepared.detection)
	a.policy.setDetectionStatus(prepared.policy, prepared.report, a.policy.contentStore().Snapshot())
	a.policy.setEffectiveTelemetry(prepared.telemetry)
	if a.batcher != nil && prepared.source == applicationpolicy.SourceStandalone {
		a.batcher.Reconfigure(telemetryadapter.BatchSettings{
			MaxItems: prepared.telemetry.MaxBatchItems, MaxBytes: prepared.telemetry.MaxBatchBytes,
			FlushInterval: prepared.telemetry.FlushInterval,
		})
	}
}

func (a *endpointPolicyApplication) ResumeApplied(ctx context.Context, intent contract.CollectionIntent) error {
	candidate, ok, err := a.PendingManaged(ctx)
	if err != nil || !ok {
		return err
	}
	prepared, _ := endpointPrepared(candidate)
	if !reflect.DeepEqual(prepared.intent, intent) {
		return nil
	}
	_, err = a.service.ResumeManaged(ctx)
	return err
}

func (a *endpointPolicyApplication) PendingIntent(ctx context.Context) (contract.CollectionIntent, bool, error) {
	candidate, ok, err := a.PendingManaged(ctx)
	if err != nil || !ok {
		return contract.CollectionIntent{}, false, err
	}
	prepared, err := endpointPrepared(candidate)
	if err != nil {
		return contract.CollectionIntent{}, false, err
	}
	return prepared.intent, true, nil
}

func (a *endpointPolicyApplication) RestoreStandalone(ctx context.Context, activate func(context.Context) error) error {
	var restoreErr error
	a.policy.withDetectionUpdateTransaction(func() {
		restoreErr = a.service.RestoreStandalone(ctx, activate)
	})
	return restoreErr
}

func (a *endpointPolicyApplication) requireCurrentPending(ctx context.Context, candidate *endpointCandidate) error {
	record, status, ok, err := a.policy.management.localStore.DesiredPolicy(ctx, "endpoint", sqlite.PolicySourceManaged)
	if err != nil {
		return err
	}
	if !ok || status != sqlite.PolicyStatusPending {
		var source sqlite.PolicySource
		record, source, ok, err = a.policy.management.localStore.ActivePolicy(ctx, "endpoint")
		if err != nil {
			return err
		}
		if source != sqlite.PolicySourceManaged {
			ok = false
		}
	}
	if !ok || record.Version != candidate.PolicyVersion() {
		return fmt.Errorf("managed endpoint policy is no longer current")
	}
	parsed, err := agentpolicy.ParseEndpointPolicy(record.Document)
	if err != nil {
		return err
	}
	if parsed.PolicyID != candidate.PolicyID() {
		return fmt.Errorf("managed endpoint policy is no longer current")
	}
	return nil
}

func endpointPrepared(candidate applicationpolicy.EndpointCandidate) (*endpointCandidate, error) {
	prepared, ok := candidate.(*endpointCandidate)
	if !ok || prepared == nil {
		return nil, fmt.Errorf("unsupported endpoint policy candidate")
	}
	return prepared, nil
}
