package runtime

import (
	"context"
	"fmt"
	"strings"

	"github.com/sysarmor/sysarmor-next-project/apps/agent/internal/adapters/config"
	agentpolicy "github.com/sysarmor/sysarmor-next-project/apps/agent/internal/adapters/policy"
	telemetryadapter "github.com/sysarmor/sysarmor-next-project/apps/agent/internal/adapters/telemetry"
	agentcontrol "github.com/sysarmor/sysarmor-next-project/apps/agent/internal/application/control"
	applicationpolicy "github.com/sysarmor/sysarmor-next-project/apps/agent/internal/application/policy"
	policymodel "github.com/sysarmor/sysarmor-next-project/apps/agent/internal/domain/policy"
)

type telemetryCandidate struct {
	policy    policymodel.TelemetryPolicy
	effective config.EffectiveTelemetry
	endpoint  policymodel.EndpointPolicy
}

func (c *telemetryCandidate) ReportJSON() string {
	report, _ := agentpolicy.EncodeTelemetryEnvelope(c.policy)
	return string(report)
}

type telemetryPolicyApplication struct {
	runner  *Coordinator
	batcher *telemetryadapter.Batcher
	service *applicationpolicy.TelemetryService
}

func newTelemetryPolicyApplication(runner *Coordinator, batcher *telemetryadapter.Batcher) *telemetryPolicyApplication {
	application := &telemetryPolicyApplication{runner: runner, batcher: batcher}
	application.service = applicationpolicy.NewTelemetryService(application, application)
	return application
}

func NewTelemetryPolicyApplication(runner *Coordinator, batcher *telemetryadapter.Batcher) agentcontrol.TelemetryApplication {
	return newTelemetryPolicyApplication(runner, batcher)
}

func (a *telemetryPolicyApplication) PolicyIdentity() agentcontrol.PolicyIdentity {
	identity := a.runner.currentIdentity()
	return agentcontrol.PolicyIdentity{TenantID: identity.TenantID, AgentID: identity.AgentID}
}

func (a *telemetryPolicyApplication) ValidatePolicyContext(ctx agentcontrol.RequestContext) error {
	return a.runner.validateControlIdentity(ctx.TenantID, ctx.AgentID)
}

func (a *telemetryPolicyApplication) BeginLocalPolicyMutation(ctx context.Context, mutation bool) (func(), error) {
	return a.runner.beginLocalPolicyMutation(ctx, mutation)
}

func (a *telemetryPolicyApplication) ValidateTelemetry(ctx context.Context, document string, input *applicationpolicy.TelemetryInput) (applicationpolicy.TelemetryCandidate, error) {
	return a.service.Validate(ctx, document, input)
}

func (a *telemetryPolicyApplication) ActivateTelemetry(ctx context.Context, document string, input *applicationpolicy.TelemetryInput) (applicationpolicy.TelemetryCandidate, error) {
	return a.service.Activate(ctx, document, input)
}

func (a *telemetryPolicyApplication) PrepareTelemetry(_ context.Context, document string, input *applicationpolicy.TelemetryInput) (applicationpolicy.TelemetryCandidate, error) {
	policy, err := parseTelemetryPolicy(document, input)
	if err != nil {
		return nil, err
	}
	if _, err := config.ResolveTelemetry(config.DefaultTelemetryConfig(), &policy); err != nil {
		return nil, err
	}
	effective, err := config.ResolveTelemetry(a.runner.Config.Telemetry, &policy)
	if err != nil {
		return nil, err
	}
	endpoint := a.runner.currentEndpointPolicy()
	endpoint.Telemetry = policy
	endpoint.Version++
	return &telemetryCandidate{policy: policy, effective: effective, endpoint: endpoint}, nil
}

func parseTelemetryPolicy(document string, input *applicationpolicy.TelemetryInput) (policymodel.TelemetryPolicy, error) {
	var policy *policymodel.TelemetryPolicy
	if strings.TrimSpace(document) != "" {
		parsed, err := parseTelemetryDocument(document)
		if err != nil {
			return policymodel.TelemetryPolicy{}, err
		}
		policy = &parsed
	}
	if input != nil {
		policy = &policymodel.TelemetryPolicy{
			MaxBatchItems: int(input.MaxBatchItems), MaxBatchBytes: int(input.MaxBatchBytes), FlushInterval: input.FlushInterval,
		}
	}
	if policy == nil {
		return policymodel.TelemetryPolicy{}, fmt.Errorf("telemetry policy is required")
	}
	return *policy, nil
}

func parseTelemetryDocument(document string) (policymodel.TelemetryPolicy, error) {
	return agentpolicy.DecodeTelemetryDocument([]byte(document))
}

func (a *telemetryPolicyApplication) PersistTelemetry(ctx context.Context, candidate applicationpolicy.TelemetryCandidate) error {
	prepared, err := preparedTelemetry(candidate)
	if err != nil {
		return err
	}
	if a.runner.localStore == nil {
		return nil
	}
	return agentpolicy.SaveEffectiveEndpointPolicy(ctx, a.runner.localStore, prepared.endpoint)
}

func (a *telemetryPolicyApplication) PublishTelemetry(candidate applicationpolicy.TelemetryCandidate) {
	prepared, err := preparedTelemetry(candidate)
	if err != nil {
		return
	}
	a.runner.setEndpointPolicy(prepared.endpoint)
	a.runner.setEffectiveTelemetry(prepared.effective)
	if a.batcher != nil {
		a.batcher.Reconfigure(telemetryadapter.BatchSettings{
			MaxItems: prepared.effective.MaxBatchItems, MaxBytes: prepared.effective.MaxBatchBytes,
			FlushInterval: prepared.effective.FlushInterval,
		})
	}
}

func preparedTelemetry(candidate applicationpolicy.TelemetryCandidate) (*telemetryCandidate, error) {
	prepared, ok := candidate.(*telemetryCandidate)
	if !ok || prepared == nil {
		return nil, fmt.Errorf("unsupported telemetry policy candidate")
	}
	return prepared, nil
}
