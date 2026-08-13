package control

import (
	"fmt"
	"strings"

	"github.com/sysarmor/sysarmor-next-project/apps/agent/internal/config"
	"github.com/sysarmor/sysarmor-next-project/apps/agent/internal/detection"
	agentpolicy "github.com/sysarmor/sysarmor-next-project/apps/agent/internal/policy"
	"github.com/sysarmor/sysarmor-next-project/apps/agent/internal/sensors/linux/tetragon"
	policymodel "github.com/sysarmor/sysarmor-next-project/packages/policy"
	"github.com/sysarmor/sysarmor-next-project/packages/sensor-sdk/contract"
)

func (c *EndpointPolicyController) prepare(document string) (PreparedEndpointPolicy, error) {
	policy, err := agentpolicy.ParseEndpointPolicy([]byte(document))
	if err != nil {
		return PreparedEndpointPolicy{}, err
	}
	collection, expansion, err := agentpolicy.ExpandCollectionPolicyRefs(policy.Collection, c.runtime.EndpointCollectionContent())
	if err != nil {
		return PreparedEndpointPolicy{}, err
	}
	policy.Collection = collection
	intent, err := agentpolicy.CollectionPolicyIntent(collection)
	if err != nil {
		return PreparedEndpointPolicy{}, err
	}
	compile := tetragon.CompileReport(intent)
	compile.ResolvedRefs = expansion.ResolvedRefs
	if len(compile.UnsupportedSelectors) > 0 {
		return PreparedEndpointPolicy{}, fmt.Errorf("unsupported collection selectors: %+v", compile.UnsupportedSelectors)
	}
	settings := c.runtime.EndpointPolicySettings()
	effective, err := config.ResolveTelemetry(settings.Telemetry, &policy.Telemetry)
	if err != nil {
		return PreparedEndpointPolicy{}, err
	}
	detectionIntent := intent
	if len(detectionIntent.Capabilities) == 0 && len(settings.Capabilities) > 0 {
		detectionIntent.Capabilities = append([]contract.CollectionBehaviorCapability(nil), settings.Capabilities...)
	}
	runtimePolicy := endpointRuntimePolicy(settings.TenantID, policy)
	engine, report := detection.NewWithRuntimeLimits(runtimePolicy.Detection, detectionIntent, c.runtime.EndpointDetectionContent(), settings.Limits)
	if report.Status == "rejected" {
		return PreparedEndpointPolicy{}, fmt.Errorf("detection policy rejected: %s", strings.Join(report.Details, "; "))
	}
	return PreparedEndpointPolicy{
		Endpoint: policy, Intent: intent, Runtime: runtimePolicy, Detection: engine,
		Report: report, Telemetry: effective, Compile: compile,
	}, nil
}

func endpointRuntimePolicy(tenantID string, endpoint agentpolicy.EndpointPolicy) policymodel.Policy {
	policy := policymodel.DefaultPolicy(tenantID)
	policy.PolicyID = endpoint.PolicyID
	policy.Version = endpoint.Version
	policy.Detection = &endpoint.Detection
	policy.Telemetry = &endpoint.Telemetry
	policy.Response = endpoint.Response
	return policy
}
