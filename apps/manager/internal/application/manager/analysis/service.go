package analysis

import (
	"context"
	"fmt"
	"strings"

	managerapp "github.com/sysarmor/sysarmor-next-project/apps/manager/internal/application/manager"
	"github.com/sysarmor/sysarmor-next-project/apps/manager/internal/domain/detection"
	domainanalysis "github.com/sysarmor/sysarmor-next-project/apps/manager/internal/domain/detection/analysis"
	"github.com/sysarmor/sysarmor-next-project/apps/manager/internal/domain/detection/rarity"
	"github.com/sysarmor/sysarmor-next-project/apps/manager/internal/domain/failure"
	domainidentity "github.com/sysarmor/sysarmor-next-project/apps/manager/internal/domain/identity"
	domainpolicy "github.com/sysarmor/sysarmor-next-project/apps/manager/internal/domain/policy"
	domaintelemetry "github.com/sysarmor/sysarmor-next-project/apps/manager/internal/domain/telemetry"
	"github.com/sysarmor/sysarmor-next-project/apps/manager/internal/domain/tenant"
	"github.com/sysarmor/sysarmor-next-project/apps/manager/internal/ports"
)

type PolicyQuery interface {
	Effective(context.Context, managerapp.RequestContext, domainpolicy.Target) (detection.Policy, error)
}

type RarityQuery interface {
	Rarity(context.Context, managerapp.RequestContext) (domainidentity.RarityBaseline, error)
}

type Query struct {
	Target  domainpolicy.Target
	Labels  map[string]string
	Disable string
	Mode    string
}

type Service struct {
	policies  PolicyQuery
	rarity    RarityQuery
	telemetry ports.AnalysisTelemetryReader
}

func NewService(policies PolicyQuery, rarityQuery RarityQuery, telemetry ports.AnalysisTelemetryReader) *Service {
	return &Service{policies: policies, rarity: rarityQuery, telemetry: telemetry}
}

func (service *Service) Recompute(ctx context.Context, request managerapp.RequestContext, query Query) (domaintelemetry.Analysis, error) {
	if err := request.Actor.Require(tenant.RoleViewer); err != nil {
		return domaintelemetry.Analysis{}, err
	}
	if service == nil || service.policies == nil || service.rarity == nil || service.telemetry == nil {
		return domaintelemetry.Analysis{}, failure.New(failure.Internal, "analysis dependencies are required")
	}
	policy, err := service.policies.Effective(ctx, request, query.Target)
	if err != nil {
		return domaintelemetry.Analysis{}, fmt.Errorf("read effective policy: %w", err)
	}
	policy, err = configurePolicy(policy, query)
	if err != nil {
		return domaintelemetry.Analysis{}, err
	}
	baseline, err := service.rarity.Rarity(ctx, request)
	if err != nil {
		return domaintelemetry.Analysis{}, fmt.Errorf("read tenant rarity baseline: %w", err)
	}
	events, err := service.telemetry.Events(ctx, request.Actor.TenantID, cloneLabels(query.Labels))
	if err != nil {
		return domaintelemetry.Analysis{}, fmt.Errorf("read analysis events: %w", err)
	}
	signals, err := service.telemetry.Signals(ctx, request.Actor.TenantID, ports.AnalysisSignalFilter{Labels: cloneLabels(query.Labels), Layer: "endpoint"})
	if err != nil {
		return domaintelemetry.Analysis{}, fmt.Errorf("read endpoint signals: %w", err)
	}
	analyzer := domainanalysis.NewAnalyzer()
	analyzer.SetRarityBaseline(rarity.Baseline{WorkloadCounts: baseline.WorkloadCounts})
	return analyzer.Analyze(events, signals, &policy), nil
}

func configurePolicy(policy detection.Policy, query Query) (detection.Policy, error) {
	policy.EndpointRules = append([]string(nil), policy.EndpointRules...)
	policy.CloudRules = append([]string(nil), policy.CloudRules...)
	if policy.Converge == nil {
		policy.Converge = &detection.ConvergePolicy{CrossLineage: true}
	} else {
		value := *policy.Converge
		policy.Converge = &value
	}
	switch query.Disable {
	case "":
	case "cloud.cross_lineage":
		policy.Converge.CrossLineage = false
	default:
		if !strings.HasPrefix(query.Disable, "cloud.rule:") {
			return detection.Policy{}, failure.New(failure.InvalidArgument, fmt.Sprintf("unknown disable %q", query.Disable))
		}
		policy.CloudRules = removeRule(policy.CloudRules, strings.TrimPrefix(query.Disable, "cloud.rule:"))
	}
	switch query.Mode {
	case "", "rarity_structural":
	case "additive_threshold":
		policy.Converge.Mode, policy.Converge.AdditiveRiskThreshold = "additive_threshold", 100
	default:
		return detection.Policy{}, failure.New(failure.InvalidArgument, fmt.Sprintf("unknown converge mode %q", query.Mode))
	}
	return policy, nil
}

func removeRule(rules []string, disabled string) []string {
	result := make([]string, 0, len(rules))
	for _, rule := range rules {
		if rule != disabled {
			result = append(result, rule)
		}
	}
	return result
}

func cloneLabels(labels map[string]string) map[string]string {
	if len(labels) == 0 {
		return nil
	}
	result := make(map[string]string, len(labels))
	for key, value := range labels {
		result[key] = value
	}
	return result
}
