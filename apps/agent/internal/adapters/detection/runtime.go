package detection

import (
	"fmt"
	"slices"
	"strings"

	detectionmodel "github.com/sysarmor/sysarmor-next-project/apps/agent/internal/domain/detection"
	domainruntime "github.com/sysarmor/sysarmor-next-project/apps/agent/internal/domain/detection/runtime"
	policymodel "github.com/sysarmor/sysarmor-next-project/apps/agent/internal/domain/policy"
	"github.com/sysarmor/sysarmor-next-project/packages/sensor-sdk/contract"
)

func New(policy *policymodel.DetectionPolicy) (*domainruntime.State, domainruntime.ApplyReport) {
	return NewWithInputs(policy, contract.CollectionIntent{})
}

func NewWithInputs(policy *policymodel.DetectionPolicy, collection contract.CollectionIntent) (*domainruntime.State, domainruntime.ApplyReport) {
	return NewWithRuntimeLimits(policy, collection, domainruntime.ContentSnapshot{}, domainruntime.EngineLimits{})
}

func NewWithRuntime(policy *policymodel.DetectionPolicy, collection contract.CollectionIntent, content domainruntime.ContentSnapshot) (*domainruntime.State, domainruntime.ApplyReport) {
	return NewWithRuntimeLimits(policy, collection, content, domainruntime.EngineLimits{})
}

func NewWithRuntimeLimits(policy *policymodel.DetectionPolicy, collection contract.CollectionIntent, content domainruntime.ContentSnapshot, limits domainruntime.EngineLimits) (*domainruntime.State, domainruntime.ApplyReport) {
	if policy == nil || len(policy.RuleSets) == 0 && policy.LearningModel == nil {
		return domainruntime.NewState(domainruntime.Program{}, limits), domainruntime.ApplyReport{Status: "rejected", Message: "detection policy rejected: explicit ruleset is required", Details: []string{"detection policy requires at least one explicit ruleset"}}
	}
	if len(policy.RuleSets) == 0 {
		return domainruntime.NewState(domainruntime.Program{}, limits), domainruntime.ApplyReport{Status: "applied", Message: "learning detection policy applied"}
	}
	input := domainruntime.ProgramInput{Content: content, Rules: resolve(policy, content)}
	program, report := domainruntime.Compile(input)
	report.Coverage = coverage(policy, collection, input.Rules)
	report.Warnings = append(report.Warnings, report.Coverage.Warnings...)
	if len(report.Warnings) > 0 && report.Status == "applied" {
		report.Status = "degraded"
		report.Message = "detection policy applied with missing collection inputs"
		report.Details = append(report.Details, report.Warnings...)
	}
	return domainruntime.NewState(program, limits), report
}

func coverage(policy *policymodel.DetectionPolicy, collection contract.CollectionIntent, rules []domainruntime.RuleSpec) domainruntime.CoverageReport {
	if policy == nil || len(collection.Behaviors) == 0 {
		return domainruntime.CoverageReport{Status: "unknown"}
	}
	behaviors, capabilities := coverageInputs(collection)
	report := domainruntime.CoverageReport{Status: "covered"}
	for _, rule := range rules {
		item := ruleCoverage(rule, behaviors, capabilities)
		if item.Status == "missing_inputs" {
			report.Status = "degraded"
			missing := append(append([]string(nil), item.MissingBehaviors...), item.MissingFields...)
			report.Warnings = append(report.Warnings, fmt.Sprintf("rule %s missing collection inputs: %s", rule.RuleID, strings.Join(missing, ",")))
		}
		report.Rules = append(report.Rules, item)
	}
	return report
}

func coverageInputs(collection contract.CollectionIntent) (map[string]bool, map[string]map[string]bool) {
	behaviors := map[string]bool{}
	for _, behavior := range collection.Behaviors {
		behaviors[strings.ToLower(strings.TrimSpace(behavior))] = true
	}
	capabilities := map[string]map[string]bool{}
	for _, capability := range collection.Capabilities {
		behavior := strings.ToLower(strings.TrimSpace(capability.Behavior))
		if capabilities[behavior] == nil {
			capabilities[behavior] = map[string]bool{}
		}
		for _, field := range capability.Fields {
			capabilities[behavior][field] = true
		}
	}
	return behaviors, capabilities
}

func ruleCoverage(rule domainruntime.RuleSpec, behaviors map[string]bool, capabilities map[string]map[string]bool) domainruntime.RuleCoverage {
	item := domainruntime.RuleCoverage{RuleID: rule.RuleID, Status: "covered"}
	for _, required := range rule.RequiredBehaviors {
		required = strings.ToLower(strings.TrimSpace(required))
		if required == "" {
			continue
		}
		item.RequiredBehaviors = append(item.RequiredBehaviors, required)
		if !behaviors[required] {
			item.MissingBehaviors = appendUnique(item.MissingBehaviors, required)
		}
	}
	for _, required := range rule.RequiredEvents {
		behavior := strings.ToLower(strings.TrimSpace(required.Behavior))
		if behavior != "" && !behaviors[behavior] {
			item.MissingBehaviors = appendUnique(item.MissingBehaviors, behavior)
		}
		for _, field := range required.Fields {
			if behavior != "" && len(capabilities) > 0 && !capabilities[behavior][field] {
				item.MissingFields = append(item.MissingFields, behavior+":"+field)
			}
		}
	}
	if len(item.MissingBehaviors) > 0 || len(item.MissingFields) > 0 {
		item.Status = "missing_inputs"
	}
	return item
}

func appendUnique(values []string, value string) []string {
	if slices.Contains(values, value) {
		return values
	}
	return append(values, value)
}

func resolve(policy *policymodel.DetectionPolicy, content domainruntime.ContentSnapshot) []domainruntime.RuleSpec {
	if policy == nil {
		return nil
	}
	sets := map[string]bool{}
	for _, ref := range policy.RuleSets {
		sets[ref.Ref] = ref.Enabled == nil || *ref.Enabled
	}
	overrides := map[string]policymodel.RuleOverride{}
	for _, override := range policy.RuleOverrides {
		if override.RuleID != "" {
			overrides[override.RuleID] = override
		}
	}
	var out []domainruntime.RuleSpec
	for _, rule := range content.Rules {
		if !sets[rule.RuleSetRef] {
			continue
		}
		rule.Mode = policy.Mode
		if override, ok := overrides[rule.RuleID]; ok {
			if override.Enabled != nil && !*override.Enabled {
				continue
			}
			if override.Mode != "" {
				rule.Mode = override.Mode
			}
			if override.Severity != "" {
				rule.Severity = override.Severity
			}
			if override.ResponseIntent != nil {
				rule.ResponseIntent = &detectionmodel.ResponseIntent{Action: override.ResponseIntent.Action, Confidence: override.ResponseIntent.Confidence, Reason: override.ResponseIntent.Reason}
			}
		}
		out = append(out, rule)
	}
	return out
}
