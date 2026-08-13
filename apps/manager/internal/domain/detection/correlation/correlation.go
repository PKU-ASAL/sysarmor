package correlation

import (
	"github.com/sysarmor/sysarmor-next-project/apps/manager/internal/domain/detection"
	"github.com/sysarmor/sysarmor-next-project/apps/manager/internal/domain/investigation/entity"
	domaintelemetry "github.com/sysarmor/sysarmor-next-project/apps/manager/internal/domain/telemetry"
)

type View struct {
	ByName map[string][]domaintelemetry.Signal
	Labels map[string]string
}

func Build(events []domaintelemetry.Event, signals []domaintelemetry.Signal, policy *detection.Policy) View {
	view := View{ByName: make(map[string][]domaintelemetry.Signal), Labels: commonLabels(events, signals)}
	for _, signal := range signals {
		if EndpointRuleEnabled(policy, signal.Name) {
			view.ByName[signal.Name] = append(view.ByName[signal.Name], signal)
		}
	}
	return view
}

func (view View) Has(name string) bool {
	return len(view.ByName[name]) > 0
}

func (view View) HasTerminal(name string) bool {
	for _, signal := range view.ByName[name] {
		if signal.Terminal {
			return true
		}
	}
	return false
}

func (view View) CollectEntities(names ...string) []domaintelemetry.Entity {
	var values []domaintelemetry.Entity
	for _, name := range names {
		for _, signal := range view.ByName[name] {
			values = append(values, signal.Entities...)
		}
	}
	return entity.Unique(values)
}

func (view View) CollectSignalRefs(names ...string) []string {
	seen := map[string]struct{}{}
	var result []string
	for _, name := range names {
		for _, signal := range view.ByName[name] {
			if signal.ID == "" {
				continue
			}
			if _, exists := seen[signal.ID]; exists {
				continue
			}
			seen[signal.ID] = struct{}{}
			result = append(result, signal.ID)
		}
	}
	return result
}

func EndpointRuleEnabled(policy *detection.Policy, name string) bool {
	if policy == nil || len(policy.EndpointRules) == 0 {
		return true
	}
	for _, rule := range policy.EndpointRules {
		if rule == name {
			return true
		}
	}
	return false
}

func commonLabels(events []domaintelemetry.Event, signals []domaintelemetry.Signal) map[string]string {
	var common map[string]string
	merge := func(labels map[string]string) {
		if len(labels) == 0 {
			return
		}
		if common == nil {
			common = cloneLabels(labels)
			return
		}
		for key, value := range common {
			if labels[key] != value {
				delete(common, key)
			}
		}
	}
	for _, event := range events {
		merge(event.Labels)
	}
	for _, signal := range signals {
		merge(signal.Labels)
	}
	return common
}

func cloneLabels(labels map[string]string) map[string]string {
	result := make(map[string]string, len(labels))
	for key, value := range labels {
		result[key] = value
	}
	return result
}
