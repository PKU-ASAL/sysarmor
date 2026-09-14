package policy

import (
	"fmt"
	"strings"
)

type EndpointProtectionMode string

const (
	ProtectionModeRuleOnly     EndpointProtectionMode = "rule-only"
	ProtectionModeLearningOnly EndpointProtectionMode = "learning-only"
	ProtectionModeHybrid       EndpointProtectionMode = "hybrid"
)

var learningCausalBehaviors = []string{
	"process.exec",
	"process.exit",
	"process.fork",
	"file.write",
	"network.connect",
}

type DetectionCapabilities struct {
	Rules    bool
	Learning bool
}

type ResponseCapabilities struct {
	Enforce bool
}

type EndpointSections struct {
	Collection bool
	Detection  bool
	Telemetry  bool
	Response   bool
}

type VersionedBundle struct {
	ID                  ID
	Version             Version
	ProtectionMode      EndpointProtectionMode
	CollectionBehaviors []string
	Detection           DetectionCapabilities
	Response            ResponseCapabilities
	Sections            EndpointSections
}

func ResolveEndpointBundle(bundle VersionedBundle) (VersionedBundle, error) {
	if bundle.ID == "" || bundle.Version == 0 {
		return VersionedBundle{}, fmt.Errorf("versioned policy bundle identity is required")
	}
	if bundle.Sections != (EndpointSections{true, true, true, true}) {
		return VersionedBundle{}, fmt.Errorf("versioned policy bundle requires collection, detection, telemetry, and response")
	}
	if err := validateProtectionMode(bundle.ProtectionMode, bundle.Detection); err != nil {
		return VersionedBundle{}, err
	}
	if bundle.ProtectionMode == ProtectionModeLearningOnly && bundle.Response.Enforce {
		return VersionedBundle{}, fmt.Errorf("learning-only protection mode requires observe-only response")
	}
	resolved := bundle
	resolved.CollectionBehaviors = normalizeBundleBehaviors(bundle.CollectionBehaviors)
	if bundle.ProtectionMode != ProtectionModeRuleOnly {
		resolved.CollectionBehaviors = normalizeBundleBehaviors(append(resolved.CollectionBehaviors, learningCausalBehaviors...))
	}
	return resolved, nil
}

func LearningCausalBehaviors() []string {
	return append([]string(nil), learningCausalBehaviors...)
}

func validateProtectionMode(mode EndpointProtectionMode, capabilities DetectionCapabilities) error {
	valid := false
	switch mode {
	case ProtectionModeRuleOnly:
		valid = capabilities.Rules && !capabilities.Learning
	case ProtectionModeLearningOnly:
		valid = !capabilities.Rules && capabilities.Learning
	case ProtectionModeHybrid:
		valid = capabilities.Rules && capabilities.Learning
	}
	if !valid {
		return fmt.Errorf("protection mode %q does not match detection capabilities", mode)
	}
	return nil
}

func normalizeBundleBehaviors(values []string) []string {
	result := make([]string, 0, len(values))
	seen := make(map[string]struct{}, len(values))
	for _, value := range values {
		value = strings.ToLower(strings.TrimSpace(value))
		if value == "" {
			continue
		}
		if _, exists := seen[value]; exists {
			continue
		}
		seen[value] = struct{}{}
		result = append(result, value)
	}
	return result
}
