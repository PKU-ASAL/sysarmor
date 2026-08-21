package policy

import (
	"slices"
	"strings"
	"testing"
)

func TestResolveEndpointBundleKeepsRuleOnlyCollectionTargeted(t *testing.T) {
	bundle := VersionedBundle{
		ID: "policy-a", Version: 1, ProtectionMode: ProtectionModeRuleOnly,
		CollectionBehaviors: []string{"process.exec"},
		Detection:           DetectionCapabilities{Rules: true},
		Sections:            EndpointSections{Collection: true, Detection: true, Telemetry: true, Response: true},
	}

	resolved, err := ResolveEndpointBundle(bundle)
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(resolved.CollectionBehaviors, []string{"process.exec"}) {
		t.Fatalf("rule-only collection = %v", resolved.CollectionBehaviors)
	}
}

func TestResolveEndpointBundleAddsLearningCausalRequirements(t *testing.T) {
	for _, mode := range []EndpointProtectionMode{ProtectionModeLearningOnly, ProtectionModeHybrid} {
		t.Run(string(mode), func(t *testing.T) {
			capabilities := DetectionCapabilities{Learning: true}
			if mode == ProtectionModeHybrid {
				capabilities.Rules = true
			}
			resolved, err := ResolveEndpointBundle(VersionedBundle{
				ID: "policy-a", Version: 2, ProtectionMode: mode,
				CollectionBehaviors: []string{"file.read"}, Detection: capabilities,
				Sections: EndpointSections{Collection: true, Detection: true, Telemetry: true, Response: true},
			})
			if err != nil {
				t.Fatal(err)
			}
			for _, behavior := range LearningCausalBehaviors() {
				if !slices.Contains(resolved.CollectionBehaviors, behavior) {
					t.Fatalf("resolved collection %v missing %s", resolved.CollectionBehaviors, behavior)
				}
			}
		})
	}
}

func TestResolveEndpointBundleRejectsModeCapabilityMismatch(t *testing.T) {
	tests := []VersionedBundle{
		{ID: "p", Version: 1, ProtectionMode: ProtectionModeRuleOnly, Detection: DetectionCapabilities{Learning: true}},
		{ID: "p", Version: 1, ProtectionMode: ProtectionModeLearningOnly, Detection: DetectionCapabilities{Rules: true}},
		{ID: "p", Version: 1, ProtectionMode: ProtectionModeHybrid, Detection: DetectionCapabilities{Rules: true}},
	}
	for _, bundle := range tests {
		bundle.Sections = EndpointSections{Collection: true, Detection: true, Telemetry: true, Response: true}
		if _, err := ResolveEndpointBundle(bundle); err == nil || !strings.Contains(err.Error(), "protection mode") {
			t.Fatalf("ResolveEndpointBundle(%+v) error = %v", bundle, err)
		}
	}
}

func TestResolveEndpointBundleRejectsIncompleteOrUnversionedBundle(t *testing.T) {
	for _, bundle := range []VersionedBundle{
		{ProtectionMode: ProtectionModeRuleOnly, Detection: DetectionCapabilities{Rules: true}},
		{ID: "p", Version: 1, ProtectionMode: ProtectionModeRuleOnly, Detection: DetectionCapabilities{Rules: true}},
	} {
		if _, err := ResolveEndpointBundle(bundle); err == nil {
			t.Fatalf("ResolveEndpointBundle(%+v) succeeded", bundle)
		}
	}
}
